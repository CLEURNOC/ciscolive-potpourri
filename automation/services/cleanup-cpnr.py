#!/usr/bin/env python

from elemental_utils import ElementalDns, ElementalNetbox
from elemental_utils.cpnr.query import RequestError

# from elemental_utils.cpnr.query import RequestError
from elemental_utils import cpnr
from utils import (
    launch_parallel_task,
    restart_dns_servers,
    get_reverse_zone,
    parse_txt_record,
)

from pynetbox.core.response import Record

# from pynetbox.models.virtualization import VirtualMachines
from colorama import Fore, Style

from dataclasses import dataclass, field
from threading import Lock
import os
import re
from typing import List
import CLEUCreds
from cleu.config import Config as C

# import ipaddress
import logging.config
import logging
import argparse
import sys

# import json
# import hvac

logging.config.fileConfig(os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/dns_logger.conf"))
logger = logging.getLogger(__name__)


# Bool to indicate whether or not DNS was modified.
EDNS_MODIFIED = False


@dataclass
class DnsRecords:
    """Class for tracking DNS records to delete."""

    deletes: List[cpnr.models.model.Record] = field(default_factory=list)
    lock: Lock = Lock()


def get_ptr_rrs(ips: list, edns: ElementalDns) -> List[cpnr.models.model.Record]:
    """Get a list of PTR records for a given set of IP addresses.

    Args:
        :ips list: The IP addresses to process
        :edns ElementalDns: ElementalDns object

    Returns:
        :list: List of RRSet records
    """
    result = []
    for addr in ips:
        rzone = get_reverse_zone(addr)
        ptr_name = addr.split(".")[::-1][0]
        ptr_rrs = edns.rrset.get(ptr_name, zoneOrigin=rzone)
        if ptr_rrs:
            result.append(ptr_rrs)

    return result


def check_record(
    host: cpnr.models.model.Record,
    primary_domain: str,
    rrs: list,
    edns: ElementalDns,
    enb: ElementalNetbox,
    wip_records: DnsRecords,
) -> None:
    """Check if a host record is still valid.

    Args:
        :host Record: Host DNS record
        :primary_domain str: Primary domain name for the hosts
        :rrs list: List of all RRSets
        :edns ElementalDns: ElementalDns object
        :dac DAC: DNS As Code Object
        :enb ElementalNetbox: ElementalNetbox object
        :wip_records DnsRecords: DnsRecords object to hold the records to delete

    """
    # We do not want to operate on the domain itself or the DNS server A records.
    if f"{host.name}.{host.zoneOrigin}" == primary_domain or host.name in (
        "@",
        primary_domain,
        C.PRIMARY_DNS,
        C.SECONDARY_DNS,
    ):
        return

    # Get the RRSet for the host.
    host_rr = None
    for rr in rrs:
        if rr.name.lower() == host.name.lower():
            host_rr = rr
            break

    if not host_rr:
        logger.warning(f"🪲 Did not find an RRSet for {host.name}.  This is definitely a bug!")
        return

    found_txt = None
    for rr in host_rr.rrList["CCMRRItem"]:
        # The re.search is to support DDNS entries.
        if rr["rrType"] == "TXT" and (
            rr["rdata"].startswith('"v=_netbox') or rr["rdata"].startswith('"v=_static') or re.search(r'^["0-9:]+$', rr["rdata"])
        ):
            found_txt = rr["rdata"]
            break

    wip_records.lock.acquire()

    if not found_txt:
        # No TXT record with NetBox data means this host record should be removed.
        wip_records.deletes.append(host_rr)
        # Also remove any PTR records.
        wip_records.deletes.extend(get_ptr_rrs(host.addrs["stringItem"], edns))
    elif found_txt.startswith('"v=_netbox'):
        txt_obj = parse_txt_record(found_txt)
        ip_obj = enb.ipam.ip_addresses.get(int(txt_obj["ip_id"]))
        if not ip_obj:
            # The IP object is gone, so remove this record.
            wip_records.deletes.append(host_rr)
            # Also remove the PTR record
            wip_records.deletes.extend(get_ptr_rrs(host.addrs["stringItem"], edns))
        elif txt_obj["type"] == "device" or txt_obj["type"] == "vm":
            # The IP object exists, so check the assigned object to make sure it hasn't been
            # renamed.
            nb_obj = None
            if txt_obj["type"] == "device":
                nb_obj = enb.dcim.devices.get(int(txt_obj["id"]))
            else:
                nb_obj = enb.virtualization.virtual_machines.get(int(txt_obj["id"]))

            if not nb_obj or (nb_obj.name.lower() != host_rr.name.lower() and host_rr.name.lower() != ip_obj.dns_name.lower()):
                wip_records.deletes.append(host_rr)
                wip_records.deletes.extend(get_ptr_rrs(host.addrs["stringItem"], edns))

    wip_records.lock.release()


def check_cname(
    rrs: cpnr.models.model.Record,
    primary_domain: str,
    edns: ElementalDns,
    wip_records: DnsRecords,
) -> None:
    """Check if a CNAME record is still valid.

    Args:
        :host Record: Host DNS record
        :primary_domain str: Primary domain name for the hosts
        :rrs list: List of all RRSets
        :edns ElementalDns: ElementalDns object
        :dac DAC: DNS As Code object
        :enb ElementalNetbox: ElementalNetbox object
        :wip_records DnsRecords: DnsRecords object to hold the records to delete
    """

    found_host = False
    for rr in rrs.rrList["CCMRRItem"]:
        if rr["rrType"] == "CNAME":
            found_host = rr["rdata"]
            break

    if not found_host:
        # This is not a CNAME, so skip it.
        return

    # Lookup the CNAME target to make sure it's still in DNS.
    domain_parts = found_host.split(".")
    host = domain_parts[0]
    if len(domain_parts) == 1:
        zone = primary_domain
    else:
        zone = ".".join(domain_parts[1:])

    host_obj = edns.host.get(host, zoneOrigin=zone)
    if not host_obj:
        # The host that this CNAME points to is gone, so delete the CNAME.
        wip_records.lock.acquire()
        wip_records.deletes.append(rrs)
        wip_records.lock.release()


def delete_record(cpnr_record: cpnr.models.model.Record, primary_domain: str, edns: ElementalDns) -> None:
    """Delete a record from CPNR.

    Args:
        :cpnr_record Record: CPNR record to delete
        :primary_domain str: Primary DNS domain
        :edns ElementalDns: ElementalDns object to use
    """
    global EDNS_MODIFIED

    name = cpnr_record.name
    domain = cpnr_record.zoneOrigin

    try:
        cpnr_record.delete()
    except RequestError as e:
        if e.req.status_code != 404:
            # We may end up deleting the same record twice.
            # If it's already gone, don't complain.
            raise
    else:
        logger.info(f"🧼 Successfully deleted record {name}.{domain}")
        EDNS_MODIFIED = True


def print_records(wip_records: DnsRecords, tenant: Record) -> None:
    """Print the records to be processed.

    Args:
        :wip_records DnsRecords: DnsRecords object containing the records to process
        :tenant Record: A NetBox Tenant for which this DNS record applies
    """
    print(f"DNS records to be deleted for tenant {tenant.name} ({len(wip_records.deletes)} records):")
    for rec in wip_records.deletes:
        print(f"\t{Fore.RED}DELETE{Style.RESET_ALL} {rec.name}.{rec.zoneOrigin}")


def parse_args() -> object:
    """Parse any command line arguments.

    Returns:
        :object: Object representing the arguments passed
    """
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Cleanup stale DNS records in CPNR")
    parser.add_argument(
        "--site",
        metavar="<SITE>",
        help="Site to cleanup",
        required=False,
    )
    parser.add_argument(
        "--tenant",
        metavar="<TENANT>",
        help="Tenant to cleanup",
        required=False,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do a dry-run (no changes made)",
        required=False,
    )
    parser.add_argument(
        "--dummy", metavar="<DUMMY SERVER>", help="Override main DNS server with a dummy server (only used with --tenant", required=False
    )

    args = parser.parse_args()

    if args.site and args.tenant:
        print("Only one of --site or --tenant can be given")
        exit(1)

    if not args.site and not args.tenant:
        print("One of --site or --tenant must be provided")
        exit(1)

    if args.dummy and not args.tenant:
        print("--dummy requires --tenant")
        exit(1)

    return args


def main():
    os.environ["NETBOX_ADDRESS"] = C.NETBOX_SERVER
    os.environ["NETBOX_API_TOKEN"] = CLEUCreds.NETBOX_API_TOKEN
    os.environ["CPNR_USERNAME"] = CLEUCreds.CPNR_USERNAME
    os.environ["CPNR_PASSWORD"] = CLEUCreds.CPNR_PASSWORD

    args = parse_args()

    if args.site:
        lower_site = args.site.lower()
    if args.tenant:
        lower_tenant = args.tenant.lower()

    enb = ElementalNetbox()

    # 1. Get a list of all tenants.  If we work tenant-by-tenant, we will likely remain connected
    #    to the same DNS server.
    tenants = enb.tenancy.tenants.all()
    for tenant in tenants:
        if args.site and str(tenant.group.parent).lower() != lower_site:
            continue

        if args.tenant and tenant.name.lower() != lower_tenant:
            continue

        primary_domain = C.DNS_DOMAIN + "."

        edns = ElementalDns(url=f"https://{C.DNS_SERVER}:8443/")
        ecdnses = C.CDNS_SERVERS

        # 2. Get all host records then all RRSets from CPNR
        hosts = edns.host.all(zoneOrigin=primary_domain)
        if len(hosts) == 0:
            continue
        rrs = edns.rrset.all(zoneOrigin=primary_domain)

        wip_records = DnsRecords()

        # 3. Use thread pools to obtain a list of records to delete.
        launch_parallel_task(check_record, "check DNS record(s)", hosts, "name", 20, False, primary_domain, rrs, edns, enb, wip_records)

        # 4. Iterate through the RRs looking for stale CNAMEs
        launch_parallel_task(check_cname, "check for stale CNAMEs", rrs, "name", 20, False, primary_domain, edns, wip_records)

        # 5. If doing a dry-run, only print out the changes.
        if args.dry_run:
            print_records(wip_records, tenant)
            continue

        # 6. Process records to be deleted first.  Use thread pools again to parallelize this.
        launch_parallel_task(delete_record, "delete DNS record", wip_records.deletes, "name", 20, False, primary_domain, edns)

    # 7. Restart affected DNS servers.
    if not args.dry_run:
        if EDNS_MODIFIED:
            # Technically nothing is modified in dry-run, but just to be safe.
            restart_dns_servers(edns, ecdnses)


if __name__ == "__main__":
    main()
