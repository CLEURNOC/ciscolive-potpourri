#!/usr/bin/env python

from elemental_utils import ElementalDns, ElementalNetbox
from elemental_utils.cpnr.query import RequestError

# from elemental_utils.cpnr.query import RequestError
from elemental_utils import cpnr
from utils import (
    dedup_cnames,
    get_cname_record,
    launch_parallel_task,
    restart_dns_servers,
    get_reverse_zone,
)

from pynetbox.core.response import Record
from pynetbox.models.ipam import IpAddresses
import CLEUCreds
from cleu.config import Config as C

# from pynetbox.models.virtualization import VirtualMachines
from colorama import Fore, Style

from typing import Union, Tuple, List
from dataclasses import dataclass, field
from threading import Lock
import os

# import ipaddress
import logging.config
import logging
import argparse
import sys

# import json
import re

# import hvac

logging.config.fileConfig(os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/dns_logger.conf"))
logger = logging.getLogger(__name__)

EDNS_MODIFIED = False


@dataclass
class ARecord:
    """Class representing a DNS Address record."""

    hostname: str
    ip: str
    domain: str
    nb_record: IpAddresses
    _name: str


@dataclass
class CNAMERecord:
    """Class representing a DNS CNAME record."""

    alias: str
    domain: str
    host: ARecord
    _name: str


@dataclass
class PTRRecord:
    """Class representing a DNS PTR record."""

    rev_ip: str
    hostname: str
    rzone: str
    nb_record: IpAddresses
    _name: str


@dataclass
class TXTRecord:
    """Class representing a DNS TXT record."""

    name: str
    value: str


@dataclass
class DnsRecords:
    """Class for tracking DNS records to delete and create."""

    creates: list = field(default_factory=list)
    deletes: List[Tuple] = field(default_factory=list)
    lock: Lock = Lock()


def get_txt_record(ip: IpAddresses) -> str:
    """Return a serialized form of an IP/VM/device object for use in a TXT record.

    Args:
        :ip IpAddresses: IP address object to process

    Returns:
        :str: TXT record data
    """
    result = "v=_netbox "
    atype = ip.assigned_object_type
    if atype == "virtualization.vminterface":
        result += (
            f"url={ip.assigned_object.virtual_machine.serialize()['url']} type=vm id={ip.assigned_object.virtual_machine.id} ip_id={ip.id}"
        )
    elif atype == "dcim.interface":
        result += f"url={ip.assigned_object.device.serialize()['url']} type=device id={ip.assigned_object.device.id} ip_id={ip.id}"

    return f'"{result}"'


def get_dns_name(ip: IpAddresses) -> str:
    """Get a DNS name based on the IP object's assigned object.

    Args:
        :ip IpAddresses: IP address object to check

    Returns:
        :str: DNS name if one is found else None
    """
    dns_name = None
    if ip.assigned_object:
        atype = ip.assigned_object_type
        aobj = ip.assigned_object
        if atype == "virtualization.vminterface":
            if aobj.virtual_machine.primary_ip4 == ip:
                dns_name = aobj.virtual_machine.name.lower()
        elif atype == "dcim.interface":
            if aobj.device.primary_ip4 == ip:
                dns_name = aobj.device.name.lower()

    return dns_name


def check_record(ip: IpAddresses, primary_domain: str, edns: ElementalDns, enb: ElementalNetbox, wip_records: DnsRecords) -> None:
    """Check to see if a given NetBox IP object needs DNS updates.

    Args:
        :ip IpAddresses: NetBox IP address object to check
        :primary_domain str: Primary domain name for the records for the IP/host with trailing '.'
        :edns ElementalDns: ElementalDns object representing the auth DNS for the primary_domain
        :enb ElementalNetbox: ElementalNetbox object for querying
        :wip_records DnsRecords: Object to hold the results of the function
    """
    dns_name = get_dns_name(ip)

    # If we don't have a name, then we have nothing to check.
    if not dns_name:
        return

    if not re.match(r"^[a-z0-9-]+$", dns_name):
        logger.warning(f"⛔️ Invalid DNS name {dns_name} for IP {ip.address}")
        return

    ip_address = ip.address.split("/")[0]
    rzone_name = get_reverse_zone(ip_address)
    ptr_name = ip_address.split(".")[::-1][0]
    old_ptrs = []

    # Get the current A record from DNS (if it exists)
    current_host_record = edns.host.get(dns_name, zoneOrigin=primary_domain)
    # Get the current PTR record from DNS (if it exists)
    current_ptr_record = edns.rrset.get(ptr_name, zoneOrigin=rzone_name)

    # Declare an A record for the current object.
    a_record = ARecord(dns_name, ip_address, primary_domain, ip, dns_name)

    # Track whether or not we need a change
    change_needed = False

    if not current_host_record:
        # An A record doesn't yet exist.
        change_needed = True
    else:
        if ip_address not in current_host_record.addrs["stringItem"]:
            # An A record exists for the hostname but pointing to a different IP.  Remove it.
            change_needed = True
            # Also, remove the old PTR.
            for addr in current_host_record.addrs["stringItem"]:
                old_ptrs.append((addr.split(".")[::-1][0], get_reverse_zone(addr)))
        else:
            # Check if we have a TXT meta-record.  If this does not exist the existing host record will be removed and a new one added
            change_needed = check_txt_record(current_host_record, ip, edns)

    if current_ptr_record:
        found_match = False
        for rr in current_ptr_record.rrList["CCMRRItem"]:
            if rr["rrType"] == "PTR" and rr["rdata"] == f"{dns_name}.{primary_domain}":
                found_match = True
                break

        if not found_match:
            change_needed = True

    if change_needed:
        # If a change is required in the A/PTR records, mark the old records for removal and add
        # the new records.
        wip_records.lock.acquire()

        if current_host_record:
            if (current_host_record.name, primary_domain) not in wip_records.deletes:
                wip_records.deletes.append((current_host_record.name, primary_domain))
            # Cleanup the old PTRs, too.
            for old_ptr in old_ptrs:
                if old_ptr not in wip_records.deletes:
                    wip_records.deletes.append(old_ptr)

        if current_ptr_record:
            if (current_ptr_record.name, rzone_name) not in wip_records.deletes:
                wip_records.deletes.append((current_ptr_record.name, rzone_name))
            # Delete the old A record, too.
            for rr in current_ptr_record.rrList["CCMRRItem"]:
                if rr["rrType"] == "PTR":
                    host_name = rr["rdata"].split(".")[0]
                    if (host_name, primary_domain) not in wip_records.deletes:
                        wip_records.deletes.append((host_name, primary_domain))

        wip_records.creates.append(a_record)

        wip_records.lock.release()

    # Process any CNAMEs that may exist for this record.
    check_cnames(ip=ip, dns_name=dns_name, primary_domain=primary_domain, a_record=a_record, enb=enb, wip_records=wip_records)


def check_cnames(
    ip: IpAddresses, dns_name: str, primary_domain: str, a_record: ARecord, enb: ElementalNetbox, wip_records: DnsRecords
) -> None:
    """Determine CNAME records to create/delete.

    Args:
        :ip IpAddresses: IP address object to check
        :dns_name str: Main hostname of the record
        :primary_domain str: Primary domain name of the record
        :a_record ARecord: A record object to link CNAMEs to
        :enb ElementalNetbox: ElementalNetbox object for NetBox queries
        :wip_records DnsRecords: DnsRecords object to hold the results
    """

    cnames = ip.custom_fields.get("CNAMEs")
    if not cnames:
        cnames = ""
    else:
        cnames = cnames.lower().strip()

    primary_cname = ""
    # Add the IP's DNS Name as a CNAME if it is unique.
    if ip.dns_name and ip.dns_name != "" and ip.dns_name.strip().lower() != dns_name:
        primary_cname = ip.dns_name.strip().lower()

    if cnames == "" and primary_cname != "":
        cnames = primary_cname
    elif primary_cname != "":
        cnames += f",{primary_cname}"

    if cnames != "":
        cname_list = dedup_cnames(cnames.split(","), primary_domain)
        for cname in cname_list:
            current_domain = ".".join(cname.split(".")[1:])
            alias = cname.split(".")[0]
            cname_record = CNAMERecord(alias, current_domain, a_record, alias)

            current_cname_record = get_cname_record(alias, current_domain, enb)

            wip_records.lock.acquire()

            if not current_cname_record:
                # There isn't a CNAME already, so add a new CNAME record.
                wip_records.creates.append(cname_record)
            else:
                found_match = False
                for rr in current_cname_record.rrList["CCMRRItem"]:
                    if rr["rrType"] == "CNAME" and rr["rdata"] == f"{dns_name}.{primary_domain}":
                        # The existing CNAME record points to the correct A record, so we don't need a change.
                        found_match = True
                        break

                if not found_match:
                    # CNAME exists but was not consistent, so remove the old one and add a new one.
                    if (current_cname_record.name, current_cname_record.zoneOrigin) not in wip_records.deletes:
                        wip_records.deletes.append((current_cname_record.name, current_cname_record.zoneOrigin))

                    wip_records.creates.append(cname_record)

            wip_records.lock.release()
            # Note: This code will leave stale CNAMEs (i.e., CNAMEs that point to non-existent hosts or CNAMEs that
            # are no longer used).  Those will be cleaned up by another script.


def check_txt_record(current_host_record: cpnr.models.model.Record, ip: IpAddresses, edns: ElementalDns) -> bool:
    rrs = edns.rrset.get(current_host_record.name, zoneOrigin=current_host_record.zoneOrigin)
    rdata = get_txt_record(ip)

    change_needed = True
    if rrs:
        # This SHOULD always be true
        for rr in rrs.rrList["CCMRRItem"]:
            if rr["rrType"] == "TXT":
                if rr["rdata"] == rdata:
                    change_needed = False
                else:
                    logger.debug(
                        f"TXT record for {current_host_record.name} in domain {current_host_record.zoneOrigin} exists, but it is "
                        f"'{rr['rdata']}' and it should be '{rdata}'"
                    )

                break

    return change_needed


def print_records(wip_records: DnsRecords, primary_domain: str, tenant: Record) -> None:
    """Print the records to be processed.

    Args:
        :wip_records DnsRecords: DnsRecords object containing the records to process
        :primary_domain str: Primary domain to append when needed
        :tenant Record: A NetBox Tenant for which this DNS record applies
    """
    print(f"DNS records to be deleted for tenant {tenant.name} ({len(wip_records.deletes)} records):")
    for rec in wip_records.deletes:
        print(f"\t{Fore.RED}DELETE{Style.RESET_ALL} {rec[0]}.{rec[1]}")

    print(f"DNS records to be created for tenant {tenant.name} ({len(wip_records.creates)} records):")
    for rec in wip_records.creates:
        if isinstance(rec, ARecord):
            print(f"\t{Fore.GREEN}CREATE{Style.RESET_ALL} [A] {rec.hostname}.{primary_domain} : {rec.ip}")
            print(f"\t{Fore.GREEN}CREATE{Style.RESET_ALL} [PTR] {rec.ip}.{get_reverse_zone(rec.ip)} ==> {rec.hostname}.{primary_domain}")
            print(f"\t{Fore.GREEN}CREATE{Style.RESET_ALL} [TXT] {rec.hostname}.{primary_domain} : {get_txt_record(rec.nb_record)}")
        elif isinstance(rec, CNAMERecord):
            print(f"\t{Fore.GREEN}CREATE{Style.RESET_ALL} [CNAME] {rec.alias}.{rec.domain} ==> {rec.host.hostname}.{rec.host.domain}")
        elif isinstance(rec, PTRRecord):
            print(f"\t{Fore.GREEN}CREATE{Style.RESET_ALL} [PTR] {rec.rev_ip}.{rec.rzone} ==> {rec.hostname}")


# def delete_txt_record(name: str, domain: str, edns: ElementalDns) -> None:
#     """Delete a TXT record associated with an A record.

#     Args:
#         :name str: Name of the record to delete
#         :domain str: Domain name where the record should be added
#         :edns ElementalDns: ElementalDns object to use
#     """
#     rrs = edns.rrset.get(name, zoneOrigin=domain)
#     if rrs:
#         if len(rrs.rrList["CCMRRItem"]) == 1 and rrs.rrList["CCMRRItem"][0]["rrType"] == "TXT":
#             rrs.delete()
#             logger.info(f"🧼 Deleted TXT record for {name} in domain {domain}")
#         else:
#             rrList = []
#             changed = False
#             for rr in rrs.rrList["CCMRRItem"]:
#                 if rr["rrType"] != "TXT":
#                     rrList.append(rr)
#                 else:
#                     logger.info(f"🧼 Removing TXT record from RRSet for {name} in domain {domain}")
#                     changed = True

#             if changed:
#                 rrs.rrList["CCMRRItem"] = rrList
#                 rrs.save()


def delete_record(cpnr_record: Tuple, primary_domain: str, edns: ElementalDns) -> None:
    """Delete a record from CPNR.

    Args:
        :cpnr_record Tuple: CPNR record to delete in a Tuple of (name, domain) format
        :primary_domain str: Primary DNS domain
        :edns ElementalDns: ElementalDns object of the auth DNS server
    """
    global EDNS_MODIFIED

    name = cpnr_record[0]
    domain = cpnr_record[1]

    # Build an RRSet to delete.
    rrs = edns.rrset.get(name, zoneOrigin=domain)
    if rrs:
        try:
            rrs.delete()
        except RequestError as e:
            if e.req.status_code != 404:
                # We may end up deleting the same record twice.
                # If it's already gone, don't complain.
                raise
        else:
            logger.info(f"🧼 Successfully deleted record {name}.{domain}")
            EDNS_MODIFIED = True


def add_record(record: Union[ARecord, CNAMERecord, PTRRecord], primary_domain: str, edns: ElementalDns) -> None:
    """Add a new DNS record to CPNR.

    Args:
        :cpnr_record Record: Record to add
        :primary_domain str: Primary domain name to add if the record doesn't contain it
        :edns ElementalDns: ElementalDns object to use for adding the record
        :dac DAC: DNS as code object
    """
    global EDNS_MODIFIED

    cpnr_record = {}

    if isinstance(record, ARecord):
        cpnr_record["name"] = record.hostname
        cpnr_record["addrs"] = {"stringItem": [record.ip]}
        cpnr_record["zoneOrigin"] = primary_domain
        cpnr_record["createPtrRecords"] = True
        txt_record = get_txt_record(record.nb_record)

        edns.host.add(**cpnr_record)
        logger.info(f"🎨 Successfully created record for host {record.hostname} : {record.ip}")
        rrs = edns.rrset.get(record.hostname, zoneOrigin=primary_domain)
        rrs.rrList["CCMRRItem"].append({"rdata": txt_record, "rrClass": "IN", "rrType": "TXT"})
        rrs.save()
        logger.info(f"🎨 Successfully created TXT meta-record for host {record.hostname} in domain {primary_domain}")
        EDNS_MODIFIED[edns] = True
    elif isinstance(record, CNAMERecord):
        curr_edns = edns
        cpnr_record["name"] = record.alias
        cpnr_record["zoneOrigin"] = record.domain
        target = f"{record.host.hostname}.{record.host.domain}"
        cpnr_record["rrList"] = {"CCMRRItem": [{"rdata": target, "rrClass": "IN", "rrType": "CNAME"}]}

        curr_edns.rrset.add(**cpnr_record)
        logger.info(f"🎨 Successfully created CNAME record in domain {record.domain} for alias {record.alias} ==> {target}")
        EDNS_MODIFIED = True
    else:
        # PTR records are not created by themselves for the moment.
        logger.warning(f"⛔️ Unexpected record of type {type(record)}")


def parse_args() -> object:
    """Parse any command line arguments.

    Returns:
        :object: Object representing the arguments passed
    """
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Sync NetBox elements to CPNR")
    parser.add_argument(
        "--site",
        metavar="<SITE>",
        help="Site to sync",
        required=False,
    )
    parser.add_argument(
        "--tenant",
        metavar="<TENANT>",
        help="Tenant to sync",
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
    global EDNS_HASH, ECDNS_HASH

    os.environ["NETBOX_SERVER"] = C.NETBOX_SERVER
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
        elif args.tenant:
            lower_site = str(tenant.group.parent).lower()

        primary_domain = C.DNS_DOMAIN

        edns = ElementalDns(url=f"https://{C.DNS_SERVER}:8443/")
        ecdnses = C.CDNS_SERVERS

        # 2. Get all IP addresses for the tenant.
        ip_addresses = list(enb.ipam.ip_addresses.filter(tenant_id=tenant.id))
        if len(ip_addresses) == 0:
            continue

        wip_records = DnsRecords()

        # 3. Use thread pools to obtain a list of records to delete then create (updates are done as a delete+create).
        launch_parallel_task(
            check_record, "check DNS record(s)", ip_addresses, "address", 20, False, primary_domain, edns, enb, wip_records
        )

        # 4. If doing a dry-run, only print out the changes.
        if args.dry_run:
            print_records(wip_records, primary_domain, tenant)
            continue

        # 5. Process records to be deleted first.  Use thread pools again to parallelize this.
        success = launch_parallel_task(delete_record, "delete DNS record", wip_records.deletes, None, 20, True, primary_domain, edns)

        if not success:
            break

        # 6. Process records to be added next.  Use thread pools again to parallelize this.
        launch_parallel_task(add_record, "add DNS record", wip_records.creates, "_name", 20, False, primary_domain, edns)

    # 7. Restart affected DNS servers.
    if not args.dry_run:
        # Technically nothing is modified in dry-run, but just to be safe.
        if EDNS_MODIFIED:
            restart_dns_servers(edns, ecdnses)


if __name__ == "__main__":
    main()
