#!/usr/bin/env python
#
# Copyright (c) 2017-2025  Joe Clarke <jclarke@cisco.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

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
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

# from pynetbox.models.virtualization import VirtualMachines
from colorama import Fore, Style

from typing import Union, Tuple, List
from dataclasses import dataclass, field
from threading import Lock
import os

import ipaddress
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
    ips: List[str]
    domain: str
    nb_record: IpAddresses
    ttl: int
    _name: str


@dataclass
class CNAMERecord:
    """Class representing a DNS CNAME record."""

    alias: str
    domain: str
    host: ARecord
    ttl: int
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
    all: list = field(default_factory=list)
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
    else:
        result += f"ip_id={ip.id} type=ip"

    return f'"{result}"'


def get_dns_name(ip: IpAddresses) -> str | None:
    """Get a DNS name based on the IP object's assigned object.

    Args:
        :ip IpAddresses: IP address object to check

    Returns:
        :str: DNS name if one is found else None
    """
    dns_name = None
    if ip.family.value == 4:
        if ip.assigned_object:
            atype = ip.assigned_object_type
            aobj = ip.assigned_object
            if atype == "virtualization.vminterface":
                if aobj.virtual_machine.primary_ip4 == ip:
                    dns_name = aobj.virtual_machine.name.lower()
                elif ip.dns_name and ip.dns_name != "":
                    dns_name = ip.dns_name.strip().lower()
            elif atype == "dcim.interface":
                if aobj.device.primary_ip4 == ip:
                    dns_name = aobj.device.name.lower()
                elif ip.dns_name and ip.dns_name != "":
                    dns_name = ip.dns_name.strip().lower()
        elif ip.dns_name and ip.dns_name != "":
            dns_name = ip.dns_name.strip().lower()
    elif ip.family.value == 6:
        # atype = ip.assigned_object_type
        # aobj = ip.assigned_object
        # if atype == "virtualization.vminterface":
        #     if aobj.virtual_machine.primary_ip6 == ip:
        #         dns_name = aobj.virtual_machine.name.lower()
        #     elif ip.dns_name and ip.dns_name != "":
        #         dns_name = ip.dns_name.strip().lower()
        # elif atype == "dcim.interface":
        #     if aobj.device.primary_ip6 == ip:
        #         dns_name = aobj.device.name.lower()
        #     elif ip.dns_name and ip.dns_name != "":
        #         dns_name = ip.dns_name.strip().lower()
        if ip.dns_name and ip.dns_name != "":
            dns_name = ip.dns_name.strip().lower()

    return dns_name


def construct_ipv6_address(ip: str) -> str:
    """Construct an IPv6 address based on addressing rules.

    Args:
        :ip str: IPv4 address to use as a base

    Returns:
        :str: Generated IPv6 address
    """
    hextets = C.IPV6_PREFIX.split(":")
    hextet = 0
    octets = ip.split(".")
    if C.VLAN_OCTET > -1:
        if C.VLAN_OCTET == C.IDF_OCTET:
            raise ValueError("VLAN octet cannot be the same as IDF octet")

        if C.VLAN_OCTET == 2:
            hextet |= int(octets[C.VLAN_OCTET - 1]) << 8
        else:
            hextet |= int(octets[C.VLAN_OCTET - 1])

    if C.IDF_OCTET > -1:
        if C.IDF_OCTET == 2:
            hextet |= int(octets[C.IDF_OCTET - 1]) << 8
        else:
            hextet |= int(octets[C.IDF_OCTET - 1])

    hextets[-2] = format(hextet, "x")
    # Re-add the last element.
    hextets.append("")
    hextets[-1] = format(int(octets[-1]), "x")

    return ":".join(hextets)


def get_ipv6_address(ip: IpAddresses) -> str | None:
    """Retrieve an IPv6 address for a given IPv4 address.

    Args:
        :ip IpAddresses: NetBox IP address to check

    Returns:
        :str: Corresponding IPv6 address or None if no assigned object
    """
    if ip.family.value != 4 or not ip.assigned_object:
        return None

    ipv6_addr = None

    atype = ip.assigned_object_type
    aobj = ip.assigned_object
    if atype == "virtualization.vminterface":
        if aobj.virtual_machine.primary_ip6 and aobj.virtual_machine.primary_ip6 != "":
            ipv6_addr = aobj.virtual_machine.primary_ip6.address.split("/")[0]
    elif atype == "dcim.interface":
        if aobj.device.primary_ip6 and aobj.device.primary_ip6 != "":
            ipv6_addr = aobj.device.primary_ip6.address.split("/")[0]

    if not ipv6_addr and ip.custom_fields.get("v6_based_on_v4"):
        ip_addr = ip.address.split("/")[0]
        ipv6_addr = construct_ipv6_address(ip_addr)

    return ipv6_addr


def check_ptr(ptr: cpnr.models.model.Record, rzone: str, deletes: list, primary_domain: str) -> None:
    """Check if a current PTR record is good.

    Args:
        :ptr cpnr.models.model.Record: PTR record to check
        :rzone str: Reverse zone name
        :deletes list: List to add to if the record needs to be deleted
        :primary_domain str: Primary domain name for the A record
    """
    if (ptr.name, rzone) not in deletes:
        deletes.append((ptr.name, rzone))
        # Delete the old A record, too.
        for rr in ptr.rrList["CCMRRItem"]:
            if rr["rrType"] == "PTR":
                host_name = rr["rdata"].split(".")[0]
                if (host_name, primary_domain) not in deletes:
                    deletes.append((host_name, primary_domain))


def find_old_ptrs(addr_list: list, old_ptrs: list) -> None:
    """Find all old PTRs and add to a list.

    Args:
        :addr_list list: List of addresses to process
        :old_ptrs list: List of old PTR records to append
    """
    for addr in addr_list:
        rzn = get_reverse_zone(addr, C.IPV6_PREFIX_SIZE, C.REVERSE_ZONE_MAP)
        ptrn = re.sub(rf"\.{rzn}", "", ipaddress.ip_address(addr).reverse_pointer + ".")
        old_ptrs.append((ptrn, rzn))


def check_record(ip: IpAddresses, primary_domain: str, edns: ElementalDns, enb: ElementalNetbox, wip_records: DnsRecords) -> None:
    """Check to see if a given NetBox IP object needs DNS updates.

    Args:
        :ip IpAddresses: NetBox IP address object to check
        :primary_domain str: Primary domain name for the records for the IP/host with trailing '.'
        :edns ElementalDns: ElementalDns object representing the auth DNS for the primary_domain
        :enb ElementalNetbox: ElementalNetbox object for querying
        :wip_records DnsRecords: Object to hold the results of the function
    """
    if ip.family.value == 6 and ip.assigned_object:
        # If this is an IPv6 address and it's assigned to an object, skip it.
        # We will pick this up via the primary IPv4 address.
        return

    dns_name = get_dns_name(ip)

    # If we don't have a name, then we have nothing to check.
    if not dns_name:
        return

    if not re.match(r"^[a-z0-9-]+$", dns_name):
        logger.warning(f"⛔️ Invalid DNS name {dns_name} for IP {ip.address}")
        return

    ip_address = ip.address.split("/")[0]
    rzone_name = get_reverse_zone(ip_address, C.IPV6_PREFIX_SIZE, C.REVERSE_ZONE_MAP)
    # We have to filter out the rzone_name from the ptr_name.
    ptr_name = re.sub(rf"\.{rzone_name}", "", ipaddress.ip_address(ip_address).reverse_pointer + ".")

    old_ptrs = []

    ttl = ip.custom_fields.get("dns_ttl")
    if not ttl:
        ttl = -1

    # Attempt to retrieve any specifically-assigned IPv6 addresses based on the assigned object (if any).
    # If no IPv6 address exists, generate one using the current prefix and the addressing rules.
    ipv6_addr = get_ipv6_address(ip)

    # Get the current A record from DNS (if it exists)
    current_host_record = edns.host.get(dns_name, zoneOrigin=primary_domain)
    # Get the current PTR record from DNS (if it exists)
    current_ptr_record = edns.rrset.get(ptr_name, zoneOrigin=rzone_name)

    addresses = [ip_address]
    v6_rzone_name = None
    current_v6_ptr_record = None
    if ipv6_addr:
        addresses.append(ipv6_addr)
        v6_rzone_name = get_reverse_zone(ipv6_addr, C.IPV6_PREFIX_SIZE, C.REVERSE_ZONE_MAP)
        v6_ptr_name = re.sub(rf"\.{v6_rzone_name}", "", ipaddress.IPv6Address(ipv6_addr).reverse_pointer + ".")
        current_v6_ptr_record = edns.rrset.get(v6_ptr_name, zoneOrigin=v6_rzone_name)

    # Declare an A record for the current object.
    a_record = ARecord(dns_name, addresses, primary_domain, ip, ttl, dns_name)

    # Track whether or not we need a change
    change_needed = False

    if not current_host_record:
        # An A record doesn't yet exist.
        change_needed = True
    else:
        if ip.family.value == 4:
            addr_list = current_host_record.addrs["stringItem"]
        else:
            addr_list = current_host_record.ip6AddressList["stringItem"]

        if ip_address not in addr_list:
            # An A record exists for the hostname but pointing to a different IP.  Remove it.
            change_needed = True
            # Also, remove the old PTR.
            find_old_ptrs(addr_list, old_ptrs)

            if ipv6_addr and current_host_record.get("ip6AddressList"):
                find_old_ptrs(current_host_record.ip6AddressList["stringItem"], old_ptrs)
        elif (
            ipv6_addr
            and (not current_host_record.get("ip6AddressList") or ipv6_addr not in current_host_record.ip6AddressList["stringItem"])
        ) or (
            not ipv6_addr
            and ip.family.value == 4
            and current_host_record.get("ip6AddressList")
            and len(current_host_record.ip6AddressList["stringItem"]) > 0
        ):
            # The host record is missing its IPv6 address or it has a v6 address but shouldn't.
            change_needed = True
            if current_host_record.get("ip6AddressList"):
                find_old_ptrs(current_host_record.ip6AddressList["stringItem"], old_ptrs)
            find_old_ptrs(current_host_record.addrs["stringItem"], old_ptrs)
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
    else:
        change_needed = True

    if current_v6_ptr_record:
        found_match = False
        for rr in current_v6_ptr_record.rrList["CCMRRItem"]:
            if rr["rrType"] == "PTR" and rr["rdata"] == f"{dns_name}.{primary_domain}":
                found_match = True
                break

        if not found_match:
            change_needed = True
    elif ipv6_addr:
        change_needed = True

    wip_records.lock.acquire()

    if change_needed:
        # If a change is required in the A/PTR records, mark the old records for removal and add
        # the new records.

        if current_host_record:
            if (current_host_record.name, primary_domain) not in wip_records.deletes:
                wip_records.deletes.append((current_host_record.name, primary_domain))
            # Cleanup the old PTRs, too.
            for old_ptr in old_ptrs:
                if old_ptr not in wip_records.deletes:
                    wip_records.deletes.append(old_ptr)

        if current_ptr_record:
            check_ptr(current_ptr_record, rzone_name, wip_records.deletes, primary_domain)

        if current_v6_ptr_record:
            check_ptr(current_v6_ptr_record, v6_rzone_name, wip_records.deletes, primary_domain)

        wip_records.creates.append(a_record)

    # Add the record to the overall list of records.
    wip_records.all.append(a_record)

    wip_records.lock.release()

    # Process any CNAMEs that may exist for this record.
    check_cnames(ip=ip, dns_name=dns_name, primary_domain=primary_domain, a_record=a_record, edns=edns, wip_records=wip_records)


def check_cnames(
    ip: IpAddresses, dns_name: str, primary_domain: str, a_record: ARecord, edns: ElementalDns, wip_records: DnsRecords
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
    ttl = ip.custom_fields.get("dns_ttl")
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
            cname_record = CNAMERecord(alias, current_domain, a_record, ttl, alias)

            current_cname_record = get_cname_record(alias, current_domain, edns)

            wip_records.lock.acquire()
            wip_records.all.append(cname_record)

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
            for ip in rec.ips:
                print(f"\t{Fore.GREEN}CREATE{Style.RESET_ALL} [A] {rec.hostname}.{primary_domain} : {ip}")
                print(
                    f"\t{Fore.GREEN}CREATE{Style.RESET_ALL} [PTR] {ipaddress.ip_address(ip).reverse_pointer + '.'} ==> {rec.hostname}.{primary_domain}"
                )
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
            logger.info(f"🧼 Successfully deleted record set for {name}.{domain}")
            EDNS_MODIFIED = True

    host = edns.host.get(name, zoneOrigin=domain)
    if host:
        try:
            host.delete()
        except RequestError as e:
            if e.req.status_code != 404:
                # We may end up deleting the same record twice.
                # If it's already gone, don't complain.
                raise
        else:
            logger.info(f"🧼 Successfully deleted host for {name}.{domain}")
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
        for ip in record.ips:
            if "." in ip:
                if "addrs" not in cpnr_record:
                    cpnr_record["addrs"] = {"stringItem": []}
                cpnr_record["addrs"]["stringItem"].append(ip)
            else:
                if "ip6AddressList" not in cpnr_record:
                    cpnr_record["ip6AddressList"] = {"stringItem": []}
                cpnr_record["ip6AddressList"]["stringItem"].append(ip)
        cpnr_record["zoneOrigin"] = primary_domain
        cpnr_record["createPtrRecords"] = True
        txt_record = get_txt_record(record.nb_record)

        edns.host.add(**cpnr_record)
        logger.info(f"🎨 Successfully created record for host {record.hostname} : {record.ips}")
        rrs = edns.rrset.get(record.hostname, zoneOrigin=primary_domain)
        rrs.rrList["CCMRRItem"].append({"rdata": txt_record, "rrClass": "IN", "rrType": "TXT"})
        if record.ttl > -1:
            for rr in rrs.rrList["CCMRRItem"]:
                rr["ttl"] = record.ttl

            for ip in record.ips:
                rzn = get_reverse_zone(ip, C.IPV6_PREFIX_SIZE, C.REVERSE_ZONE_MAP)
                ptr_name = re.sub(rf"\.{rzn}", "", ipaddress.ip_address(ip).reverse_pointer + ".")

                ptr_rrs = edns.rrset.get(ptr_name, zoneOrigin=rzn)
                if ptr_rrs:
                    for rr in ptr_rrs.rrList["CCMRRItem"]:
                        rr["ttl"] = record.ttl

                    ptr_rrs.save()

        rrs.save()
        logger.info(f"🎨 Successfully created TXT meta-record for host {record.hostname} in domain {primary_domain}")
        EDNS_MODIFIED = True
    elif isinstance(record, CNAMERecord):
        curr_edns = edns
        cpnr_record["name"] = record.alias
        cpnr_record["zoneOrigin"] = record.domain
        target = f"{record.host.hostname}.{record.host.domain}"
        cpnr_record["rrList"] = {"CCMRRItem": [{"rdata": target, "rrClass": "IN", "rrType": "CNAME", "ttl": record.ttl}]}

        curr_edns.rrset.add(**cpnr_record)
        logger.info(f"🎨 Successfully created CNAME record in domain {record.domain} for alias {record.alias} ==> {target}")
        EDNS_MODIFIED = True
    else:
        # PTR records are not created by themselves for the moment.
        logger.warning(f"⛔️ Unexpected record of type {type(record)}")


def dump_hosts(records: list[Union[ARecord, CNAMERecord, PTRRecord]], primary_domain: str, output_file: str) -> None:
    """Dump the A and CNAME records to a hosts-like file

    Args:
        :records list: List of records to dump
        :primary_domain str: Primary domain name to add if the record doesn't contain it
        :output_file str: Path to the output file
    """
    aliases = {}
    hosts = {}
    for record in records:
        if isinstance(record, PTRRecord):
            continue

        if isinstance(record, ARecord):
            fqdn = f"{record.hostname}.{primary_domain}"
            for ip in record.ips:
                hosts[ip] = fqdn
            if fqdn not in aliases:
                aliases[fqdn] = [fqdn, record.hostname]
            else:
                aliases[fqdn] += [fqdn, record.hostname]
        elif isinstance(record, CNAMERecord):
            fqdn = f"{record.host.hostname}.{record.host.domain}"
            if fqdn not in aliases:
                aliases[fqdn] = [f"{record.alias}.{record.domain}"]
            else:
                aliases[fqdn].append(f"{record.alias}.{record.domain}")

    with open(output_file, "a") as fd:
        for ip, hname in hosts.items():
            fd.write(f"{ip}\t{' '.join(aliases[hname])}\n")


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
    parser.add_argument("--dump-hosts", action="store_true", help="Dump records to a hosts file", required=False)
    parser.add_argument("--hosts-output", metavar="<OUTPUT_FILE>", help="Path to file to dump host records", required=False)

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

    if args.dump_hosts and not args.hosts_output:
        print("A hosts output file must be specified")
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

    if args.dump_hosts:
        with open(args.hosts_output, "w") as fd:
            fd.truncate()

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

        # 2. Get all IP addresses for the tenant.
        ip_addresses = list(enb.ipam.ip_addresses.filter(tenant_id=tenant.id))
        if len(ip_addresses) == 0:
            continue

        wip_records = DnsRecords()

        # 3. Use thread pools to obtain a list of records to delete then create (updates are done as a delete+create).
        launch_parallel_task(
            check_record, "check DNS record(s)", ip_addresses, "address", 20, False, primary_domain, edns, enb, wip_records
        )

        # 4. If desired, dump all hosts to a file.
        if args.dump_hosts:
            dump_hosts(wip_records.all, primary_domain, args.hosts_output)

        # 5. If doing a dry-run, only print out the changes.
        if args.dry_run:
            print_records(wip_records, primary_domain, tenant)
            continue

        # 6. Process records to be deleted first.  Use thread pools again to parallelize this.
        success = launch_parallel_task(delete_record, "delete DNS record", wip_records.deletes, None, 20, True, primary_domain, edns)

        if not success:
            break

        # 7. Process records to be added next.  Use thread pools again to parallelize this.
        launch_parallel_task(add_record, "add DNS record", wip_records.creates, "_name", 20, False, primary_domain, edns)

    # 7. Restart affected DNS servers.
    if not args.dry_run:
        # Technically nothing is modified in dry-run, but just to be safe.
        if EDNS_MODIFIED:
            restart_dns_servers(edns, ecdnses)
            pass


if __name__ == "__main__":
    main()
