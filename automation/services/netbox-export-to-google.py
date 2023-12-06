#!/usr/bin/env python

from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import pynetbox
import os
from typing import Any
import traceback
import netaddr
import ipaddress
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

CREDS_FILE = "gs_token.json"
SHEET_ID = "1kKOqbK_y3l6Ume-MSkLg1nTVbw571mcq3EOQw5IWuWQ"


def export_ips(nb: Any, gs_service: Any) -> None:
    """Export NetBox IPs to a Google Sheet"""

    # Get all IP addresses from NetBox
    ips = list(nb.ipam.ip_addresses.all())

    new_values = []

    headers = [
        "Address",
        "VRF",
        "Status",
        "Role",
        "Tenant",
        "Assigned",
        "DNS name",
        "Description",
        "ID",
        "Tenant Group",
        "NAT (Inside)",
        "NAT (Outside)",
        "Comments",
        "Tags",
        "Created",
        "Last updated",
        "Interface",
        "Parent",
        "List of additional CNAMEs",
        "End of Row",
    ]

    new_values.append(headers)

    for ip in ips:
        tenant = ""
        tenant_group = ""
        if ip.tenant:
            ip.tenant.full_details()
            tenant = ip.tenant.name
            if ip.tenant.group:
                tenant_group = str(ip.tenant.group)

        parent = ""
        if ip.assigned_object:
            if ip.assigned_object_type == "virtualization.vminterface":
                parent = ip.assigned_object.virtual_machine.name
            elif ip.assigned_object_type == "dcim.interface":
                parent = ip.assigned_object.device.name

        role = ""
        if ip.role:
            role = str(ip.role)

        nat_inside = ""
        if ip.nat_inside:
            nat_inside = str(nat_inside)

        nat_outside = ""
        if len(ip.nat_outside) > 0:
            nat_outside = ",".join(ip.nat_outside)

        vrf = ""
        if ip.vrf:
            vrf = str(ip.vrf)

        tags = ""
        if len(ip.tags) > 0:
            tags = ",".join(ip.tags)

        interface = ""
        if ip.assigned_object:
            interface = str(ip.assigned_object)

        new_values.append(
            [
                ip.address,  # Address
                vrf,  # VRF
                ip.status.label,  # Status
                role,  # Role
                tenant,  # Tenant
                ip.assigned_object_id,  # Assigned
                ip.dns_name,  # DNS name
                ip.description,  # Description
                ip.id,  # ID
                tenant_group,  # Tenant Group
                nat_inside,  # NAT (Inside)
                nat_outside,  # NAT (Outside)
                ip.comments,  # Comments
                tags,  # Tags
                str(ip.created),  # Created
                str(ip.last_updated),  # Last updated
                interface,  # Interface
                parent,  # Parent
                ip.custom_fields["CNAMEs"],  # List of additional CNAMEs
                ".",  # End of Row
            ]
        )

    ip_sheet = gs_service.spreadsheets()
    ip_sheet.values().update(
        spreadsheetId=SHEET_ID, range="IP Addresses!A1:ZZ", body={"values": new_values}, valueInputOption="RAW"
    ).execute()


def _get_prefix_utilization(prefix: Any, nb: Any) -> float:
    """Get the utilization of a prefix"""
    if prefix.mark_utilized:
        return 100.0

    prefix_size = ipaddress.ip_network(prefix.prefix).num_addresses
    child_ips = nb.ipam.ip_addresses.filter(parent=prefix.prefix, vrf_id=prefix.vrf.id)
    prefixlen = ipaddress.ip_network(prefix.prefix).prefixlen

    if prefix.status.label.lower() == "container":
        queryset = nb.ipam.prefixes.filter(within=prefix.prefix, vrf_id=prefix.vrf.id)
        child_prefixes = netaddr.IPSet([p.prefix for p in queryset])
        utilization = float(child_prefixes.size) / prefix_size * 100
    else:
        child_ipset = netaddr.IPSet([_.address for _ in child_ips])
        if prefix.family.label == "IPv4" and prefixlen < 31 and not prefix.is_pool:
            prefix_size -= 2
        utilization = float(child_ipset.size) / prefix_size * 100

    return min(utilization, 100)


def export_prefixes(nb: Any, gs_service: Any) -> None:
    """Export NetBox IP prefixes to a Google Sheet"""

    # Get all IP prefixes from NetBox
    prefixes = list(nb.ipam.prefixes.all())

    new_values = []

    headers = [
        "Prefix",
        "Status",
        "Children",
        "VRF",
        "Utilization",
        "Tenant",
        "Site",
        "VLAN",
        "Role",
        "Description",
        "Pool",
        "ID",
        "Prefix (Flat)",
        "Tenant Group",
        "VLAN Group",
        "Mark Utilized",
        "Comments",
        "Tags",
        "Created",
        "Last updated",
        "Depth",
    ]

    new_values.append(headers)

    for prefix in prefixes:
        tenant = ""
        tenant_group = ""
        if prefix.tenant:
            prefix.tenant.full_details()
            tenant = prefix.tenant.name
            if prefix.tenant.group:
                tenant_group = str(prefix.tenant.group)

        vlan = ""
        vlan_group = ""
        if prefix.vlan:
            prefix.vlan.full_details()
            vlan = f"{prefix.vlan.name} ({prefix.vlan.vid})"
            if prefix.vlan.group:
                vlan_group = str(prefix.vlan.group)

        site = ""
        if prefix.site:
            site = prefix.site.name

        role = ""
        if prefix.role:
            role = str(prefix.role)

        vrf = ""
        if prefix.vrf:
            vrf = str(prefix.vrf)

        tags = ""
        if len(prefix.tags) > 0:
            tags = ",".join(prefix.tags)

        row = {
            "Prefix": prefix.prefix,
            "Status": prefix.status.label,
            "Children": prefix.children,
            "VRF": vrf,
            "Utilized": "%.2f" % _get_prefix_utilization(prefix, nb) + "%",
            "Tenant": tenant,
            "Site": site,
            "VLAN": vlan,
            "Role": role,
            "Description": prefix.description,
            "Pool": prefix.is_pool,
            "ID": prefix.id,
            "Prefix (Flat)": prefix.prefix,
            "Tenant Group": tenant_group,
            "VLAN Group": vlan_group,
            "Mark Utilized": prefix.mark_utilized,
            "Comments": prefix.comments,
            "Tags": tags,
            "Created": str(prefix.created),
            "Last updated": str(prefix.last_updated),
            "Depth": prefix._depth,
        }
        new_values.append(list(row.values()))

    prefix_sheet = gs_service.spreadsheets()
    prefix_sheet.values().update(
        spreadsheetId=SHEET_ID, range="IP Prefixes!A1:ZZ", body={"values": new_values}, valueInputOption="RAW"
    ).execute()


def export_vlans(nb: Any, gs_service: Any) -> None:
    """Export VLANs from NetBox to a Google Sheet"""

    # Get all VLANs from NetBox
    vlans = list(nb.ipam.vlans.all())

    new_values = []

    headers = [
        "VID",
        "Name",
        "Site",
        "Group",
        "Prefixes",
        "Tenant",
        "Status",
        "Role",
        "Description",
        "ID",
        "Tenant Group",
        "Comments",
        "Tags",
        "L2VPN",
        "Created",
        "Last updated",
    ]

    new_values.append(headers)

    for vlan in vlans:
        tenant = ""
        tenant_group = ""
        if vlan.tenant:
            vlan.tenant.full_details()
            tenant = vlan.tenant.name
            if vlan.tenant.group:
                tenant_group = str(vlan.tenant.group)

        group = ""
        if vlan.group:
            group = str(vlan.group)

        site = ""
        if vlan.site:
            site = vlan.site.name

        role = ""
        if vlan.role:
            role = str(vlan.role)

        tags = ""
        if len(vlan.tags) > 0:
            tags = ",".join(vlan.tags)

        l2vpn = ""
        if vlan.l2vpn_termination:
            l2vpn = str(vlan.l2vpn_termination)

        prefixes = ",".join([_.prefix for _ in list(nb.ipam.prefixes.filter(vlan_id=vlan.id))])

        row = {
            "VID": vlan.vid,
            "Name": vlan.name,
            "Site": site,
            "Group": group,
            "Prefixes": prefixes,
            "Tenant": tenant,
            "Status": vlan.status.label,
            "Role": role,
            "Description": vlan.description,
            "ID": vlan.id,
            "Tenant Group": tenant_group,
            "Comments": vlan.comments,
            "Tags": tags,
            "L2VPN": l2vpn,
            "Created": str(vlan.created),
            "Last updated": str(vlan.last_updated),
        }
        new_values.append(list(row.values()))

    vlan_sheet = gs_service.spreadsheets()
    vlan_sheet.values().update(spreadsheetId=SHEET_ID, range="VLANs!A1:ZZ", body={"values": new_values}, valueInputOption="RAW").execute()


def main() -> int:
    """Export NetBox IP address data to a Google Sheet"""
    global creds, SHEET_ID

    # Connect to NetBox
    nb = pynetbox.api(C.NETBOX_SERVER, CLEUCreds.NETBOX_API_TOKEN)

    gs_service = build("sheets", "v4", credentials=creds)

    try:
        export_ips(nb, gs_service)
    except Exception as e:
        print(f"ERROR: Failed to export IP addresses to Google Sheets: {e}")
        traceback.print_exc()
        return 1

    try:
        export_prefixes(nb, gs_service)
    except Exception as e:
        print(f"ERROR: Failed to export IP prefixes to Google Sheets: {e}")
        traceback.print_exc()
        return 1

    try:
        export_vlans(nb, gs_service)
    except Exception as e:
        print(f"ERROR: Failed to export VLANs to Google Sheets: {e}")
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    if not os.path.isfile(CREDS_FILE):
        print(f"ERROR: Token file {CREDS_FILE} does not exist!  Please re-authenticate this app.")
        exit(1)

    creds = Credentials.from_authorized_user_file(CREDS_FILE, ["https://www.googleapis.com/auth/spreadsheets"])
    if not creds.valid:
        creds.refresh(Request())

    with open(CREDS_FILE, "w") as fd:
        fd.write(creds.to_json())

    exit(main())
