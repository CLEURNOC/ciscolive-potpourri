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

from __future__ import annotations

import ipaddress
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import CLEUCreds  # type: ignore
import netaddr
import pynetbox
from cleu.config import Config as C  # type: ignore
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

CREDS_FILE = Path("gs_token.json")
SHEET_ID = "1kKOqbK_y3l6Ume-MSkLg1nTVbw571mcq3EOQw5IWuWQ"


@dataclass
class NetBoxExporter:
    """Handles exporting NetBox data to Google Sheets."""

    netbox_api: Any
    sheets_service: Any
    sheet_id: str

    def _clear_and_update_sheet(self, sheet_name: str, values: list[list[Any]]) -> None:
        """Clear a sheet and update it with new values."""
        sheet = self.sheets_service.spreadsheets()
        sheet.values().clear(spreadsheetId=self.sheet_id, range=sheet_name, body={}).execute()
        sheet.values().update(
            spreadsheetId=self.sheet_id, range=f"{sheet_name}!A1:ZZ", body={"values": values}, valueInputOption="RAW"
        ).execute()

    def export_ips(self) -> None:
        """Export NetBox IPs to a Google Sheet."""
        # Get all IP addresses from NetBox
        ips = list(self.netbox_api.ipam.ip_addresses.all())

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
        ]

        rows = [headers]

        for ip in ips:
            # Extract tenant information
            tenant = ""
            tenant_group = ""
            if ip.tenant:
                ip.tenant.full_details()
                tenant = ip.tenant.name
                if ip.tenant.group:
                    tenant_group = str(ip.tenant.group)

            # Determine parent device/VM
            parent = ""
            if ip.assigned_object:
                match ip.assigned_object_type:
                    case "virtualization.vminterface":
                        parent = ip.assigned_object.virtual_machine.name
                    case "dcim.interface":
                        parent = ip.assigned_object.device.name

            # Extract other fields with safe defaults
            role = str(ip.role) if ip.role else ""
            nat_inside = str(ip.nat_inside) if ip.nat_inside else ""
            nat_outside = ",".join(ip.nat_outside) if ip.nat_outside else ""
            vrf = str(ip.vrf) if ip.vrf else ""
            tags = ",".join(str(tag) for tag in ip.tags) if ip.tags else ""
            interface = str(ip.assigned_object) if ip.assigned_object else ""

            row = [
                ip.address,
                vrf,
                ip.status.label,
                role,
                tenant,
                ip.assigned_object_id,
                ip.dns_name,
                ip.description,
                ip.id,
                tenant_group,
                nat_inside,
                nat_outside,
                ip.comments,
                tags,
                str(ip.created),
                str(ip.last_updated),
                interface,
                parent,
                ip.custom_fields.get("CNAMEs", ""),
            ]
            rows.append(row)

        self._clear_and_update_sheet("IP Addresses", rows)

    def _get_prefix_utilization(self, prefix: Any) -> float:
        """Calculate the utilization percentage of a prefix."""
        if prefix.mark_utilized:
            return 100.0

        prefix_size = ipaddress.ip_network(prefix.prefix).num_addresses
        child_ips = self.netbox_api.ipam.ip_addresses.filter(parent=prefix.prefix, vrf_id=prefix.vrf.id)
        prefixlen = ipaddress.ip_network(prefix.prefix).prefixlen

        if prefix.status.label.lower() == "container":
            queryset = self.netbox_api.ipam.prefixes.filter(within=prefix.prefix, vrf_id=prefix.vrf.id)
            child_prefixes = netaddr.IPSet([p.prefix for p in queryset])
            utilization = float(child_prefixes.size) / prefix_size * 100
        else:
            child_ipset = netaddr.IPSet([ip.address for ip in child_ips])
            if prefix.family.label == "IPv4" and prefixlen < 31 and not prefix.is_pool:
                prefix_size -= 2
            utilization = float(child_ipset.size) / prefix_size * 100

        return min(utilization, 100.0)

    def export_prefixes(self) -> None:
        """Export NetBox IP prefixes to a Google Sheet."""
        # Get all IP prefixes from NetBox
        prefixes = list(self.netbox_api.ipam.prefixes.all())

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

        rows = [headers]

        for prefix in prefixes:
            # Extract tenant information
            tenant = ""
            tenant_group = ""
            if prefix.tenant:
                prefix.tenant.full_details()
                tenant = prefix.tenant.name
                if prefix.tenant.group:
                    tenant_group = str(prefix.tenant.group)

            # Extract VLAN information
            vlan = ""
            vlan_group = ""
            if prefix.vlan:
                prefix.vlan.full_details()
                vlan = f"{prefix.vlan.name} ({prefix.vlan.vid})"
                if prefix.vlan.group:
                    vlan_group = str(prefix.vlan.group)

            # Site field (currently commented out in original)
            site = ""
            # if prefix.site:
            #     site = prefix.site.name

            # Extract other fields with safe defaults
            role = str(prefix.role) if prefix.role else ""
            vrf = str(prefix.vrf) if prefix.vrf else ""
            tags = ",".join(prefix.tags) if prefix.tags else ""
            utilization = f"{self._get_prefix_utilization(prefix):.2f}%"

            row = [
                prefix.prefix,
                prefix.status.label,
                prefix.children,
                vrf,
                utilization,
                tenant,
                site,
                vlan,
                role,
                prefix.description,
                prefix.is_pool,
                prefix.id,
                prefix.prefix,
                tenant_group,
                vlan_group,
                prefix.mark_utilized,
                prefix.comments,
                tags,
                str(prefix.created),
                str(prefix.last_updated),
                prefix._depth,
            ]
            rows.append(row)

        self._clear_and_update_sheet("IP Prefixes", rows)

    def export_vlans(self) -> None:
        """Export VLANs from NetBox to a Google Sheet."""
        # Get all VLANs from NetBox
        vlans = list(self.netbox_api.ipam.vlans.all())

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

        rows = [headers]

        for vlan in vlans:
            # Extract tenant information
            tenant = ""
            tenant_group = ""
            if vlan.tenant:
                vlan.tenant.full_details()
                tenant = vlan.tenant.name
                if vlan.tenant.group:
                    tenant_group = str(vlan.tenant.group)

            # Extract other fields with safe defaults
            group = str(vlan.group) if vlan.group else ""
            site = vlan.site.name if vlan.site else ""
            role = str(vlan.role) if vlan.role else ""
            tags = ",".join(vlan.tags) if vlan.tags else ""
            l2vpn = str(vlan.l2vpn_termination) if vlan.l2vpn_termination else ""
            prefixes = ",".join(p.prefix for p in self.netbox_api.ipam.prefixes.filter(vlan_id=vlan.id))

            row = [
                vlan.vid,
                vlan.name,
                site,
                group,
                prefixes,
                tenant,
                vlan.status.label,
                role,
                vlan.description,
                vlan.id,
                tenant_group,
                vlan.comments,
                tags,
                l2vpn,
                str(vlan.created),
                str(vlan.last_updated),
            ]
            rows.append(row)

        self._clear_and_update_sheet("VLANs", rows)

    def export_all(self) -> None:
        """Export all NetBox data to Google Sheets."""
        self.export_ips()
        self.export_prefixes()
        self.export_vlans()


def load_and_refresh_credentials(creds_file: Path) -> Credentials:
    """Load Google Sheets credentials and refresh if needed."""
    if not creds_file.exists():
        print(f"ERROR: Token file {creds_file} does not exist! Please re-authenticate this app.", file=sys.stderr)
        sys.exit(1)

    creds = Credentials.from_authorized_user_file(str(creds_file), ["https://www.googleapis.com/auth/spreadsheets"])

    if not creds.valid:
        creds.refresh(Request())

        # Create backup before updating
        backup_file = creds_file.with_suffix(f"{creds_file.suffix}.bak")
        if creds_file.exists():
            try:
                backup_file.write_text(creds_file.read_text())
            except Exception as e:
                print(f"WARNING: Failed to create backup of credentials: {e}", file=sys.stderr)

        # Write new credentials atomically to prevent truncation
        new_creds_json = creds.to_json()
        if not new_creds_json or len(new_creds_json.strip()) == 0:
            print("ERROR: Credentials JSON is empty, refusing to write", file=sys.stderr)
            sys.exit(1)

        temp_file = creds_file.with_suffix(f"{creds_file.suffix}.tmp")
        try:
            temp_file.write_text(new_creds_json)
            temp_file.replace(creds_file)
        except Exception as e:
            print(f"ERROR: Failed to update credentials file: {e}", file=sys.stderr)
            if temp_file.exists():
                temp_file.unlink()
            sys.exit(1)

    return creds


def main() -> int:
    """Export NetBox data to Google Sheets."""
    # Load credentials
    creds = load_and_refresh_credentials(CREDS_FILE)

    # Connect to NetBox
    netbox_api = pynetbox.api(C.NETBOX_SERVER, CLEUCreds.NETBOX_API_TOKEN)
    # XXX Disable when back in prod
    # netbox_api.http_session.verify = False

    # Build Google Sheets service
    sheets_service = build("sheets", "v4", credentials=creds)

    # Create exporter and run exports
    exporter = NetBoxExporter(netbox_api=netbox_api, sheets_service=sheets_service, sheet_id=SHEET_ID)

    try:
        exporter.export_all()
        return 0
    except Exception as e:
        print(f"ERROR: Failed to export NetBox data to Google Sheets: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
