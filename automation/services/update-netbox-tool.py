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

import argparse
import json
import re
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import CLEUCreds  # type: ignore
import requests
from cleu.config import Config as C  # type: ignore
import pynetbox
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore

CACHE_FILE = Path("netbox_tool_cache.json")

SKU_MAP: dict[str, str] = {
    "WS-C3560CX-12PD-S": "WS-C3560CX-12PD-S",
    "C9200CX-12P-2X2G": "C9200CX-12P-2X2G",
    "C9200CX-8UXG-2X": "C9200CX-8UXG-2X",
    "C9300-48U": "C9300-48P",
    "C9300-48P": "C9300-48P",
    "C9300-48UXM": "C9300-48P",
    "C9300X-48HX": "C9300X-48HX",
    "C9300-24U": "C9300-24P",
    "C9300-24P": "C9300-24P",
    "WS-C3750X-24P-S": "WS-C3750X-24P-S",
    "WS-C3750X-24": "WS-C3750X-24P-S",
    "WS-C3750X-48P-S": "WS-C3750X-48P-S",
    "WS-C3750X-48": "WS-C3750X-48P-S",
    "WS-C3560CG-8": "WS-C3560CG-8PC-S",
    "WS-C3560CG-8PC-S": "WS-C3560CG-8PC-S",
    "C9500-48Y4C": "C9500-48Y4C",
    "CMICR-4PT": "CMICR-4PT",
}

INTF_MAP: dict[str, str] = {"IDF": "loopback0", "Access": "Vlan127"}
INTF_CIDR_MAP: dict[str, int] = {"IDF": 32, "Access": 24}
SITE_MAP: dict[str, str] = {"IDF": "IDF Closet", "Access": "Conference Space"}
ROLE_MAP: dict[str, str] = {"IDF": "L3 Access Switch", "Access": "L2 Access Switch"}

MGMT_PREFIX = "10.127.0."
VRF_NAME = "default"
TENANT_NAME = "DC Infrastructure"
DNS_TTL = 300


@dataclass
class DeviceInfo:
    """Device information from Tool."""

    name: str
    type: str
    role: str
    site: str
    intf: str
    ip: str
    cidr: int
    v6: bool
    aliases: list[str] = field(default_factory=list)


@dataclass
class NetBoxObjects:
    """Cached NetBox API objects."""

    role_objs: dict[str, Any] = field(default_factory=dict)
    site_objs: dict[str, Any] = field(default_factory=dict)
    type_objs: dict[str, Any] = field(default_factory=dict)
    vrf_obj: Any = None
    tenant_obj: Any = None


@dataclass
class NetBoxSynchronizer:
    """Manages synchronization between Tool and NetBox."""

    netbox: pynetbox.api
    dns_domain: str
    objects: NetBoxObjects = field(default_factory=NetBoxObjects)

    def populate_netbox_objects(self) -> None:
        """Populate cached NetBox objects."""
        for val in ROLE_MAP.values():
            self.objects.role_objs[val] = self.netbox.dcim.device_roles.get(name=val)

        for val in SITE_MAP.values():
            self.objects.site_objs[val] = self.netbox.dcim.sites.get(name=val)

        for val in SKU_MAP.values():
            self.objects.type_objs[val] = self.netbox.dcim.device_types.get(part_number=val)

        self.objects.tenant_obj = self.netbox.tenancy.tenants.get(name=TENANT_NAME)
        self.objects.vrf_obj = self.netbox.ipam.vrfs.get(name=VRF_NAME)

    def _parse_device(self, tool_device: dict[str, Any]) -> DeviceInfo | None:
        """Parse a Tool device into DeviceInfo."""
        # Skip invalid IPs
        if tool_device.get("IPAddress") == "0.0.0.0":
            return None

        hostname = tool_device.get("Hostname", "")

        # Skip non-standard naming
        if not re.search(r"^[0-9A-Za-z]{3}-", hostname):
            return None

        sku = tool_device.get("SKU")
        if sku not in SKU_MAP:
            return None

        device_type = SKU_MAP[sku]

        # Check if IDF switch
        if match := re.search(r"^[0-9A-Za-z]{3}-[Xx](\d{3})", hostname):
            # IDF switch
            idf_num = match.group(1).lstrip("0")
            return DeviceInfo(
                name=hostname,
                type=device_type,
                role=ROLE_MAP["IDF"],
                site=SITE_MAP["IDF"],
                intf=INTF_MAP["IDF"],
                ip=f"{MGMT_PREFIX}{idf_num}",
                cidr=INTF_CIDR_MAP["IDF"],
                v6=True,
                aliases=[tool_device.get("Name", ""), tool_device.get("AssetTag", "")],
            )
        else:
            # Access switch
            return DeviceInfo(
                name=hostname,
                type=device_type,
                role=ROLE_MAP["Access"],
                site=SITE_MAP["Access"],
                intf=INTF_MAP["Access"],
                ip=tool_device.get("IPAddress", ""),
                cidr=INTF_CIDR_MAP["Access"],
                v6=False,
                aliases=[tool_device.get("Name", ""), tool_device.get("AssetTag", "")],
            )

    def get_devices_from_tool(self, tool_url: str) -> list[DeviceInfo]:
        """Fetch and parse devices from Tool."""
        url = f"http://{tool_url}/get/switches/json"

        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            tool_devices = response.json()
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Failed to fetch devices from Tool: {e}", file=sys.stderr)
            return []

        devices = []
        for tool_device in tool_devices:
            if device := self._parse_device(tool_device):
                devices.append(device)

        return devices

    def delete_device(self, device_name: str) -> None:
        """Delete a device from NetBox."""
        try:
            dev_obj = self.netbox.dcim.devices.get(name=device_name)
            if dev_obj:
                if dev_obj.primary_ip4:
                    dev_obj.primary_ip4.delete()
                dev_obj.delete()
        except Exception as e:
            print(f"WARNING: Failed to delete NetBox device {device_name}: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    def add_device(self, device: DeviceInfo) -> bool:
        """Add a device to NetBox."""
        role_obj = self.objects.role_objs.get(device.role)
        type_obj = self.objects.type_objs.get(device.type)
        site_obj = self.objects.site_objs.get(device.site)
        tenant_obj = self.objects.tenant_obj
        vrf_obj = self.objects.vrf_obj

        # Validate required objects
        if not role_obj:
            print(f"ERROR: Invalid role for {device.name}: {device.role}", file=sys.stderr)
            return False

        if not type_obj:
            print(f"ERROR: Invalid type for {device.name}: {device.type}", file=sys.stderr)
            return False

        if not site_obj:
            print(f"ERROR: Invalid site for {device.name}: {device.site}", file=sys.stderr)
            return False

        # Create device
        try:
            dev_obj = self.netbox.dcim.devices.create(
                name=device.name, role=role_obj.id, device_type=type_obj.id, site=site_obj.id, tenant=tenant_obj.id
            )
        except Exception as e:
            print(f"ERROR: Failed to create NetBox entry for {device.name}: {e}", file=sys.stderr)
            return False

        if not dev_obj:
            print(f"ERROR: Failed to create NetBox entry for {device.name}", file=sys.stderr)
            return False

        # Create IP address
        try:
            ip_obj = self.netbox.ipam.ip_addresses.create(address=f"{device.ip}/{device.cidr}", tenant=tenant_obj.id, vrf=vrf_obj.id)
        except Exception as e:
            dev_obj.delete()
            print(f"ERROR: Failed to create IP entry for {device.ip}: {e}", file=sys.stderr)
            return False

        if not ip_obj:
            dev_obj.delete()
            print(f"ERROR: Failed to create IP entry for {device.ip}", file=sys.stderr)
            return False

        # Find interface and assign IP
        dev_intf = self.netbox.dcim.interfaces.get(device=dev_obj.name, name=device.intf)
        if not dev_intf:
            dev_obj.delete()
            ip_obj.delete()
            print(f"ERROR: Failed to find interface {device.intf} for {device.name}", file=sys.stderr)
            return False

        # Update IP with interface and custom fields
        ip_obj.assigned_object_id = dev_intf.id
        ip_obj.assigned_object_type = "dcim.interface"
        device.aliases.sort()
        ip_obj.custom_fields["CNAMEs"] = ",".join(device.aliases)
        ip_obj.custom_fields["dns_ttl"] = DNS_TTL
        ip_obj.custom_fields["v6_based_on_v4"] = device.v6
        ip_obj.save()

        # Set primary IP
        dev_obj.primary_ip4 = ip_obj.id
        dev_obj.save()

        return True

    def device_needs_update(self, device: DeviceInfo) -> bool:
        """Check if a device needs to be updated in NetBox."""
        dev_obj = self.netbox.dcim.devices.get(name=device.name)
        if not dev_obj:
            return True

        ip_obj = dev_obj.primary_ip4
        if not ip_obj:
            return True

        # Check if IP matches
        if ip_obj.address != f"{device.ip}/{device.cidr}":
            return True

        # Check if CNAMEs match
        cnames = ip_obj.custom_fields.get("CNAMEs", "")
        device.aliases.sort()
        expected_cnames = ",".join(device.aliases)

        return cnames != expected_cnames


def load_cache(cache_file: Path) -> list[str]:
    """Load cached device names."""
    if not cache_file.exists():
        return []

    try:
        return json.loads(cache_file.read_text())
    except Exception as e:
        print(f"WARNING: Failed to load cache: {e}", file=sys.stderr)
        return []


def save_cache(cache_file: Path, device_names: list[str]) -> None:
    """Save device names to cache atomically."""
    temp_file = cache_file.with_suffix(f"{cache_file.suffix}.tmp")
    try:
        temp_file.write_text(json.dumps(device_names, indent=2))
        temp_file.replace(cache_file)
    except Exception as e:
        print(f"ERROR: Failed to save cache: {e}", file=sys.stderr)
        if temp_file.exists():
            temp_file.unlink()


def main() -> int:
    """Synchronize devices from Tool to NetBox."""
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Synchronize devices from Tool to NetBox")
    parser.add_argument("--purge", action="store_true", help="Force re-creation of all devices")
    parser.add_argument("--log", "-l", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    # Initialize NetBox connection
    import os

    os.environ["NETBOX_ADDRESS"] = C.NETBOX_SERVER
    os.environ["NETBOX_API_TOKEN"] = CLEUCreds.NETBOX_API_TOKEN

    netbox = pynetbox.api(C.NETBOX_SERVER, token=CLEUCreds.NETBOX_API_TOKEN)
    synchronizer = NetBoxSynchronizer(netbox=netbox, dns_domain=C.DNS_DOMAIN)
    synchronizer.populate_netbox_objects()

    # Load previous records
    prev_records = load_cache(CACHE_FILE)

    # Get current devices from Tool
    devices = synchronizer.get_devices_from_tool(C.TOOL)
    if not devices:
        print("WARNING: No devices retrieved from Tool", file=sys.stderr)
        return 1

    # Remove devices that no longer exist in Tool
    current_names = {dev.name.replace(f".{C.DNS_DOMAIN}", "") for dev in devices}
    for prev_name in prev_records:
        if prev_name not in current_names:
            if args.log:
                print(f"INFO: Removing obsolete device {prev_name}")
            synchronizer.delete_device(prev_name)

    # Process each device
    records = []
    for device in devices:
        hostname = device.name.replace(f".{C.DNS_DOMAIN}", "")
        records.append(hostname)

        # Handle purge flag
        if args.purge:
            if args.log:
                print(f"INFO: Purging device {hostname}")
            synchronizer.delete_device(hostname)

        # Check if device exists
        dev_obj = netbox.dcim.devices.get(name=hostname)

        if not dev_obj:
            # Check for IP conflict
            ip_obj = netbox.ipam.ip_addresses.get(address=f"{device.ip}/{device.cidr}")
            if ip_obj and ip_obj.assigned_object:
                old_device = ip_obj.assigned_object.device
                if args.log:
                    print(f"INFO: Found IP conflict {device.ip} => {old_device.name}")
                synchronizer.delete_device(old_device.name)

            # Add new device
            if args.log:
                print(f"INFO: Adding device {hostname}")
            synchronizer.add_device(device)

        elif synchronizer.device_needs_update(device):
            # Update existing device
            if args.log:
                print(f"INFO: Updating device {hostname}")
            synchronizer.delete_device(hostname)
            synchronizer.add_device(device)
        else:
            # Device is up to date
            if args.log:
                print(f"INFO: Device {hostname} is up to date")

    # Save cache
    save_cache(CACHE_FILE, records)

    if args.log:
        print(f"\nSynchronization complete. {len(records)} devices processed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
