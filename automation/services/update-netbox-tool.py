#!/usr/bin/env python
#
# Copyright (c) 2017-2023  Joe Clarke <jclarke@cisco.com>
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


from __future__ import print_function
from elemental_utils import ElementalNetbox
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore
import json
import sys
import re
import os
import argparse
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

CACHE_FILE = "netbox_tool_cache.json"
SKU_MAP = {
    "WS-C3560CX-12PD-S": "WS-C3560CX-12PD-S",
    "C9300-48U": "C9300-48P",
    "C9300-48P": "C9300-48P",
    "C9300-24U": "C9300-24P",
    "C9300-24P": "C9300-24P",
    "WS-C3750X-24P-S": "WS-C3750X-24P-S",
    "WS-C3750X-48P-S": "WS-C3750X-48P-S",
    "WS-C3560CG-8": "WS-C3560CG-8PC-S",
    "WS-C3560CG-8PC-S": "WS-C3560CG-8PC-S",
    "C9500-48Y4C": "C9500-48Y4C",
}
TYPE_OBJ_MAP = {}

INTF_MAP = {"IDF": "loopback0", "Access": "Vlan127"}
INTF_CIDR_MAP = {"IDF": 32, "Access": 24}

SITE_MAP = {"IDF": "IDF Closet", "Access": "Conference Space"}
SITE_OBJ_MAP = {}

ROLE_MAP = {"IDF": "L3 Access Switch", "Access": "L2 Access Switch"}
ROLE_OBJ_MAP = {}

VRF_NAME = "default"
VRF_OBJ = None
TENANT_NAME = "Infrastructure"
TENANT_OBJ = None


def get_devs():
    url = f"http://{C.TOOL}/get/switches/json"

    devices = []
    response = requests.request("GET", url)
    code = response.status_code
    if code == 200:
        j = response.json()

        for dev in j:
            dev_dic = {}
            if dev["IPAddress"] == "0.0.0.0":
                continue

            # Do not add MDF switches (or APs)
            if not re.search(r"^[0-9A-Za-z]{3}-", dev["Hostname"]):
                continue

            if dev["SKU"] not in SKU_MAP:
                continue

            dev_dic["type"] = SKU_MAP[dev["SKU"]]
            if re.search(r"^[0-9A-Za-z]{3}-[Xx]", dev["Hostname"]):
                dev_dic["role"] = ROLE_MAP["IDF"]
                dev_dic["intf"] = INTF_MAP["IDF"]
                dev_dic["cidr"] = INTF_CIDR_MAP["IDF"]
                dev_dic["site"] = SITE_MAP["IDF"]
            else:
                dev_dic["role"] = ROLE_MAP["Access"]
                dev_dic["intf"] = INTF_MAP["Access"]
                dev_dic["cidr"] = INTF_CIDR_MAP["Access"]
                dev_dic["site"] = SITE_MAP["Access"]

            dev_dic["name"] = dev["Hostname"]
            dev_dic["aliases"] = [f"{dev['Name']}", f"{dev['AssetTag']}"]

            dev_dic["ip"] = dev["IPAddress"]

            devices.append(dev_dic)

    return devices


def delete_netbox_device(enb: ElementalNetbox, dname: str) -> None:
    try:
        dev_obj = enb.dcim.devices.get(name=dname)
        if dev_obj:
            if dev_obj.primary_ip4:
                dev_obj.primary_ip4.delete()

            dev_obj.delete()
    except Exception as e:
        sys.stderr.write(f"WARNING: Failed to delete NetBox device for {dname}\n")


def populate_objects(enb: ElementalNetbox) -> None:
    global ROLE_OBJ_MAP, SITE_OBJ_MAP, TYPE_OBJ_MAP, TENANT_OBJ, VRF_OBJ

    for _, val in ROLE_MAP.items():
        ROLE_OBJ_MAP[val] = enb.dcim.device_roles.get(name=val)

    for _, val in SITE_MAP.items():
        SITE_OBJ_MAP[val] = enb.dcim.sites.get(name=val)

    for _, val in SKU_MAP.items():
        TYPE_OBJ_MAP[val] = enb.dcim.device_types.get(part_number=val)

    TENANT_OBJ = enb.tenancy.tenants.get(name=TENANT_NAME)
    VRF_OBJ = enb.ipam.vrfs.get(name=VRF_NAME)


def add_netbox_device(enb: ElementalNetbox, dev: dict) -> None:
    role_obj = ROLE_OBJ_MAP[dev["role"]]
    type_obj = TYPE_OBJ_MAP[dev["type"]]
    tenant_obj = TENANT_OBJ
    site_obj = SITE_OBJ_MAP[dev["site"]]
    vrf_obj = VRF_OBJ

    if not role_obj:
        sys.stderr.write(f"ERROR: Invalid role for {dev['name']}: {dev['role']}\n")
        return

    if not type_obj:
        sys.stderr.write(f"ERROR: Invalid type for {dev['name']}: {dev['type']}\n")
        return

    if not site_obj:
        sys.stderr.write(f"ERROR: Invalid site for {dev['name']}: {dev['site']}\n")
        return

    dev_obj = enb.dcim.devices.create(
        name=dev["name"], device_role=role_obj.id, device_type=type_obj.id, site=site_obj.id, tenant=tenant_obj.id
    )

    if not dev_obj:
        sys.stderr.write(f"ERROR: Failed to create NetBox entry for {dev['name']}\n")
        return

    ip_obj = enb.ipam.ip_addresses.create(address=f"{dev['ip']}/{dev['cidr']}", tenant=tenant_obj.id, vrf=vrf_obj.id)

    if not ip_obj:
        dev_obj.delete()
        sys.stderr.write(f"ERROR: Failed to create IP entry for {dev['ip']}\n")
        return

    dev_intf = enb.dcim.interfaces.get(device=dev_obj.name, name=dev["intf"])
    if not dev_intf:
        dev_obj.delete()
        ip_obj.delete()
        sys.stderr.write(f"ERROR: Failed to find interface {dev['intf']} for {dev['name']}\n")
        return

    ip_obj.assigned_object_id = dev_intf.id
    ip_obj.assigned_object_type = "dcim.interface"
    dev["aliases"].sort()
    ip_obj.custom_fields["CNAMEs"] = ",".join(dev["aliases"])
    ip_obj.save()

    dev_obj.primary_ip4 = ip_obj.id
    dev_obj.save()


if __name__ == "__main__":

    os.environ["NETBOX_ADDRESS"] = C.NETBOX_SERVER
    os.environ["NETBOX_API_TOKEN"] = CLEUCreds.NETBOX_API_TOKEN

    parser = argparse.ArgumentParser(description="Usage:")

    # script arguments
    parser.add_argument("--purge", help="Purge previous records", action="store_true")
    args = parser.parse_args()

    enb = ElementalNetbox()
    populate_objects(enb)

    prev_records = []

    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as fd:
            prev_records = json.load(fd)

    devs = get_devs()
    for record in prev_records:
        found_record = False
        for dev in devs:
            hname = dev["name"].replace(f".{C.DNS_DOMAIN}", "")
            if record == hname:
                found_record = True
                break
        if found_record:
            continue

        delete_netbox_device(enb, record)

    records = []
    for dev in devs:
        hname = dev["name"].replace(f".{C.DNS_DOMAIN}", "")

        records.append(hname)
        if args.purge:
            delete_netbox_device(enb, hname)

        dev_obj = enb.dcim.devices.get(name=hname)
        if not dev_obj:
            ip_obj = enb.ipam.ip_addresses.get(address=f"{dev['ip']}/{dev['cidr']}")
            cur_entry = None
            if ip_obj and ip_obj.assigned_object:
                cur_entry = ip_obj.assigned_object.device

            if cur_entry:
                print(f"INFO: Found old entry for IP {dev['ip']} => {cur_entry.name}")

                delete_netbox_device(enb, cur_entry.name)

            add_netbox_device(enb, dev)
        else:
            cur_entry = dev_obj
            create_new = True
            ip_obj = dev_obj.primary_ip4
            if ip_obj:
                cnames = ip_obj.custom_fields["CNAMEs"]
                if not cnames:
                    cnames = ""

                dev["aliases"].sort()
                cname_str = ",".join(dev["aliases"])

                if cname_str == cnames:
                    create_new = False

            if create_new:
                print(f"INFO: Deleting entry for {hname}")
                delete_netbox_device(enb, hname)

                add_netbox_device(enb, dev)
            else:
                # print("Not creating a new entry for {} as it already exists".format(dev["name"]))
                pass

    with open(CACHE_FILE, "w") as fd:
        json.dump(records, fd, indent=4)
