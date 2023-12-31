#!/usr/bin/env python
#
# Copyright (c) 2017-2024  Joe Clarke <jclarke@cisco.com>
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
import pickle
import os.path
import os
from googleapiclient.discovery import build
from elemental_utils import ElementalNetbox
from pynetbox.models.ipam import IpAddresses
from sparker import Sparker, MessageType  # type: ignore
import sys
import re
import subprocess
import ipaddress
import random
import argparse
from argparse import Namespace
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

DC_TEAM = {"Joe": "jclarke@cisco.com", "Anthony": "anjesani@cisco.com", "Jara": "josterfe@cisco.com"}

JUMP_HOSTS = ["10.100.252.26", "10.100.252.27", "10.100.252.28", "10.100.252.29"]

DC_MAP = {
    "DC1": ["dc1_datastore_1", "dc1_datastore_2"],
    "DC2": ["dc2_datastore_1", "dc2_datastore_2"],
    # "HyperFlex-DC1": ["DC1-HX-DS-01", "DC1-HX-DS-02"],
    # "HyperFlex-DC2": ["DC2-HX-DS-01", "DC2-HX-DS-02"],
}

DEFAULT_CLUSTER = "FlexPod"

# HX_DCs = {"HyperFlex-DC1": 1, "HyperFlex-DC2": 1}

IP4_SUBNET = "10.100."
IP6_PREFIX = "2a11:d940:2:"
STRETCHED_OCTET = 252
GW_OCTET = 254

# Map VMware VLAN names to NetBox names
# VLAN_MAP = {"CISCO_LABS": "Cisco-Labs", "SESSION_RECORDING": "Session-Recording", "WIRED_DEFAULT": "Wired-Default"}

NETWORK_MAP = {
    "Cross-DC-VMs": {
        "subnet": "{}{}.0/24".format(IP4_SUBNET, STRETCHED_OCTET),
        "gw": "{}{}.{}".format(IP4_SUBNET, STRETCHED_OCTET, GW_OCTET),
        "prefix": "{}64{}::".format(IP6_PREFIX, format(int(STRETCHED_OCTET), "x")),
        "gw6": "{}64{}::{}".format(IP6_PREFIX, format(int(STRETCHED_OCTET), "x"), format(int(GW_OCTET), "x")),
    },
    "DC1-VMs": {
        "subnet": "{}253.0/24".format(IP4_SUBNET),
        "gw": "{}253.{}".format(IP4_SUBNET, GW_OCTET),
        "prefix": "{}64fd::".format(IP6_PREFIX),
        "gw6": "{}64fd::{}".format(IP6_PREFIX, format(int(GW_OCTET), "x")),
    },
    "DC2-VMs": {
        "subnet": "{}254.0/24".format(IP4_SUBNET),
        "gw": "{}254.{}".format(IP4_SUBNET, GW_OCTET),
        "prefix": "{}64fe::".format(IP6_PREFIX),
        "gw6": "{}64fe::{}".format(IP6_PREFIX, format(int(GW_OCTET), "x")),
    },
    "Public-Internet": {
        "subnet": "83.97.13.128/27",
        "gw": "83.97.13.158",
        "prefix": "{}c8fd::".format(IP6_PREFIX),
        "gw6": "{}c8fd::{}".format(IP6_PREFIX, format(158, "x")),
    },
}

OSTYPE_LIST = [
    (r"(?i)ubuntu ?22.04", "ubuntu64Guest", "ubuntu22.04", "eth0"),
    (r"(?i)ubuntu", "ubuntu64Guest", "linux", "eth0"),
    (r"(?i)windows 1[01]", "windows9_64Guest", "windows", "Ethernet 1"),
    (r"(?i)windows 2012", "windows8Server64Guest", "windows", "Ethernet 1"),
    (r"(?i)windows ?2019", "windows9Server64Guest", "windows2019", "Ethernet 1"),
    (r"(?i)windows 201(6|9)", "windows9Server64Guest", "windows", "Ethernet 1"),
    (r"(?i)windows", "windows9Server64Guest", "windows", "Ethernet 1"),
    (r"(?i)debian 8", "debian8_64Guest", "linux", "eth0"),
    (r"(?i)debian", "debian9_64Guest", "linux", "eth0"),
    (r"(?i)centos 7", "centos7_64Guest", "linux", "eth0"),
    (r"(?i)centos", "centos8_64Guest", "linux", "eth0"),
    (r"(?i)red hat", "rhel7_64Guest", "linux", "eth0"),
    (r"(?i)linux", "other3xLinux64Guest", "linux", "eth0"),
    (r"(?i)freebsd ?13.2", "freebsd12_64Guest", "freebsd13.2", "vmx0"),
    (r"(?i)freebsd", "freebsd12_64Guest", "other", "vmx0"),
]

DNS1 = "10.100.253.6"
DNS2 = "10.100.254.6"
NTP1 = "10.127.0.233"
NTP2 = "10.127.0.234"
VCENTER = "https://" + C.VCENTER
DOMAIN = C.DNS_DOMAIN
AD_DOMAIN = C.AD_DOMAIN
SMTP_SERVER = C.SMTP_SERVER
SYSLOG = SMTP_SERVER
ISO_DS = "dc1_datastore_1"
# ISO_DS_HX1 = "DC1-HX-DS-01"
# ISO_DS_HX2 = "DC2-HX-DS-01"
VPN_SERVER_IP = C.VPN_SERVER_IP
ANSIBLE_PATH = "/home/jclarke/src/git/ciscolive/automation/cleu-ansible-n9k"
DATACENTER = "CiscoLive"
CISCOLIVE_YEAR = C.CISCOLIVE_YEAR
PW_RESET_URL = C.PW_RESET_URL

TENANT_NAME = "DC Infrastructure"
VRF_NAME = "default"

SPREADSHEET_ID = "1pH2h0vpld6cmPkQTlVvJWrcOwUO2az2kEUsTud4ukWo"
SHEET_HOSTNAME = 13
SHEET_OS = 1
SHEET_OVA = 2
SHEET_CONTACT = 5
SHEET_CPU = 6
SHEET_RAM = 7
SHEET_DISK = 8
SHEET_NICS = 9
SHEET_COMMENTS = 11
SHEET_CLUSTER = 14
SHEET_DC = 15
SHEET_VLAN = 16

FIRST_IP = 30


def get_next_ip(enb: ElementalNetbox, prefix: str, args: Namespace) -> IpAddresses:
    """
    Get the next available IP for a prefix.
    """
    global FIRST_IP, TENANT_NAME, VRF_NAME

    prefix_obj = enb.ipam.prefixes.get(prefix=prefix)
    available_ips = prefix_obj.available_ips.list()

    for addr in available_ips:
        ip_obj = ipaddress.ip_address(addr.address.split("/")[0])
        if int(ip_obj.packed[-1]) > FIRST_IP:
            tenant = enb.tenancy.tenants.get(name=TENANT_NAME)
            vrf = enb.ipam.vrfs.get(name=VRF_NAME)
            if args.create:
                return enb.ipam.ip_addresses.create(address=addr.address, tenant=tenant.id, vrf=vrf.id)
            else:
                return addr

    return None


def parse_args() -> Namespace:
    parser = argparse.ArgumentParser(description="Create new VMs and notify owners.")
    parser.add_argument("row_range", nargs=1, metavar="ROW_RANGE", help="Spreadsheet range of rows")
    parser.add_argument("--create", action=argparse.BooleanOptionalAction, default=True, help="Perform create operations")

    args = parser.parse_args()

    return args


def main():
    global NETWORK_MAP

    args = parse_args()

    if not os.path.exists("gs_token.pickle"):
        print("ERROR: Google Sheets token does not exist!  Please re-auth the app first.")
        sys.exit(1)

    creds = None

    with open("gs_token.pickle", "rb") as token:
        creds = pickle.load(token)

    if "VMWARE_USER" not in os.environ or "VMWARE_PASSWORD" not in os.environ:
        print("ERROR: VMWARE_USER and VMWARE_PASSWORD environment variables must be set prior to running!")
        sys.exit(1)

    gs_service = build("sheets", "v4", credentials=creds)

    vm_sheet = gs_service.spreadsheets()
    vm_result = vm_sheet.values().get(spreadsheetId=SPREADSHEET_ID, range=args.row_range[0]).execute()
    vm_values = vm_result.get("values", [])

    if not vm_values:
        print("ERROR: Did not read anything from Google Sheets!")
        sys.exit(1)

    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    enb = ElementalNetbox()

    (rstart, _) = args.row_range[0].split(":")

    i = int(rstart) - 1
    users = {}

    for row in vm_values:
        i += 1
        try:
            owners = row[SHEET_CONTACT].strip().split(",")
            name = row[SHEET_HOSTNAME].strip()
            opsys = row[SHEET_OS].strip()
            is_ova = row[SHEET_OVA].strip()
            cpu = int(row[SHEET_CPU].strip())
            mem = int(row[SHEET_RAM].strip()) * 1024
            disk = int(row[SHEET_DISK].strip())
            dc = row[SHEET_DC].strip()
            cluster = row[SHEET_CLUSTER].strip()
            vlan = row[SHEET_VLAN].strip()
            comments = row[SHEET_COMMENTS].strip()
        except Exception as e:
            print(f"WARNING: Failed to process malformed row {i}: {e}")
            continue

        if name == "" or vlan == "" or dc == "":
            print(f"WARNING: Ignoring malformed row {i}")
            continue

        ova_bool = False

        if is_ova.lower() == "true" or is_ova.lower() == "yes":
            ova_bool = True

        ostype = None
        platform = "other"
        mgmt_intf = "Ethernet 1"

        for ostypes in OSTYPE_LIST:
            if re.search(ostypes[0], opsys):
                ostype = ostypes[1]
                platform = ostypes[2]
                mgmt_intf = ostypes[3]
                break

        if not ova_bool and ostype is None:
            print(f"WARNING: Did not find OS type for {opsys} on row {i}")
            continue

        vm = {
            "name": name.upper(),
            "os": opsys,
            "ostype": ostype,
            "platform": platform,
            "mem": mem,
            "is_ova": ova_bool,
            "mgmt_intf": mgmt_intf,
            "cpu": cpu,
            "disk": disk,
            "vlan": vlan,
            "cluster": cluster,
            "dc": dc,
        }

        if vm["vlan"] not in NETWORK_MAP:
            # This is an Attendee VLAN that has been added to the DC.
            # if vm["vlan"] in VLAN_MAP:
            #     nbvlan = VLAN_MAP[vm["vlan"]]
            # else:
            nbvlan = vm["vlan"]

            nb_vlan = enb.ipam.vlans.get(name=nbvlan, tenant=TENANT_NAME.lower().replace(" ", "-"))
            if not nb_vlan:
                print(f"WARNING: Invalid VLAN {nbvlan} for {name}.")
                continue

            NETWORK_MAP[vm["vlan"]] = {
                "subnet": f"10.{nb_vlan.vid}.{STRETCHED_OCTET}.0/24",
                "gw": f"10.{nb_vlan.vid}.{STRETCHED_OCTET}.{GW_OCTET}",
                "prefix": f"{IP6_PREFIX}{format(int(nb_vlan.vid), 'x')}{format(int(STRETCHED_OCTET), 'x')}::",
                "gw6": f"{IP6_PREFIX}{format(int(nb_vlan.vid), 'x')}{format(int(STRETCHED_OCTET), 'x')}::{format(int(GW_OCTET), 'x')}",
            }

        ip_obj = get_next_ip(enb, NETWORK_MAP[vm["vlan"]]["subnet"], args)
        if not ip_obj:
            print(f"WARNING: No free IP addresses for {name} in subnet {NETWORK_MAP[vm['vlan']]}.")
            continue

        vm["ip"] = ip_obj.address.split("/")[0]

        vm_obj = enb.virtualization.virtual_machines.filter(name=name.lower())
        if vm_obj and len(vm_obj) > 0 and args.create:
            print(f"WARNING: Duplicate VM name {name} in NetBox for row {i}.")
            continue

        platform_obj = enb.dcim.platforms.get(name=vm["platform"])
        cluster_obj = enb.virtualization.clusters.get(name=vm["cluster"])

        if args.create:
            tenant = enb.tenancy.tenants.get(name=TENANT_NAME)
            vm_obj = enb.virtualization.virtual_machines.create(
                name=name.lower(),
                tenant=tenant.id,
                platform=platform_obj.id,
                vcpus=vm["cpu"],
                disk=vm["disk"],
                memory=vm["mem"],
                cluster=cluster_obj.id,
            )
            vm["vm_obj"] = vm_obj
        else:
            vm["vm_obj"] = {}

        if args.create:
            vm_intf = enb.virtualization.interfaces.create(virtual_machine=vm_obj.id, name=mgmt_intf)

            ip_obj.assigned_object_id = vm_intf.id
            ip_obj.assigned_object_type = "virtualization.vminterface"
            ip_obj.save()

            vm_obj.primary_ip4 = ip_obj.id

        contacts = []

        for owner in owners:
            owner = owner.strip().lower()
            if owner not in users:
                users[owner] = []

            users[owner].append(vm)
            contacts.append(owner)

        if args.create:
            # TODO: Switch to using the official Contacts and Comments fields.
            vm_obj.custom_fields["Contact"] = ",".join(contacts)
            vm_obj.custom_fields["Notes"] = comments
            vm_obj.save()

    created = {}

    for user, vms in users.items():
        m = re.search(r"<?(\S+)@", user)
        username = m.group(1)
        m = re.search(r"<?(\S+@[a-zA-Z0-9.-_]+)", user)
        webex_addr = m.group(1)

        body = "Please find the CLEUR Data Centre Access details below:\n\n"
        body += f"Before you can access the Data Centre from remote, AnyConnect to {VPN_SERVER_IP} and login with **{CLEUCreds.VPN_USER}** / **{CLEUCreds.VPN_PASS}**\n"
        body += f"Once connected, your browser should redirect you to the password change tool.  If not [reset]({PW_RESET_URL}) your password by logging in with **{username}** and password **{CLEUCreds.DEFAULT_USER_PASSWORD}**\n"
        body += "You must use a complex password that contains lower and uppercase letters, numbers, or a special character.\n"
        body += f"After resetting your password, drop the VPN and reconnect to {VPN_SERVER_IP} with **{username}** and the new password you just set.\n\n"
        body += "You can use any of the following Windows Jump Hosts to access the data centre using RDP:\n\n"

        for js in JUMP_HOSTS:
            body += f"* {js}\n"

        body += "\nIf a Jump Host is full, try the next one.\n\n"
        body += (
            f"Your login is **{username}** (or **{username}@{AD_DOMAIN}** on Windows).  Your password is the same you used for the VPN.\n\n"
        )
        body += "The network details for your VM(s) are:\n\n"
        body += "```text\n"
        body += f"DNS1          : {DNS1}\n"
        body += f"DNS2          : {DNS2}\n"
        body += f"NTP1          : {NTP1}\n"
        body += f"NTP2          : {NTP2}\n"
        body += f"DNS DOMAIN    : {DOMAIN}\n"
        body += f"SMTP          : {SMTP_SERVER}\n"
        body += f"AD DOMAIN     : {AD_DOMAIN}\n"
        body += f"Syslog/NetFlow: {SYSLOG}\n\n"
        body += "```\n"

        body += f"vCenter is {VCENTER}.  You MUST use the web client.  Your AD credentials above will work there.  VMs that don't require an OVA have been pre-created, but require installation and configuration.  If you use an OVA, you will need to deploy it yourself.\n\n"

        body += "Your VM details are as follows.  DNS records have been pre-created for the VM name (i.e., hostname) below:\n\n"
        body += "```text\n"
        for vm in vms:
            datastore = DC_MAP[vm["dc"]][random.randint(0, len(DC_MAP[vm["dc"]]) - 1)]
            iso_ds = datastore
            cluster = DEFAULT_CLUSTER

            # if vm["dc"] in HX_DCs:
            #     cluster = vm["dc"]

            if not vm["is_ova"] and vm["vlan"] != "" and vm["name"] not in created and args.create:
                created[vm["name"]] = False
                print(f"===Adding VM for {vm['name']}===")
                scsi = "lsilogic"

                if re.search(r"^win", vm["ostype"]):
                    scsi = "lsilogicsas"

                os.chdir(ANSIBLE_PATH)
                command = [
                    "ansible-playbook",
                    "-i",
                    "inventory/hosts",
                    "-e",
                    f"vmware_cluster='{cluster}'",
                    "-e",
                    f"vmware_datacenter='{DATACENTER}'",
                    "-e",
                    f"guest_id={vm['ostype']}",
                    "-e",
                    f"guest_name={vm['name']}",
                    "-e",
                    f"guest_size={vm['disk']}",
                    "-e",
                    f"guest_mem={vm['mem']}",
                    "-e",
                    f"guest_cpu={vm['cpu']}",
                    "-e",
                    f"guest_datastore={datastore}",
                    "-e",
                    f"guest_network='{vm['vlan']}'",
                    "-e",
                    f"guest_scsi={scsi}",
                    "-e",
                    f"ansible_python_interpreter={sys.executable}",
                    "add-vm-playbook.yml",
                ]

                p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                output = ""
                for c in iter(lambda: p.stdout.read(1), b""):
                    output += c.decode("utf-8")

                p.wait()
                rc = p.returncode

                if rc != 0:
                    print(f"\n\n***ERROR: Failed to add VM {vm['name']}\n{output}!")
                    vm["vm_obj"].delete()
                    continue

                print("===DONE===")
                created[vm["name"]] = True

            octets = vm["ip"].split(".")

            body += '{}          : {} (v6: {}{})\n\n(Network: {}, Subnet: {}, GW: {}, v6 Prefix: {}/64,\n v6 GW: {})\n\nDeploy to the {} datastore in the "{}" cluster.\nFor this VM upload ISOs to the {} datastore.  There is an "ISOs" folder there already.\n'.format(
                vm["name"],
                vm["ip"],
                NETWORK_MAP[vm["vlan"]]["prefix"],
                format(int(octets[3]), "x"),
                vm["vlan"],
                NETWORK_MAP[vm["vlan"]]["subnet"],
                NETWORK_MAP[vm["vlan"]]["gw"],
                NETWORK_MAP[vm["vlan"]]["prefix"],
                NETWORK_MAP[vm["vlan"]]["gw6"],
                datastore,
                cluster,
                iso_ds,
            )

        body += "```\n"

        body += "DO NOT REPLY HERE.  Let us know directly via Webex if you need any other details.\n\n"

        sig = []

        for member, addr in DC_TEAM.items():
            sig.append(f"[{member}](webexteams://im?email={addr})")

        body += ", ".join(sig)

        body = f"# Cisco Live Europe {CISCOLIVE_YEAR} Data Centre Access Info\n\n" + body

        spark.post_to_spark(None, None, body, mtype=MessageType.NEUTRAL, person=webex_addr)

        for member in DC_TEAM.values():
            spark.post_to_spark(None, None, body, mtype=MessageType.NEUTRAL, person=member)


if __name__ == "__main__":
    os.environ["NETBOX_ADDRESS"] = C.NETBOX_SERVER
    os.environ["NETBOX_API_TOKEN"] = CLEUCreds.NETBOX_API_TOKEN
    os.environ["CPNR_USERNAME"] = CLEUCreds.CPNR_USERNAME
    os.environ["CPNR_PASSWORD"] = CLEUCreds.CPNR_PASSWORD
    os.environ["VMWARE_USER"] = CLEUCreds.VMWARE_USER
    os.environ["VMWARE_PASSWORD"] = CLEUCreds.VMWARE_PASSWORD
    main()
