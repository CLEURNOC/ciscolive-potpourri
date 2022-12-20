#!/usr/bin/env python

from __future__ import print_function
import pickle
import os.path
import os
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from elemental_utils import ElementalNetbox
from pynetbox.models.ipam import IpAddresses
import smtplib
from email.message import EmailMessage
import sys
import re
import subprocess
import ipaddress
import CLEUCreds
from cleu.config import Config as C

FROM = "Joe Clarke <jclarke@cisco.com>"
CC = "Anthony Jesani <anjesani@cisco.com>, Jara Osterfeld <josterfe@cisco.com>"

JUMP_HOSTS = ["10.100.252.26", "10.100.252.27", "10.100.252.28", "10.100.252.29"]

DC_MAP = {"DC1": "dc1_datastore_1", "DC2": "dc2_datastore_1", "HyperFlex-DC1": "DC1-HX-DS-01", "HyperFlex-DC2": "DC2-HX-DS-01"}

DEFAULT_CLUSTER = "FlexPod"

HX_DCs = {"HyperFlex-DC1": 1, "HyperFlex-DC2": 1}

IP4_SUBNET = "10.100."
IP6_PREFIX = "2a11:d940:2:"

NETWORK_MAP = {
    "Stretched_VMs": {
        "subnet": "{}252.0/24".format(IP4_SUBNET),
        "gw": "{}252.254".format(IP4_SUBNET),
        "prefix": "{}64fc::".format(IP6_PREFIX),
        "gw6": "{}64fc::fe".format(IP6_PREFIX),
    },
    "VMs-DC1": {
        "subnet": "{}253.0/24".format(IP4_SUBNET),
        "gw": "{}253.254".format(IP4_SUBNET),
        "prefix": "{}64fd::".format(IP6_PREFIX),
        "gw6": "{}64fd::fe".format(IP6_PREFIX),
    },
    "VMs-DC2": {
        "subnet": "{}254.0/24".format(IP4_SUBNET),
        "gw": "{}254.254".format(IP4_SUBNET),
        "prefix": "{}64fe::".format(IP6_PREFIX),
        "gw6": "{}64fe::fe".format(IP6_PREFIX),
    },
}

OSTYPE_LIST = [
    (r"(?i)ubuntu ?22.04", "ubuntu64Guest", "ubuntu22.04"),
    (r"(?i)ubuntu", "ubuntu64Guest", "linux"),
    (r"(?i)windows 10", "windows9_64Guest", "windows"),
    (r"(?i)windows 2012", "windows8Server64Guest", "windows"),
    (r"(?i)windows ?2019", "windows9Server64Guest", "windows2019"),
    (r"(?i)windows 201(6|9)", "windows9Server64Guest", "windows"),
    (r"(?i)debian 8", "debian8_64Guest", "linux"),
    (r"(?i)debian", "debian9_64Guest", "linux"),
    (r"(?i)centos 7", "centos7_64Guest", "linux"),
    (r"(?i)centos", "centos8_64Guest", "linux"),
    (r"(?i)red hat", "rhel7_64Guest", "linux"),
    (r"(?i)linux", "other3xLinux64Guest", "linux"),
    (r"(?i)freebsd ?13.1", "freebsd12_64Guest", "freebsd13.1"),
    (r"(?i)freebsd", "freebsd12_64Guest", "other"),
]

INTERFACE_MAP = {
    "freebsd13.1": "vmx0",
    "linux": "eth0",
    "ubuntu22.04": "eth0",
    "windows": "Ethernet 1",
    "windows2019": "Ethernet 1",
    "other": "Ethernet 1",
}

DNS1 = "10.100.253.6"
DNS2 = "10.100.254.6"
NTP1 = "10.128.0.1"
NTP2 = "10.128.0.2"
VCENTER = "https://" + C.VCENTER
DOMAIN = C.DNS_DOMAIN
AD_DOMAIN = C.AD_DOMAIN
SMTP_SERVER = C.SMTP_SERVER
SYSLOG = SMTP_SERVER
ISO_DS = "dc1_datastore_1"
ISO_DS_HX1 = "DC1-HX-DS-01"
ISO_DS_HX2 = "DC2-HX-DS-01"
VPN_SERVER_IP = C.VPN_SERVER_IP
ANSIBLE_PATH = "/home/jclarke/src/git/ciscolive/automation/cleu-ansible-n9k"
DATACENTER = "CiscoLive"
CISCOLIVE_YEAR = C.CISCOLIVE_YEAR
PW_RESET_URL = C.PW_RESET_URL

TENANT_NAME = "Infrastructure"
VRF_NAME = "default"

SPREADSHEET_ID = "15sC26okPX1lHzMFDJFnoujDKLNclh4NQhBPmV175slY"
SHEET_HOSTNAME = 0
SHEET_OS = 1
SHEET_OVA = 2
SHEET_CONTACT = 5
SHEET_CPU = 6
SHEET_RAM = 7
SHEET_DISK = 8
SHEET_NICS = 9
SHEET_CLUSTER = 12
SHEET_DC = 13
SHEET_VLAN = 14

FIRST_IP = 30


def get_next_ip(enb: ElementalNetbox, prefix: str) -> IpAddresses:
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
            return enb.ipam.ip_addresses.create(address=addr.address, tenant=tenant.id, vrf=vrf.id)

    return None


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} ROW_RANGE")
        sys.exit(1)

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
    vm_result = vm_sheet.values().get(spreadsheetId=SPREADSHEET_ID, range=sys.argv[1]).execute()
    vm_values = vm_result.get("values", [])

    if not vm_values:
        print("ERROR: Did not read anything from Google Sheets!")
        sys.exit(1)

    enb = ElementalNetbox()

    (rstart, _) = sys.argv[1].split(":")

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

        for ostypes in OSTYPE_LIST:
            if re.search(ostypes[0], opsys):
                ostype = ostypes[1]
                platform = ostypes[2]
                break

        if not ova_bool and ostype is None:
            print(f"WARNING: Did not find OS type for {vm['os']} on row {i}")
            continue

        vm = {
            "name": name.upper(),
            "os": opsys,
            "ostype": ostype,
            "platform": platform,
            "mem": mem,
            "is_ova": ova_bool,
            "cpu": cpu,
            "disk": disk,
            "vlan": vlan,
            "cluster": cluster,
            "dc": dc,
        }

        ip_obj = get_next_ip(enb, NETWORK_MAP[vm["vlan"]]["subnet"])
        if not ip_obj:
            print(f"WARNING: No free IP addresses for {name} in subnet {NETWORK_MAP[vm['vlan']]}.")
            continue

        vm["ip"] = ip_obj.address.split("/")[0]

        vm_obj = enb.virtualization.virtual_machines.filter(name=name.lower())
        if vm_obj and len(vm_obj) > 0:
            print(f"WARNING: Duplicate VM name {name} in NetBox for row {i}.")
            continue

        platform_obj = enb.dcim.platforms.get(name=vm["platform"])
        cluster_obj = enb.virtualization.clusters.get(name=vm["cluster"])

        vm_obj = enb.virtualization.virtual_machines.create(
            name=name.lower(), platform=platform_obj.id, vcpus=vm["cpu"], disk=vm["disk"], memory=vm["mem"], cluster=cluster_obj.id
        )
        vm["vm_obj"] = vm_obj

        vm_intf = enb.virtualization.interfaces.create(virtual_machine=vm_obj.id, name=INTERFACE_MAP[vm["platform"]])

        ip_obj.assigned_object_id = vm_intf.id
        ip_obj.assigned_object_type = "virtualization.vminterface"
        ip_obj.save()

        vm_obj.primary_ip4 = ip_obj.id

        contacts = []

        for owner in owners:
            owner = owner.strip()
            if owner not in users:
                users[owner] = []

            users[owner].append(vm)
            contacts.append(owner)

        vm_obj.custom_fields["Contact"] = ",".join(contacts)
        vm_obj.save()

    for user, vms in users.items():
        m = re.search(r"<?(\S+)@", user)
        username = m.group(1)

        body = "Please find the CLEU Data Centre Access details below\r\n\r\n"
        body += f"Before you can access the Data Centre from remote, AnyConnect to {VPN_SERVER_IP} and login with {CLEUCreds.VPN_USER} / {CLEUCreds.VPN_PASS}\r\n"
        body += f"Once connected, your browser should redirect you to the password change tool.  If not go to {PW_RESET_URL} and login with {username} and password {CLEUCreds.DEFAULT_USER_PASSWORD}\r\n"
        body += "Reset your password.  You must use a complex password that contains lower and uppercase letters, numbers, or a special character.\r\n"
        body += f"After resetting your password, drop the VPN and reconnect to {VPN_SERVER_IP} with {username} and the new password you just set.\r\n\r\n"
        body += "You can use any of the following Windows Jump Hosts to access the data centre using RDP:\r\n\r\n"

        for js in JUMP_HOSTS:
            body += f"{js}\r\n"

        body += "\r\nIf a Jump Host is full, try the next one.\r\n\r\n"
        body += f"Your login is {username} (or {username}@{AD_DOMAIN} on Windows).  Your password is the same you used for the VPN.\r\n\r\n"
        body += "The network details for your VM(s) are:\r\n\r\n"
        body += f"DNS1          : {DNS1}\r\n"
        body += f"DNS2          : {DNS2}\r\n"
        body += f"NTP1          : {NTP1}\r\n"
        body += f"NTP2          : {NTP2}\r\n"
        body += f"DNS DOMAIN    : {DOMAIN}\r\n"
        body += f"SMTP          : {SMTP_SERVER}\r\n"
        body += f"AD DOMAIN     : {AD_DOMAIN}\r\n"
        body += f"Syslog/NetFlow: {SYSLOG}\r\n\r\n"

        body += f"vCenter is {VCENTER}.  You MUST use the web client.  Your AD credentials above will work there.  VMs that don't require an OVA have been pre-created, but require installation and configuration.  If you use an OVA, you will need to deploy it yourself.\r\n\r\n"

        body += "Your VM details are as follows.  DNS records have been pre-created for the VM name (i.e., hostname) below:\r\n\r\n"
        created = {}
        for vm in vms:
            iso_ds = ISO_DS
            cluster = DEFAULT_CLUSTER

            if vm["dc"] in HX_DCs:
                if vm["dc"].endswith("2"):
                    iso_ds = ISO_DS_HX2
                else:
                    iso_ds = ISO_DS_HX1

                cluster = vm["dc"]

            if not vm["is_ova"] and vm["vlan"] != "" and vm["name"] not in created:
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
                    f"guest_datastore={DC_MAP[vm['dc']]}",
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

            octets = vm["ip"].split(".")

            body += '{}          : {} (v6: {}{}) (Network: {}, Subnet: {}, GW: {}, v6 Prefix: {}/64, v6 GW: {})  : Deploy to the {} datastore in the "{}" cluster.\r\n\r\nFor this VM upload ISOs to the {} datastore.  There is an "ISOs" folder there already.\r\n\r\n'.format(
                vm["name"],
                vm["ip"],
                NETWORK_MAP[vm["vlan"]]["prefix"],
                format(int(octets[3]), "x"),
                vm["vlan"],
                NETWORK_MAP[vm["vlan"]]["subnet"],
                NETWORK_MAP[vm["vlan"]]["gw"],
                NETWORK_MAP[vm["vlan"]]["prefix"],
                NETWORK_MAP[vm["vlan"]]["gw6"],
                DC_MAP[vm["dc"]],
                cluster,
                iso_ds,
            )
            created[vm["name"]] = True

        body += "Let us know via Webex if you need any other details.\r\n\r\n"

        body += "Joe, Anthony, and Jara\r\n\r\n"

        subject = f"Cisco Live Europe {CISCOLIVE_YEAR} Data Centre Access Info"

        smtp = smtplib.SMTP(SMTP_SERVER)
        msg = EmailMessage()
        msg.set_content(body)

        msg["Subject"] = subject
        msg["From"] = FROM
        msg["To"] = user
        msg["Cc"] = CC + "," + FROM

        smtp.send_message(msg)
        smtp.quit()


if __name__ == "__main__":
    os.environ["NETBOX_ADDRESS"] = C.NETBOX_SERVER
    os.environ["NETBOX_API_TOKEN"] = CLEUCreds.NETBOX_API_TOKEN
    os.environ["CPNR_USERNAME"] = CLEUCreds.CPNR_USERNAME
    os.environ["CPNR_PASSWORD"] = CLEUCreds.CPNR_PASSWORD
    os.environ["VMWARE_USER"] = CLEUCreds.VMWARE_USER
    os.environ["VMWARE_PASSWORD"] = CLEUCreds.VMWARE_PASSWORD
    main()
