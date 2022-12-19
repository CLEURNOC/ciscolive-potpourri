#!/usr/bin/env python3

from __future__ import print_function
import pickle
import os.path
import os
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from elemental_utils import ElementalDns, ElementalNetbox
import smtplib
from email.message import EmailMessage
import sys
import re
import subprocess
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
    "CROSS DC VMs": {
        "subnet": "{}252.0/24".format(IP4_SUBNET),
        "gw": "{}252.254".format(IP4_SUBNET),
        "prefix": "{}64fc::".format(IP6_PREFIX),
        "gw6": "{}64fc::fe".format(IP6_PREFIX),
    },
    "DC1 ONLY VMs": {
        "subnet": "{}253.0/24".format(IP4_SUBNET),
        "gw": "{}253.254".format(IP4_SUBNET),
        "prefix": "{}64fd::".format(IP6_PREFIX),
        "gw6": "{}64fd::fe".format(IP6_PREFIX),
    },
    "DC2 ONLY VMs": {
        "subnet": "{}254.0/24".format(IP4_SUBNET),
        "gw": "{}254.254".format(IP4_SUBNET),
        "prefix": "{}64fe::".format(IP6_PREFIX),
        "gw6": "{}64fe::fe".format(IP6_PREFIX),
    },
}

OSTYPE_LIST = [
    (r"(?i)ubuntu", "ubuntu64Guest"),
    (r"(?i)windows 10", "windows9_64Guest"),
    (r"(?i)windows 2012", "windows8Server64Guest"),
    (r"(?i)windows 201(6|9)", "windows9Server64Guest"),
    (r"(?i)debian 8", "debian8_64Guest"),
    (r"(?i)debian", "debian9_64Guest"),
    (r"(?i)centos 7", "centos7_64Guest"),
    (r"(?i)centos", "centos8_64Guest"),
    (r"(?i)red hat", "rhel7_64Guest"),
    (r"(?i)linux", "other3xLinux64Guest"),
]

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
VPN_SERVER = C.VPN_SERVER
VPN_SERVER_IP = C.VPN_SERVER_IP
ANSIBLE_PATH = "/home/jclarke/src/git/ciscolive/automation/cleu-ansible-n9k"
UPDATE_DNS_PATH = "/home/jclarke"
DATACENTER = "CiscoLive"
CISCOLIVE_YEAR = C.CISCOLIVE_YEAR
PW_RESET_URL = C.PW_RESET_URL

SPREADSHEET_ID = "1ExTNQJ7SArHSJKfPOj_x1O2aTj76dHjlG8kCDHW39hw"
SHEET_HOSTNAME = 0
SHEET_OS = 1
SHEET_OVA = 2
SHEET_CONTACT = 4
SHEET_CPU = 5
SHEET_RAM = 6
SHEET_DISK = 7
SHEET_NICS = 8
SHEET_DC = 11
SHEET_IP = 12
SHEET_VLAN = 13


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

    (rstart, rend) = sys.argv[1].split(":")

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
            mem = int(row[SHEET_RAM].strip())
            disk = int(row[SHEET_DISK].strip())
            dc = row[SHEET_DC].strip()
            vlan = row[SHEET_VLAN].strip()
            ip = row[SHEET_IP].strip()
        except Exception as e:
            print(f"WARNING: Failed to process malformed row {i}: {e}")
            continue

        if name == "" or ip == "" or dc == "":
            print(f"WARNING: Ignoring malformed row {r}")
            continue

        for owner in owners:
            owner = owner.strip()
            if owner not in users:
                users[owner] = []

            vm = {
                "name": name.upper(),
                "os": opsys,
                "mem": mem,
                "is_ova": is_ova,
                "cpu": cpu,
                "disk": disk,
                "vlan": vlan,
                "ip": ip,
                "dc": dc,
            }
            users[owner].append(vm)

    for user, vms in users.items():
        m = re.search(r"<?(\S+)@", user)
        username = m.group(1)

        body = "Please find the CLEU Data Centre Access details below\r\n\r\n"
        body += f"Before you can access the Data Centre from remote, AnyConnect to {VPN_SERVER} and login with {CLEUCreds.VPN_USER} / {CLEUCreds.VPN_PASS}\r\n"
        body += f"Once connected, your browser should redirect you to the password change tool.  If not go to {PW_RESET_URL} and login with {username} and password {CLEUCreds.DEFAULT_USER_PASSWORD}\r\n"
        body += "Reset your password.  You must use a complex password that contains lower and uppercase letters, numbers, or a special character.\r\n"
        body += "After resetting your password, drop the VPN and reconnect to {VPN_SERVER} with {username} and the new password you just set.\r\n\r\n"
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

            is_ova = False

            if vm["is_ova"].lower() == "true" or vm["is_ova"].lower() == "yes":
                is_ova = True

            ostype = None

            for ostypes in OSTYPE_LIST:
                if re.search(ostypes[0], vm["os"]):
                    ostype = ostypes[1]
                    break

            if not is_ova and ostype is None:
                print(f"WARNING: Did not find OS type for {vm['os']}")
                continue

            if not is_ova and vm["vlan"] != "" and vm["name"] not in created:
                print(f"===Adding VM for {vm['name']}===")
                mem = vm["mem"] * 1024
                scsi = "lsilogic"

                if re.search(r"^win", ostype):
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
                    f"guest_id={ostype}",
                    "-e",
                    f"guest_name={vm['name']}",
                    "-e",
                    f"guest_size={vm['disk']}",
                    "-e",
                    f"guest_mem={mem}",
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
                    continue

                print("===DONE===")

            if vm["name"] not in created:
                print(f"===Adding DNS record for {vm['name']} ==> {vm['ip']}===")

                os.chdir(UPDATE_DNS_PATH)
                command = ["{}/update_dns.py".format(UPDATE_DNS_PATH), "--ip", vm["ip"], "--host", vm["name"]]

                p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                output = ""
                for c in iter(lambda: p.stdout.read(1), b""):
                    output += c.decode("utf-8")
                p.wait()
                rc = p.returncode

                if rc != 0:
                    print("\n\n***ERROR: Failed to add DNS record!\n{}".format(output))
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
    main()
