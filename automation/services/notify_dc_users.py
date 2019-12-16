#!/usr/bin/env python3

from __future__ import print_function
import pickle
import os.path
import os
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import smtplib
from email.message import EmailMessage
import sys
import re
import subprocess
import CLEUCreds
from cleu.config import Config as C

FROM = 'Joe Clarke <jclarke@cisco.com>'
CC = 'Kris Sekula <ksekula@cisco.com>, Anthony Jesani <anjesani@cisco.com>'

JUMP_HOSTS = [
    '10.100.252.26', '10.100.252.27', '10.100.252.28', '10.100.252.29'
]

DC_MAP = {
    'DC1': 'dc1_datastore_1',
    'DC2': 'dc2_datastore_1',
    'HyperFlex-DC1': 'DC1-HX-DS-01',
    'HyperFlex-DC2': 'DC2-HX-DS-01'
}

DEFAULT_CLUSTER = 'CiscoLive'

HX_DCs = {
    'HyperFlex-DC1': 1,
    'HyperFlex-DC2': 1
}

IP4_SUBNET = '10.100.'
IP6_PREFIX = '2a05:f8c0:2:'

NETWORK_MAP = {
    'CROSS DC VMs': {
        'subnet': '{}252.0/24'.format(IP4_SUBNET),
        'gw': '{}252.254'.format(IP4_SUBNET),
        'prefix': '{}64fc::'.format(IP6_PREFIX),
        'gw6': '{}64fc::fe'.format(IP6_PREFIX)
    },
    'DC1 ONLY VMs': {
        'subnet': '{}253.0/24'.format(IP4_SUBNET),
        'gw': '{}253.254'.format(IP4_SUBNET),
        'prefix': '{}64fd::'.format(IP6_PREFIX),
        'gw6': '{}64fd::fe'.format(IP6_PREFIX)
    },
    'DC2 ONLY VMs': {
        'subnet': '{}254.0/24'.format(IP4_SUBNET),
        'gw': '{}254.254'.format(IP4_SUBNET),
        'prefix': '{}64fe::'.format(IP6_PREFIX),
        'gw6': '{}64fe::fe'.format(IP6_PREFIX)
    }
}

OSTYPE_MAP = [
    (r'?iubuntu', 'ubuntu64Guest'),
    (r'?iwindows 10', 'windows9_64Guest'),
    (r'?iwindows 2012', 'windows8Server64Guest'),
    (r'?iwindows 201(6|9)', 'windows9Server64Guest'),
    (r'?idebian 8', 'debian8_64Guest'),
    (r'?idebian', 'debian9_64Guest'),
    (r'?icentos 7', 'centos7_64Guest'),
    (r'?icentos', 'centos8_64Guest'),
    (r'?ired hat', 'rhel7_64Guest'),
    (r'?ilinux', 'other3xLinux64Guest')
]

DNS1 = '10.100.253.6'
DNS2 = '10.100.254.6'
VCENTER = 'https://' + C.VCENTER
DOMAIN = C.DNS_DOMAIN
AD_DOMAIN = C.AD_DOMAIN
SMTP_SEVER = C.SMTP_SERVER
ISO_DS = 'dc1_datastore_1'
ISO_DS_HX1 = 'DC1-HX-DS-01'
ISO_DS_HX2 = 'DC2-HX-DS-01'
VPN_SERVER = C.VPN_SERVER
ANSIBLE_PATH = '/home/jclarke/src/git/ciscolive/automation/cleu-ansible-n9k'
UPDATE_DNS_PATH = '/home/jclarke'
DATACENTER = 'CiscoLive'
CISCOLIVE_YEAR = C.CISCOLIVE_YEAR

SPREADSHEET_ID = '1ExTNQJ7SArHSJKfPOj_x1O2aTj76dHjlG8kCDHW39hw'
SHEET_HOSTNAME = 0
SHEET_OS = 1
SHEET_OVA = 2
SHEET_CONTACT = 3
SHEET_CPU = 4
SHEET_RAM = 5
SHEET_DISK = 6
SHEET_NICS = 7
SHEET_DC = 10
SHEET_IP = 11
SHEET_VLAN = 12


def main():
    if len(sys.args) != 2:
        print('usage: {} ROW_RANGE'.format(sys.args[0]))
        sys.exit(1)

    if not os.path.exists('gs_token.pickle'):
        print('ERROR: Google Sheets token does not exist!  Please re-auth the app first.')
        sys.exit(1)

    creds = None

    with open('gs_token.pickle', 'rb') as token:
        creds = pickle.load(token)

    if 'VMWARE_USER' not in os.environ or 'VMWARE_PASSWORD' not in os.environ:
        print('ERROR: VMWARE_USER and VMWARE_PASSWORD environment variables must be set prior to running!')
        sys.exit(1)

    gs_service = build('sheets', 'v4', credentials=creds)

    vm_sheet = service.spreadsheets()
    vm_result = vm_sheet.values().get(spreadsheetId=SPREADSHEET_ID,
                                      range=sys.args[1]).execute()
    vm_values = vm_result.get('values', [])

    if not vm_values:
        print('ERROR: Did not read anything from Google Sheets!')
        sys.exit(1)

    i = 0
    users = {}

    for row in values:
        i += 1
        owners = row[SHEET_CONTACT].trim().split(',')
        name = row[SHEET_HOSTNAME].trim()
        os = row[SHEET_OS].trim()
        is_ova = row[SHEET_OVA].trim()
        cpu = int(row[SHEET_CPU].trim())
        mem = int(row[SHEET_RAM].trim())
        disk = int(row[SHEET_DISK].trim())
        dc = row[SHEET_DC].trim()
        vlan = row[SHEET_VLAN].trim()
        ip = row[SHEET_IP].trim()

        if name == '' or ip == '' or dc == '':
            print('WARNING: Ignorning malformed row {}'.format(i))
            continue

        for owner in owners:
            if owner not in users:
                users[owner] = []

            vm = {
                'name': name.upper(),
                'os': os,
                'mem': mem,
                'is_ova': is_ova,
                'cpu': cpu,
                'disk': disk,
                'vlan': vlan,
                'ip': ip,
                'dc': dc
            }
            users[owner].append()

    for user, vms in users.items():
        username = user
        if re.search(r';', user):
            [user, username] = user.split(';')
        else:
            user = '{}@cisco.com'.format(user)

        body = 'Please find the CLEU Data Centre Access details below\r\n\r\n'
        body += 'Before you can access the Data Centre from remote, AnyConnect to {} and login with {} / {}\r\n'.format(
            VPN_SERVER, CLEUCreds.VPN_USER, CLEUCreds.VPN_PASS)
        body += '(Note: if you get a sinkhole error on the Cisco network, VPN to {} instead.)\r\n'.format(VPN_SERVER_IP)
        body += 'Once connected, go to {} and login with {} and password {}\r\n'.format(
            PW_RESET_URL, username, CLEUCreds.DEFAULT_USER_PASSWORD)
        body += 'Reset your password.  You must use a complex password that contains lower and\r\n'
        body += 'uppercase letters, numbers, or a special character.\r\n'
        body += 'After resetting your password, drop the VPN and reconnect to {} with {} and the new password you just set.\r\n\r\n'.format(
            VPN_SERVER, username)
        body += 'You can use any of the following Jump Hosts to access the data centre:\r\n\r\n'

        for js in JUMP_HOSTS:
            body += '{}\r\n'.format(js)

        body += '\r\nIf a Jump Host is full, try the next one.\r\n\r\n'
        body += 'Your login is {} (or {}@{} on Windows).  Your password is the same you used for the VPN\r\n\r\n'.format(
            username, username, AD_DOMAIN)
        body += 'The network details for your VM(s) are:\r\n\r\n'
        body += 'DNS1          : {}\r\n'.format(DNS1)
        body += 'DNS2          : {}\r\n'.format(DNS2)
        body += 'NTP1          : {}\r\n'.format(NTP1)
        body += 'NTP2          : {}\r\n'.format(NTP2)
        body += 'DNS DOMAIN    : {}\r\n'.format(DOMAIN)
        body += 'SMTP          : {}\r\n'.format(SMTP_SERVER)
        body += 'AD DOMAIN     : {}\r\n'.format(AD_DOMAIN)
        body += 'Syslog/NetFlow: {}\r\n\r\n'.format(SYSLOG)

        body += 'vCenter is {}.  You MUST use the web client.  Your AD credentials above will work there.  VMs that don\'t require an OVA have been pre-created, but require installation and configuration.  If you use an OVA, you will need to deploy it yourself.\r\n\r\n'

        body += 'Your VM details are:\r\n\r\n'
        for vm in vms:
            iso_ds = ISO_DS
            cluster = DEFAULT_CLUSTER

            if vm['dc'] in HX_DCs:
                if vm['dc'].endswith('2'):
                    iso_ds = ISO_DS_HX2
                else:
                    iso_ds = ISO_DS_HX

                cluster = vm['dc']

            is_ova = False

            if vm['is_ova'].lower() == 'true' or vm['is_ova'].lower() == 'yes':
                is_ova = True

            ostype = None

            for ostypes in OSTYPE_LIST:
                if re.search(ostypes[0], vm['os']):
                    ostype = ostypes[1]
                    break

            if not is_ova and ostype is None:
                print('WARNING: Did not find OS type for {}'.format(vm['os']))
                continue

            if not is_ova and vm['vlan'] != '':
                print('===Adding VM for {}==='.format(vm['name']))
                mem = vm['mem'] * 1024
                scsi = 'lsiLogic'

                if re.search(r'^win', ostype):
                    scsi = 'lsilogicsas'

                os.chdir(ANSIBLE_PATH)
                command = ['ansible-playbook', '-i', 'inventory/hosts', '-e', 'vmware_cluster={}'.format(cluster), '-e', 'vmware_datacenter={}'.format(DATACENTER), '-e', 'guest_id={}'.format(ostype), '-e', 'guest_name={}'.format(vm['name']), '-e', 'guest_size={}'.format(
                    vm['disk']), '-e', 'guest_mem={}'.format(mem), '-e', 'guest_cpu={}'.format(vm['cpu']), '-e', 'guest_datastore={}'.format(DC_MAP[vm['dc']]), '-e', 'guest_network={}'.format(vm['vlan']), '-e', 'guest_scsi={}'.format(scsi), '-e', 'ansible_python_interpreter={}'.format(sys.executable), 'add-vm-playbook.yml']

                p = subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                p.wait()
                rc = p.returncode

                if rc != 0:
                    print(
                        '\n\n***ERROR: Failed to add VM {}!'.format(vm['name']))
                    continue

                print('===DONE===')

            print('===Adding DNS record for {} ==> {}==='.format(
                vm['name'], vm['ip']))

            os.chdir(UPDATE_PATH)
            command = ['./update_dns.py', '--ip',
                       vm['ip'], '--host', vm['name']]

            p = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            p.wait()
            rc = p.returncode

            if rc != 0:
                print('\n\n***ERROR: Failed to add DNS record!')
                continue

            print('===DONE===')

            body += '{}          : {} (Subnet: {}, GW: {}, v6 Prefix: {}, v6 GW: {})  : Deploy the {} datastore in the "{}" cluster.\r\n\r\nFor this VM upload ISOs to the {} datastore.  There is an "ISOs" folder there already.\r\n\r\n'.format(
                vm['name'], vm['ip'], NETWORK_MAP[vm['vlan']]['subnet'], NETWORK_MAP[vm['vlan']]['gw'], NETWORK_MAP[vm['vlan']]['prefix'], NETWORK_MAP[vm['vlan']]['gw6'], DC_MAP[vm['dc']], cluster, iso_ds)

        body += 'Let us know via Webex Teams if you need any other details.\r\n\r\n'

        body += 'Joe, Kris and Anthony\r\n\r\n'

        subject = 'Cisco Live Europe {} Data Centre Access Info'.format(
            CISCOLIVE_YEAR)

        smtp = smtplib.SMTP(SMTP_SEVER)
        msg = EmailMessage()
        msg.set_content(body)

        msg['Subject'] = subject
        msg['From'] = FROM
        msg['To'] = user
        msg['Cc'] = CC + ',' + FROM

        smtp.send_message(msg)
        smtp.quit()


if __name__ == '__main__':
    main()
