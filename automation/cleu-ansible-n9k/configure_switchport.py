#!/usr/bin/env python2

import argparse
import sys
import re
import subprocess
import os
import csv
import json


def main():
    parser = argparse.ArgumentParser(
        prog=sys.argv[0], description='Configure a switch port')
    parser.add_argument('--switch', '-s', metavar='<SWITCH NAME>',
                        help='Name of the switch to configure', required=True)
    parser.add_argument('--interface', '-i', action='append', metavar='<INTF>',
                        help='Name of interface to configure (can be specified multiple times)')
    parser.add_argument('--descr', '-d', metavar='<INTF_DESCR>',
                        help='Interface description')
    parser.add_argument('--mode', '-m', metavar='<trunk|access>',
                        help='Switchport mode to configure (access or trunk)')
    parser.add_argument('--mtu', metavar='<MTU>',
                        help='MTU for switchport', type=int)
    parser.add_argument('--port-channel', metavar='<PC NUM>',
                        help='Port-channel number (also used as for vPC)', type=int)
    parser.add_argument(
        '--no-vpc', help='Whether or not to put port-channel in a vPC (default: yes)', action='store_true')
    parser.add_argument('--access-vlan', '-a', metavar='<ACCESS_VLAN_NUM>',
                        help='Access VLAN number (when mode=access)')
    parser.add_argument('--trunk-allowed-vlans', metavar='<TRUNK_VLANS>',
                        help='List of VLANs allowed on the trunk (when mode=trunk)')
    parser.add_argument('--pc-descr', metavar='<PORT_CHANNEL_DESCR>',
                        help='Description for the port-channel interface (default is to use the interface description)')
    parser.add_argument('--username', '-u', metavar='<USERNAME>',
                        help='Username to use to connect to the N9Ks', required=True)
    parser.add_argument('--input', metavar='<input TSV file>',
                        help='Path to the input TSV file')
    args = parser.parse_args()

    n9k_switchports = []

    if args.input:
        with open(args.input, 'rb') as tsvin:
            tsvin = csv.reader(tsvin, delimiter='\t')

            for row in tsvin:
                if len(row) >= 4:
                    row[3] = re.sub(r'\s', '', row[3])
                    n9k_switchport = {
                        'name': row[1].capitalize().strip(),
                        'descr': row[0].strip(),
                        'mode': row[2].strip()
                    }

                    m = re.match(r'Ethernet\d+/\d+(/\d+)?',
                                 n9k_switchport['name'])
                    if not m:
                        print('WARNING: Invalid interface name {}'.format(
                            n9k_switchport['name']))
                        continue

                    if row[2] == 'access':
                        n9k_switchport['access_vlan'] = row[3]
                    elif row[2] == 'trunk':
                        n9k_switchport['trunk_allowed_vlans'] = row[3]
                    else:
                        print(
                            'WARNING: Invalid value for mode, {}'.format(row[2]))
                        continue

                    if len(row) >= 5:
                        if m.group(1) is None:
                            mtu = 1500
                            try:
                                mtu = int(row[4])
                            except:
                                print('WARNING: MTU must be an integer for {}'.format(
                                    n9k_switchport['name']))
                                continue

                            if mtu < 1500 or mtu > 9216:
                                print('WARNING: MTU for {} must be between 1500 and 9216'.format(
                                    n9k_switchport['name']))
                                continue
                            n9k_switchport['mtu'] = mtu

                    if len(row) >= 6:
                        pcn = None
                        try:
                            pcn = int(row[5])
                        except:
                            print(
                                'WARNING: Port-channel must be an integer for {}'.format(n9k_switchport['name']))
                            continue

                        if pcn < 1 or pcn > 4096:
                            print(
                                'WARNING: Port-channel number for {} must be between 1 and 4096'.format(n9k_switchport['name']))
                            continue

                        n9k_switchport['port_channel'] = pcn

                    if len(row) >= 7:
                        if re.match(r'[tT]rue', row[6]):
                            n9k_switchport['vpc'] = True

                    if len(row) >= 8:
                        n9k_switchport['pc_descr'] = row[7]

                    n9k_switchports.append(n9k_switchport)
    else:
        if not args.mode or (args.mode != 'trunk' and args.mode != 'access'):
            print('ERROR: Mode must be one of "trunk" or "access"')
            sys.exit(1)

        if not args.interface or len(args.interface) == 0:
            print('ERROR: At least one interface must be specified')
            sys.exit(1)

        if args.mode != 'access' and args.access_vlan:
            print('ERROR: Access VLAN must only be specified when mode is access')
            sys.exit(1)

        if args.mode != 'trunk' and args.trunk_allowed_vlans:
            print('ERROR: Trunk allowed VLANs must only be specified when mode is trunk')
            sys.exit(1)

        if args.mode == 'access' and not args.access_vlan:
            print('ERROR: You must specify an access VLAN when mode is access')
            sys.exit(1)

        if args.mode == 'trunk' and not args.trunk_allowed_vlans:
            args.trunk_allowed_vlans = '1-4094'

        if args.port_channel and (args.port_channel < 1 or args.port_channel > 4096):
            print('ERROR: Port-channel number must be between 1 and 4096')
            sys.exit(1)

        for intf in args.interface:
            m = re.match(r'[eE]thernet\d+/\d+(/\d+)?', intf)
            if not m:
                print(
                    'WARNING: The interface {} is not in the format "Ethernet[FEX/]MOD/PORT (e.g., Ethernet101/1/2)"'.format(intf))
                continue

            n9k_switchport = {
                'name': intf.capitalize(),
                'mode': args.mode,
            }

            if args.descr:
                n9k_switchport['descr'] = args.descr

            if args.mode == 'access':
                n9k_switchport['access_vlan'] = args.access_vlan
            else:
                n9k_switchport['trunk_allowed_vlans'] = args.trunk_allowed_vlans

            if m.group(1) is None:
                if args.mtu:
                    if args.mtu < 1500 or args.mtu > 9216:
                        print('WARNING: MTU must be between 1500 and 9216')
                        continue

                    n9k_switchport['mtu'] = args.mtu

            if args.port_channel:
                n9k_switchport['port_channel'] = args.port_channel
                if not args.no_vpc:
                    n9k_switchport['vpc'] = True
                if args.pc_descr:
                    n9k_switchport['pc_descr'] = args.pc_descr

            n9k_switchports.append(n9k_switchport)

    os.environ['ANSIBLE_FORCE_COLOR'] = 'True'
    os.environ['ANSIBLE_HOST_KEY_CHECKING'] = 'False'
    os.environ['ANSIBLE_PERSISTENT_COMMAND_TIMEOUT'] = '300'

    command = ['ansible-playbook', '-i', 'inventory/hosts', '--limit', '{}'.format(args.switch),
               '-u', args.username, '-k', '-e',
               '{{"n9k_switchports": {}}}'.format(
        json.dumps(n9k_switchports)),
        '-e', 'ansible_python_interpreter={}'.format(sys.executable),
        'configure-switchport-playbook.yml']

    p = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    for c in iter(lambda: p.stdout.read(1), ''):
        sys.stdout.write(c)
        sys.stdout.flush()


if __name__ == '__main__':
    main()
