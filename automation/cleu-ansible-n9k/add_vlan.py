#!/usr/bin/env python3

import argparse
import sys
import re
import subprocess
import os
import tempfile
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

IPV4SEG = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
IPV4ADDR = r'(?:(?:' + IPV4SEG + r'\.){3,3}' + IPV4SEG + r')'
IPV6SEG = r'(?:(?:[0-9a-fA-F]){1,4})'
IPV6GROUPS = (
    r'(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,                  # 1:2:3:4:5:6:7:8
    # 1::                                 1:2:3:4:5:6:7::
    r'(?:' + IPV6SEG + r':){1,7}:',
    # 1::8               1:2:3:4:5:6::8   1:2:3:4:5:6::8
    r'(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,
    # 1::7:8             1:2:3:4:5::7:8   1:2:3:4:5::8
    r'(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',
    # 1::6:7:8           1:2:3:4::6:7:8   1:2:3:4::8
    r'(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',
    # 1::5:6:7:8         1:2:3::5:6:7:8   1:2:3::8
    r'(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',
    # 1::4:5:6:7:8       1:2::4:5:6:7:8   1:2::8
    r'(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',
    # 1::3:4:5:6:7:8     1::3:4:5:6:7:8   1::8
    IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',
    # ::2:3:4:5:6:7:8    ::2:3:4:5:6:7:8  ::8       ::
    r':(?:(?::' + IPV6SEG + r'){1,7}|:)',
    # fe80::7:8%eth0     fe80::7:8%1  (link-local IPv6 addresses with zone index)
    r'fe80:(?::' + IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',
    # ::255.255.255.255  ::ffff:255.255.255.255  ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    r'::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + IPV4ADDR,
    # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
    r'(?:' + IPV6SEG + r':){1,4}:[^\s:]' + IPV4ADDR,
)
# Reverse rows for greedy match
IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])


def main():
    parser = argparse.ArgumentParser(
        prog=sys.argv[0], description='Add a VLAN to the network')
    parser.add_argument('--vlan-name', '-n', metavar='<VLAN_NAME>',
                        help='Name of the VLAN to add', required=True)
    parser.add_argument('--vlan-id', '-i', metavar='<VLAN_ID>',
                        help='ID of the VLAN to add', type=int, required=True)
    parser.add_argument('--vm-vlan-name', metavar='<VM_VLAN_NAME>',
                        help='Name of the VLAN port group in VMware (required when adding to vCenter)')
    parser.add_argument('--svi-v4-network', metavar='<SVI_NETWORK>',
                        help='IPv4 network address of the SVI')
    parser.add_argument('--svi-subnet-len', metavar='<SVI_PREFIX_LEN>',
                        help='Subnet length of the SVI v4 IP (e.g., 24 for a /24)', type=int)
    parser.add_argument(
        '--svi-standard-v4', help='Follow the standard rules to add a MAJOR.VLAN.IDF.0/24 SVI address', action='store_true')
    parser.add_argument('--svi-v6-network', metavar='<SVI_NETWORK>',
                        help='IPv6 network address of the SVI (should end with "::"; prefix len is assumed to be /64)')
    parser.add_argument(
        '--svi-standard-v6', help='Follow the standard rules to add a PREFIX:[VLAN][IDF]::/64 SVI address', action='store_true')
    parser.add_argument('--svi-descr', metavar='<SVI_DESCRIPTION>',
                        help='Description of the SVI')
    parser.add_argument('--mtu', '-m', metavar='<MTU>',
                        help='MTU of SVI (default: 9216)', type=int)
    parser.add_argument(
        '--is-stretched', help='VLAN is stretched between both data centres (default: False)', action='store_true')
    parser.add_argument(
        '--no-hsrp', help='Use HSRP or not (default: HSRP will be configured)', action='store_true')
    parser.add_argument('--no-passive-interface',
                        help='Whether or not to have OSPF use passive interface (default: SVI will be a passive interface)', action='store_true')
    parser.add_argument(
        '--v6-link-local', help='Only use v6 link-local addresses (default: global IPv6 is expected)', action='store_true')
    parser.add_argument(
        '--ospf-broadcast', help='OSPF network is broadcast instead of P2P (default: P2P)', action='store_true')
    parser.add_argument('--interface', action='append', metavar='<INTF>',
                        help='Interface to enable for VLAN (can be specified more than once)')
    parser.add_argument(
        '--generate-iflist', help='Automatically generate a list of allowed interfaces for VLAN (default: False)', action='store_true')
    parser.add_argument('--vmware-cluster', action='append', metavar='<CLUSTER>',
                        help='VMware cluster to configure for VLAN (can be specified more than once) (default: all clusters are configured)')
    parser.add_argument('--username', '-u', metavar='<USERNAME>',
                        help='Username to use to connect to the N9Ks', required=True)
    parser.add_argument('--limit', '-L', metavar='<HOSTS_OR_GROUP_NAMES>',
                        help='Comma-separated list of hosts or host group names (from inventory/hosts) on which to restrict operations')
    parser.add_argument('--tags', metavar='<TAG_LIST>',
                        help='Comma-separated list of task tags to execute')
    parser.add_argument(
        '--list-tags', help='List available task tags', action='store_true')
    parser.add_argument(
        '--test-only', help='Only check syntax and attempt to predict changes (NO CHANGES WILL BE MADE)', action='store_true')
    args = parser.parse_args()

    if args.vlan_id < 1 or args.vlan_id > 3967:
        print('ERROR: VLAN ID must be between 1 and 3967')
        sys.exit(1)

    svi_prefix = None
    build_v4 = False
    use_hsrp = True
    passive_interface = True
    svi_v6_link_local = False
    build_v6 = True
    ospf_type = 'point-to-point'
    is_stretched = False
    generate_iflist = False

    if args.svi_v4_network and args.svi_standard_v4:
        print('ERROR: Cannot specify both --svi-v4-network and --svi-standard-v4.')
        sys.exit(1)

    if args.svi_standard_v4:
        build_v4 = True

    if args.is_stretched:
        is_stretched = True

    if args.generate_iflist and args.interface and len(args.interface) > 0:
        print('ERROR: Cannot specify both an interface list and --generate-iflist.')
        sys.exit(1)

    if args.generate_iflist:
        generate_iflist = True

    if args.svi_v4_network:
        m = re.match(r'(\d+)\.(\d+)\.(\d+).(\d+)', args.svi_v4_network)
        for i in range(1, 5):
            if int(m.group(i)) > 255:
                print('ERROR: Invalid SVI IPv4 address, {}'.format(
                    args.svi_v4_network))
                sys.exit(1)

        if not m:
            print('ERROR: SVI Network must be an IPv4 network address.')
            sys.exit(1)

        if not args.svi_subnet_len:
            print(
                'ERROR: SVI Prefix Length is required when an SVI Network is specified.')
            sys.exit(1)

        if int(args.svi_subnet_len) < 8 or int(args.svi_subnet_len) > 30:
            print('ERROR: SVI Prefix Length must be between 8 and 30.')
            sys.exit(1)

        if args.svi_subnet_len >= 24:
            svi_prefix = '{}.{}.{}'.format(m.group(1), m.group(2), m.group(3))
        elif args.svi_prefix_len < 24 and args.svi_subnet_len >= 16:
            svi_prefix = '{}.{}'.format(m.group(1), m.group(2))
        else:
            svi_prefix = m.group(1)

    if args.svi_v4_network or args.svi_v6_network or args.svi_standard_v4 or args.svi_standard_v6:
        if args.mtu and (args.mtu < 1500 or args.mtu > 9216):
            print('ERROR: MTU must be between 1500 and 9216.')
            sys.exit(1)
        elif not args.mtu:
            args.mtu = 9216

        if args.no_passive_interface:
            passive_interface = False

        if args.no_hsrp:
            use_hsrp = False

        if args.ospf_broadcast:
            ospf_type = 'broadcast'

    if args.svi_standard_v6 and args.svi_v6_network:
        print('ERROR: Cannot specify both --svi-v6-network and --svi-standard-v6.')
        sys.exit(1)

    if args.svi_standard_v6:
        build_v6 = True

    if args.svi_v6_network:
        m = re.match(IPV6ADDR, args.svi_v6_network)

        if not m:
            print('ERROR: SVI Network must be an IPv6 network address.')
            sys.exit(1)

        if args.v6_link_local:
            print('ERROR: Cannot specify both svi-v6-network and v6-link-local.')
            sys.exit(1)

    elif args.v6_link_local:
        svi_v6_link_local = True

    os.environ['ANSIBLE_FORCE_COLOR'] = 'True'
    os.environ['ANSIBLE_HOST_KEY_CHECKING'] = 'False'
    os.environ['ANSIBLE_PERSISTENT_COMMAND_TIMEOUT'] = '300'

    if 'AD_PASSWORD' not in os.environ:
        print(
            'ERROR: AD_PASSWORD must be set in the environment first (used for vCenter and UCS).')
        sys.exit(1)

    os.environ['VMWARE_USER'] = args.username
    os.environ['VMWARE_PASSWORD'] = os.environ['AD_PASSWORD']

    cred_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    vars = {
        'ucs_mgr_username': args.username,
        'ucs_mgr_password': os.environ['AD_PASSWORD']
    }
    dump(vars, cred_file, Dumper=Dumper)
    cred_file.close()

    command = ['ansible-playbook', '-i', 'inventory/hosts',
               '-u', args.username, '-k', '-e',
               'vlan_name={}'.format(
                   args.vlan_name), '-e', 'vlan_id={}'.format(args.vlan_id),
               '-e', 'ansible_python_interpreter={}'.format(sys.executable),
               '-e', '@{}'.format(cred_file.name),
               '-e', 'build_v4={}'.format(build_v4),
               '-e', 'build_v6={}'.format(build_v6),
               '-e', 'is_stretched={}'.format(is_stretched),
               '-e', 'generate_iflist={}'.format(generate_iflist),
               '-e', 'ospf_type={}'.format(ospf_type),
               'add-vlan-playbook.yml']
    if args.vm_vlan_name:
        command += ['-e', 'vm_vlan_name=\'{}\''.format(args.vm_vlan_name)]
    if args.svi_v4_network:
        command += ['-e', 'svi_v4_prefix={}'.format(
            svi_prefix), '-e', 'svi_subnet_len={}'.format(args.svi_subnet_len),
            '-e', 'svi_v4_network={}'.format(args.svi_v4_network)]
    if args.svi_v6_network:
        command += ['-e', 'svi_v6_network={}'.format(args.svi_v6_network)]
    if args.mtu:
        command += ['-e', 'svi_mtu={}'.format(args.mtu)]
    if args.svi_descr:
        command += ['-e', 'svi_descr=\'{}\''.format(args.svi_descr)]
    if use_hsrp:
        command += ['-e', 'use_hsrp={}'.format(use_hsrp)]
    if passive_interface:
        command += ['-e', 'passive_interface={}'.format(passive_interface)]
    if svi_v6_link_local:
        command += ['-e', 'svi_v6_link_local={}'.format(svi_v6_link_local)]
    if args.interface and len(args.interface) > 0:
        command += ['-e',
                    '{{"iflist": [{}]}}'.format(','.join(args.interface))]
    if args.generate_iflist:
        command += ['-e', '{"iflist": []}']
    if args.vmware_cluster and len(args.vmware_cluster) > 0:
        command += ['-e',
                    '{{"vm_clusters": [{}]}}'.format(','.join(args.vmware_cluster))]
    if args.limit:
        command += ['--limit', args.limit]
    if args.tags:
        command += ['--tags', args.tags]
    if args.list_tags:
        command += ['--list-tags']
    if args.test_only:
        command += ['-C']
    p = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    for c in iter(lambda: p.stdout.read(1), b''):
        sys.stdout.write(c.decode('utf-8'))
        sys.stdout.flush()

    p.poll()

    if os.path.isfile(cred_file.name):
        os.remove(cred_file.name)


if __name__ == '__main__':
    main()
