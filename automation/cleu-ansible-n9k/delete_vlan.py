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


def main():
    parser = argparse.ArgumentParser(
        prog=sys.argv[0], description='Delete a VLAN from the network')
    parser.add_argument('--vlan-name', '-n', metavar='<VLAN_NAME>',
                        help='Name of the VLAN to add', required=True)
    parser.add_argument('--vm-vlan-name', metavar='<VM_VLAN_NAME>',
                        help='Name of the VLAN port group in VMware ', required=True)
    parser.add_argument('--vlan-id', '-i', metavar='<VLAN_ID>',
                        help='ID of the VLAN to add', type=int, required=True)
    parser.add_argument(
        '--is-stretched', help='VLAN is stretched between both data centres (default: False)', action='store_true')
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
        '--check-only', help='Only check syntax and attempt to predict changes', action='store_true')
    args = parser.parse_args()

    if args.vlan_id < 1 or args.vlan_id > 3967:
        print('ERROR: VLAN ID must be between 1 and 3967')
        sys.exit(1)

    is_stretched = False
    generate_iflist = False

    if args.is_stretched:
        is_stretched = True

    if args.generate_iflist and args.interface and len(args.interface) > 0:
        print('ERROR: Cannot specify both an interface list and --generate-iflist.')
        sys.exit(1)

    if args.generate_iflist:
        generate_iflist = True

    os.environ['ANSIBLE_FORCE_COLOR'] = 'True'
    os.environ['ANSIBLE_HOST_KEY_CHECKING'] = 'False'
    os.environ['ANSIBLE_PERSISTENT_COMMAND_TIMEOUT'] = '300'

    if 'AD_PASSWORD' not in os.environ:
        print(
            'ERROR: AD_PASSWORD must be set in the environment first (used for vCenter and UCS).')
        sys.exit(1)

    os.environ['VMWARE_USER'] = args.username
    os.environ['VMWARE_PASSWORD'] = os.environ['VMWARE_PASSWORD']

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
                   args.vlan_name), '-e', 'vlan_id={}'.format(args.vlan_id), '-e', 'vm_vlan_name=\'{}\''.format(args.vm_vlan_name),
               '-e', 'ansible_python_interpreter={}'.format(sys.executable),
               '-e', '@{}'.format(cred_file.name),
               '-e', 'delete_vlan=True',
               '-e', 'is_stretched={}'.format(is_stretched),
               '-e', 'generate_iflist={}'.format(generate_iflist),
               'delete-vlan-playbook.yml']
    if args.interface and len(args.interface) > 0:
        command += ['-e',
                    '{{"iflist": [{}]}}'.format(','.join(args.interface))]
    if args.generate_iflist:
        command += ['-e', '{{"iflist": []}}']
    if args.vmware_cluster and len(args.vmware_cluster) > 0:
        command += ['-e',
                    '{{"vm_clusters": [{}]}}'.format(','.join(args.vmware_cluster))]
    if args.limit:
        command += ['--limit', args.limit]
    if args.tags:
        command += ['--tags', args.tags]
    if args.list_tags:
        command += ['--list-tags']
    if args.check_only:
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
