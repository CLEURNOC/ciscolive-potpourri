#!/usr/bin/env python3

import argparse
import sys
import re
import subprocess
import os


def main():
    parser = argparse.ArgumentParser(
        prog=sys.argv[0], description='Add a VLAN to the core')
    parser.add_argument('--key', metavar='<TACACS_KEY>',
                        help='Clear text TACACS+ key', required=True)
    parser.add_argument('--username', '-u', metavar='<USERNAME>',
                        help='Username to use to connect to the N9Ks', required=True)
    parser.add_argument('--site', '-s', metavar='<SITE NAME>',
                        help='Name of site to which to add N9Ks (default: all sites)')
    args = parser.parse_args()

    os.environ['ANSIBLE_FORCE_COLOR'] = 'True'
    os.environ['ANSIBLE_HOST_KEY_CHECKING'] = 'False'
    os.environ['ANSIBLE_PERSISTENT_COMMAND_TIMEOUT'] = '300'

    command = ['ansible-playbook', '-i', 'inventory/hosts',
               '-u', args.username, '-k', '-e',
               'tacacs_key={}'.format(args.key), '-e', 'ansible_python_interpreter={}'.format(sys.executable),
               'add-aaa-playbook.yml']
    if args.site:
        command += ['--limit', args.site]
    p = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    for c in iter(lambda: p.stdout.read(1), b''):
        sys.stdout.write(c.decode('utf-8'))
        sys.stdout.flush()


if __name__ == '__main__':
    main()
