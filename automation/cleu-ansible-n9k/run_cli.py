#!/usr/bin/env python3

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
    parser.add_argument('--switch', '-s', metavar='<SWITCH NAME(s)>',
                        help='Switch name or names (comma-separated) on which to run commands (defaults to all) ')
    parser.add_argument('--commands', '-c', metavar='<COMMAND(s)>', help='Pipe-separated list of commands to run', required=True)
    parser.add_argument('--parents', '-p', metavar='<PARENT(s)>', help='Pipe-separated list of parents for all commands')
    parser.add_argument('--username', '-u', metavar='<USERNAME>',
                        help='Username to use to connect to the N9Ks', required=True)
    args = parser.parse_args()

    clist = args.commands.split('|')
    plist = []

    if args.parents:
        plist = args.parents.split('|')

    os.environ['ANSIBLE_FORCE_COLOR'] = 'True'
    os.environ['ANSIBLE_HOST_KEY_CHECKING'] = 'False'
    os.environ['ANSIBLE_PERSISTENT_COMMAND_TIMEOUT'] = '300'

    command = ['ansible-playbook', '-i', 'inventory/hosts',
               '-u', args.username, '-k', '-e',
               '{{"cli_commands": {}}}'.format(
        json.dumps(clist)), '-e', '{{"cli_parents": {}}}'.format(json.dumps(plist)),
        '-e', 'ansible_python_interpreter={}'.format(sys.executable),
        'run-cli-playbook.yml']

    if args.switch:
        command += ['--limit', '{}'.format(args.switch)]

    p = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    for c in iter(lambda: p.stdout.read(1), b''):
        sys.stdout.write(c.decode('utf-8'))
        sys.stdout.flush()


if __name__ == '__main__':
    main()
