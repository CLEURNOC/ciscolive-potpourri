#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017-2018  Joe Clarke <jclarke@cisco.com>
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


import time
import os
import pprint
import argparse
import sys
import re
from NXOSVlans import NXOSVlans

if __name__ == '__main__':
    nav = NXOSVlans()

    parser = argparse.ArgumentParser(
        prog=sys.argv[0], description='Add or delete a VLAN to an NX-OS switch')
    parser.add_argument('--device', '-d', dest='device', metavar='<HOSTNAME|IP>',
                        help='NX-OS device to which to add VLAN', required=True)
    parser.add_argument('--vlan', '-v', dest='vid',
                        metavar='<VLAN_ID>', help='VLAN ID', type=int, required=True)
    parser.add_argument('--name', '-n', dest='vname',
                        metavar='<VLAN_NAME>', help='VLAN Name')
    parser.add_argument('--username', '-u', dest='username',
                        metavar='<USERNAME>', help='Device username', required=True)
    parser.add_argument('--trunks', '-t', dest='trunks', metavar='<TRUNK_PORT1 TRUNK_PORT2 ...>',
                        nargs='+', help='List of trunk ports to which VLAN will be added')
    parser.add_argument('--svi', '-i', dest='svi',
                        action='store_true', help='Create an SVI for this VLAN?')
    parser.add_argument('--description', '-e', dest='description',
                        metavar='<DESCRIPTION>', help='SVI description')
    parser.add_argument('--ip', '-4', dest='ipv4', metavar='<IP_ADDRESS/CIDR>',
                        help='SVI IPv4 address and subnet bits')
    parser.add_argument('--ip6', '-6', dest='ipv6', metavar='<IPV6_ADDRESS/LENGTH>',
                        help='SVI IPv6 address and prefix length')
    parser.add_argument('--hsrp', '-r', dest='hsrpv4',
                        metavar='<HSRP_IPV4_ADDRESS>', help='SVI HSRP virtual IPv4 address')
    parser.add_argument('--hsrpv6', '-R', dest='hsrpv6',
                        metavar='<HSRP_IPV6_ADDRESS>', help='SVI HSRP virtual IPv6 address')
    parser.add_argument('--priority', '-p', dest='hsrp_priority',
                        metavar='<PRIORITY>', type=int, help='SVI HSRP priority')
    parser.add_argument('--delete', '-D', action='store_true',
                        dest='delete', help='Delete the specified VLAN')
    parser.set_defaults(svi=False, delete=False)
    parser.parse_args(namespace=nav)
    if not nav.delete and not nav.vname:
        parser.error('VLAN name must be specified')
    if not nav.delete and nav.svi and not nav.ipv4:
        parser.error('IPv4 address must be specified for the SVI')
    if not nav.delete and nav.svi and not nav.description:
        nav.description = '-> {}'.format(nav.name)
    if not nav.delete and nav.svi and nav.hsrpv6 and not nav.ipv6:
        parser.error('IPv6 address must be specified if HSRPv6 is used')
    if not nav.delete and not nav.svi and (nav.ipv4 or nav.ipv6 or nav.hsrpv4 or nav.hsrpv6):
        parser.error(
            'IP and HSRP addresses can only be specified if --svi is given')
    if not nav.delete and nav.ipv4 and not re.match(r'[\d\.]+/\d+', nav.ipv4):
        parser.error(
            'Invalid IPv4 address; must be in the format of ADDRESS/CIDR')
    if not nav.delete and nav.ipv6 and not re.match(r'[a-fA-F0-9:]+/\d+', nav.ipv6):
        parser.error(
            'Invalid IPv6 address; must be in the format of ADDRESS/LENGTH')
    if not nav.delete and nav.hsrpv4 and not re.match(r'[\d\.]+', nav.hsrpv4):
        parser.error('Invalid HSRPv4 address')
    if not nav.delete and nav.hsrpv6 and not re.match(r'[a-fA-F0-9:]+', nav.hsrpv6):
        parser.error('Invalid HSRPv6 address')
    if not nav.delete and (nav.hsrpv4 or nav.hsrpv6) and not nav.hsrp_priority:
        parser.error('SVI HSRP priority must be specified')

    if 'NXOS_ADMIN_PW' not in os.environ:
        print('The environment variable "NXOS_ADMIN_PW" must be set with the password for {}'.format(
            nav.username))
        sys.exit(1)

    if nav.delete:
        res = nav.delete_l2_vlan()
        if not res:
            print('Error deleting VLAN {} from {}'.format(nav.vid, nav.device))
            sys.exit(1)
    else:

        res = nav.deploy_l2_vlan()
        if not res:
            print('Error deploying VLAN {} to {}; removing VLAN'.format(
                nav.vid, nav.device))
            nav.delete_l2_vlan()
            sys.exit(1)

        if nav.svi:
            res = nav.deploy_svi()
            if res:
                nav.write_config()
            else:
                print('Error deploying SVI for VLAN {} to {}; removing L2 VLAN'.format(
                    nav.vid, nav.device))
                nav.delete_l2_vlan()
                sys.exit(1)
