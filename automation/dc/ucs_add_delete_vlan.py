#!/usr/bin/env python2
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


import argparse
import os
import sys
from UCSVlans import UCSVlans

if __name__ == '__main__':
    uv = UCSVlans()

    parser = argparse.ArgumentParser(
        prog=sys.argv[0], description='Add a new VLAN to a UCS fabric')
    parser.add_argument('--device', '-d', dest='device', metavar='<HOSTNAME|IP>',
                        help='UCS chassis to which to add VLAN', required=True)
    parser.add_argument('--vlan', '-v', dest='vid',
                        metavar='<VLAN_ID>', help='VLAN ID', type=int, required=True)
    parser.add_argument('--name', '-n', dest='vname',
                        metavar='<VLAN_NAME>', help='VLAN Name')
    parser.add_argument('--username', '-u', dest='username',
                        metavar='<USERNAME>', help='Device username', required=True)
    parser.add_argument('--policy', '-p', dest='policy', metavar='<POLICY>',
                        help='Name of LAN Connectivity Policy')
    parser.add_argument('--vnic-a', '-a', dest='vnic_a', metavar='<VNIC_A_NAME>',
                        help='Name of vNIC in LAN connectivity policy for Fabric-A')
    parser.add_argument('--vnic-b', '-b', dest='vnic_b', metavar='<VNIC_B_NAME>',
                        help='Name of vNIC in LAN connectivity policy for Fabric-B')
    parser.add_argument('--delete', '-D', dest='delete',
                        action='store_true', help='Delete the specified VLAN')
    parser.set_defaults(delete=False)
    parser.parse_args(namespace=uv)

    if 'UCS_ADMIN_PW' not in os.environ:
        print('The environment variable "UCS_ADMIN_PW" must be set with the password for {}'.format(
            uv.username))
        sys.exit(1)

    if not uv.delete and not uv.vname:
        parser.error('VLAN name must be specified')
    if not uv.delete and not uv.policy:
        parser.error('LAN connectivity policy name must be specified')
    if not uv.delete and not uv.vnic_a:
        parser.error('vNIC name for Fabric-A must be specified')
    if not uv.delete and not uv.vnic_b:
        parser.error('vNIC name for Fabric-B muct be specified')

    if uv.delete:
        res = uv.delete_fabric_vlan()
        if not res:
            print('Error deleting VLAN {} from {}'.format(uv.vid, uv.device))
            uv.logout()
            sys.exit(1)
    else:
        res = uv.deploy_fabric_vlan()
        if not res:
            uv.logout()
            sys.exit(1)

        res = uv.deploy_lan_policy()
        if not res:
            print('Error deploying LAN Policy changes to {}; removing VLAN from fabric'.format(
                uv.device))
            uv.delete_fabric_vlan()
            uv.logout()
            sys.exit(1)

    uv.logout()
