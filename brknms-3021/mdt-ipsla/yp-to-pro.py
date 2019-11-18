#!/usr/bin/env python
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

from flask import Flask
from flask import Response
from ncclient import manager
from ncclient.operations import RPCError
import xmltodict
import sys
import lxml.etree as ET
from argparse import ArgumentParser
import json

app = Flask(__name__)

CONFIG_VERBOSE = False
CONFIG_OPER_ID = 0

curr_rtt = -1


@app.route('/')
def get_stats():
    global curr_rtt

    return Response('rtt {}\n'.format(curr_rtt), mimetype='text/plain')


def callback(notif):
    global curr_rtt, CONFIG_OPER_ID, CONFIG_VERBOSE

    d = xmltodict.parse(notif.xml)
    if CONFIG_VERBOSE:
        print(json.dumps(d, indent=4))
    opers = []
    if isinstance(d['notification']['push-update']['datastore-contents-xml']['ip-sla-stats']['sla-oper-entry'], list):
        opers = d['notification'][
            'push-update']['datastore-contents-xml']['ip-sla-stats']['sla-oper-entry']
    else:
        opers.append(d['notification']['push-update']
                     ['datastore-contents-xml']['ip-sla-stats']['sla-oper-entry'])
    found_rtt = False
    for oper in opers:
        if CONFIG_VERBOSE:
            print('Notif oper-id: {}'.format(oper['oper-id']))
        if int(oper['oper-id']) == CONFIG_OPER_ID:
            if CONFIG_VERBOSE:
                print('Setting curr_rtt to {}'.format(
                    oper['rtt-info']['latest-rtt']['rtt']))
            curr_rtt = int(oper['rtt-info']['latest-rtt']['rtt'])
            found_rtt = True
            break

    if not found_rtt:
        curr_rtt = -1


def errback(e):
    print('Error : {}'.format(e))


def subscribe(dev, user, password, port=830, timeout=90, period=1000):
    global app, CONFIG_VERBOSE

    with manager.connect(host=dev, port=port, username=user, password=password, timeout=timeout, hostkey_verify=False) as m:
        try:
            response = m.establish_subscription(
                callback, errback, '/ip-sla-ios-xe-oper:ip-sla-stats/sla-oper-entry', period).xml
            data = ET.fromstring(response.encode('utf-8'))
            if CONFIG_VERBOSE:
                print(ET.tostring(data, pretty_print=True))
            app.run()
        except RPCError as e:
            print('RPC Error subscribing to stream: {}'.format(e._raw))
            sys.exit(1)

if __name__ == '__main__':
    parser = ArgumentParser(description='usage:')

    parser.add_argument('-a', '--host', type=str, required=True,
                        help='Device IP address or hostname')
    parser.add_argument('-u', '--username', type=str, required=True,
                        help='Device username (NETCONF server username)')
    parser.add_argument('-p', '--password', type=str, required=True,
                        help='Device password (NETCONF server password)')
    parser.add_argument('-t', '--timeout', type=int, default=90,
                        help='NETCONF server connection timeout')
    parser.add_argument('-o', '--oper-id', type=int,
                        required=True, help='IP SLA operation ID to monitor')
    parser.add_argument('--period', type=int, default=1000,
                        help='Period to wait for notification pushes')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--port', type=int, default=830,
                        help='NETCONF server port')
    args = parser.parse_args()

    CONFIG_VERBOSE = args.verbose
    CONFIG_OPER_ID = args.oper_id

    if CONFIG_VERBOSE:
        print('Oper ID: {}'.format(CONFIG_OPER_ID))

    subscribe(args.host, args.username, args.password,
              args.port, args.timeout, args.period)
