#!/usr/bin/env python3
#
# Copyright (c) 2017-2019  Joe Clarke <jclarke@cisco.com>
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

import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys
import re
from netaddr import IPAddress
import CLEUCreds
from cleu.config import Config as C

IDF_CNT = 99
ADDITIONAL_IDFS = (252, 253, 254)
FIRST_IP = 31
LAST_IP = 253

IDF_OVERRIDES = {
    252: {
        'first_ip': 160,
        'last_ip': '250'
    },
    253: {
        'first_ip': 160,
        'last_ip': '250'
    },
    254: {
        'first_ip': 160,
        'last_ip': '250'
    }
}

SCOPE_BASE = C.DHCP_BASE + Scope

DHCP_TEMPLATE = {
    "optionList": {
        "OptionItem": []
    }
}

HEADERS = {
    'authorization': CLEUCreds.JCLARKE_BASIC,
    'accept': 'application/json',
    'content-type': 'application/json'
}


def mtoc(mask):
    return IPAddress(mask).netmask_bits()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.stderr.write("usage: {} INPUT_FILE\n".format(sys.argv[0]))
        sys.exit(1)

    contents = None

    try:
        fd = open(sys.argv[1], 'r')
        contents = fd.read()
        fd.close()
    except Exception as e:
        sys.stderr.write("Failed to open {}: {}\n".format(sys.argv[1], str(e)))
        sys.exit(1)

    for row in contents.split('\n'):
        row = row.strip()
        if re.search(r'^#', row):
            continue
        if row == '':
            continue
        [vlan, mask, name, policy] = row.split(',')
        if vlan == '' or mask == '' or name == '' or policy == '':
            sys.stderr.write("Skipping malformed row '{}'\n".format(row))
            continue

        start = 1
        cnt = IDF_CNT

        idf_set = ()

        if mask == '255.255.0.0':
            start = 0
            cnt = 0

        for i in range(start, cnt + 1):
            idf_set += (i,)

        if mask != '255.255.0.0':
            idf_set += ADDITIONAL_IDFS

        for i in idf_set:
            prefix = 'IDF-{}'.format(str(i).zfill(3))
            if i == 0:
                prefix = 'CORE'

            scope = ('{}-{}'.format(prefix, name)).upper()
            ip = '10.{}.{}.0'.format(vlan, i)
            octets = ['10', vlan, str(i), '0']
            roctets = list(octets)
            roctets[3] = '254'

            url = '{}/{}'.format(DHCP_BASE, scope)

            response = requests.request(
                'GET', url, headers=HEADERS, verify=False)
            if response.status_code != 404:
                sys.stderr.write("Scope {} already exists: {}\n".format(
                    scope, response.status_code))
                continue

            template = {'optionList': {'OptionItem': []}}
            if mask == '255.255.0.0':
                roctets[2] = '255'
            template['optionList']['OptionItem'].append(
                {'number': '3', 'value': '.'.join(roctets)})
            first_ip = FIRST_IP
            last_ip = LAST_IP
            if i in IDF_OVERRIDES:
                first_ip = IDF_OVERRIDES[i]['first_ip']
                last_ip = IDF_OVERRIDES[i]['last_ip']

            sipa = list(octets)
            sipa[3] = str(first_ip)
            eipa = list(octets)
            eipa[3] = str(last_ip)
            if mask == '255.255.0.0':
                eipa[2] = '255'

            sip = '.'.join(sipa)
            eip = '.'.join(eipa)

            rlist = {'RangeItem': [{'end': eip, 'start': sip}]}
            cidr = mtoc(mask)

            payload = {'embeddedPolicy': template, 'name': scope, 'policy': policy,
                       'rangeList': rlist, 'subnet': '{}/{}'.format(ip, cidr), 'tenantId': '0', 'vpnId': '0'}

            try:
                response = requests.request('PUT', url, data=json.dumps(
                    payload), headers=HEADERS, verify=False)
                response.raise_for_status()
            except Exception as e:
                sys.stderr.write("Error adding scope {} ({}/{}) with range sip:{} eip:{}: {} ({})\n".format(
                    scope, ip, cidr, sip, eip, response.text, str(e)))
                sys.stderr.write("Request: {}\n".format(
                    json.dumps(payload, indent=4)))
                continue
