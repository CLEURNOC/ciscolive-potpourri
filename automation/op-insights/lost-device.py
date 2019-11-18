#!/usr/local/bin/python2
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


import sys
import sparker
import re
import requests
import json
import logging
import traceback
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import CLEUCreds

TEAM_NAME = 'CL18-Infra_team'
ROOM_NAME = 'Lost Devices'

CMX_URL = 'http://10.100.253.13:8002/api/v0.1/cmx'

HEADERS = {
    'Accept': 'image/jpeg, application/json'
}

OUR_TENANT = 31

if __name__ == '__main__':
    spark = sparker.Sparker(True)

    print('Content-type: application/json\r\n\r\n')

    output = sys.stdin.read()

    j = json.loads(output)

    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s : %(message)s',
                        filename='/var/log/lost-device.log', level=logging.DEBUG)
    logging.debug(json.dumps(j, indent=4))

    if not 'rule' in j or j['rule']['name'] != 'LostDevicesAlert':
        logging.debug('Dropping message for {}'.format(j['rule']['name']))
        print(json.dumps({'result': 'ignore'}))
        sys.exit(0)

    message = j['message'] + '\n\n'
    cmxres = {}

    msg = message
    for asset in j['assets']:
        location = 'UNKNOWN'
        for state in asset['state']:
            if state['key'] == 'location':
                if 'hierarchy' in state['value']:
                    location = state['value']['hierarchy'].replace('!', ' > ')
                break

        msg += '* Device **{}** with MAC _{}_ is back in **{}**\n'.format(
            asset['name'], asset['macAddresses'][0].lower(), location)

        try:
            response = requests.request('GET', CMX_URL, params={'mac': asset['macAddresses'][
                                        0].lower(), 'marker': 'green', 'size': 1440}, headers=HEADERS, stream=True)
            response.raise_for_status()
        except Exception as e:
            logging.error('Failed to get result from CMX: {}'.format(e))
            continue

        if response.headers.get('content-type') == 'application/json':
            continue

        cmxres[asset['name']] = response.raw.data

    spark.post_to_spark(TEAM_NAME, ROOM_NAME, msg)
    for cmx in cmxres:
        spark.post_to_spark_with_attach(TEAM_NAME, ROOM_NAME, 'Location of {}'.format(
            cmx), cmxres[cmx], '{}_location.jpg'.format(cmx.replace(' ', '_')), 'image/jpeg')

    print(json.dumps({'result': 'success'}))
