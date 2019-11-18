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
BEER_ROOM_NAME = 'Beer Alarms'
OPI_ROOM_NAME = 'CL18 - Operational Insights Demo'

LOGIN_URL_1 = 'https://am-api.cmxcisco.com/api/tm/v1/account/local/login'
LOGIN_URL_2 = 'https://am-api.cmxcisco.com/api/tm/v1/account/registered/apps/31'
LOGIN_URL_3 = 'https://opinsights.cisco.com/api/am/v1/auth/user/current/user'

CMX_URL = 'http://10.100.253.13:8002/api/v0.1/cmx'

SENSOR_URL = 'https://opinsights.cisco.com/api/am/v1/entities/tags/30'

HEADERS = {
    'Authorization': 'Basic {}'.format(CLEUCreds.OPINSIGHT_BASIC)
}

OUR_TENANT = 31

if __name__ == '__main__':
    spark = sparker.Sparker(True)

    print('Content-type: application/json\r\n\r\n')

    output = sys.stdin.read()

    j = json.loads(output)

    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s : %(message)s',
                        filename='/var/log/fridge-alarm.log', level=logging.DEBUG)
    logging.debug(json.dumps(j, indent=4))

    message = j['message']
    us = 'Anonymous'

    noc_fridge = 'NOC Fridge'

    if 'name' in j['assets'][0]:
        us = j['assets'][0]['name']

    if us == noc_fridge:
        try:
            response = requests.request(
                'POST', LOGIN_URL_1, headers=HEADERS, verify=False)
            response.raise_for_status()
        except Exception as e:
            logging.error('Failed to login to {}: {}'.format(LOGIN_URL_1, e))
            print(json.dumps({'result': 'fail'}))
            sys.exit(1)

        login1 = response.json()
        token1 = None

        for account in login1['accountDetails']:
            if account['tenantId'] == OUR_TENANT:
                token1 = account['token']
                break

        if token1 is None:
            logging.error('Failed to get token from {}'.format(response.text))
            print(json.dumps({'result': 'fail'}))
            sys.exit(1)

        headers = {
            'Authorization': 'JWT {}'.format(token1)
        }

        try:
            response = requests.request(
                'GET', LOGIN_URL_2, headers=headers, verify=False)
            response.raise_for_status()
        except Exception as e:
            logging.error('Failed to login to {}: {}'.format(LOGIN_URL_2, e))
            print(json.dumps({'result': 'fail'}))
            sys.exit(1)

        try:
            response = requests.request(
                'GET', LOGIN_URL_3, headers=headers, verify=False)
            response.raise_for_status()
        except Exception as e:
            logging.error('Failed to login to {}: {}'.format(LOGIN_URL_3, e))
            print(json.dumps({'result': 'fail'}))
            sys.exit(1)

        login3 = response.json()
        token2 = login3['token']

        headers = {
            'Authorization': 'JWT {}'.format(token2)
        }

        try:
            response = requests.request(
                'GET', SENSOR_URL, headers=headers, verify=False)
            response.raise_for_status()
        except Exception as e:
            logging.error(
                'Failed to get sensor info from {}: {}'.format(SENSOR_URL, e))
            print(json.dumps({'result': 'fail'}))
            sys.exit(1)

        sensor_data = response.json()
        logging.debug('Read {}'.format(json.dumps(sensor_data, indent=4)))

        temperature = None
        for datum in sensor_data['data']:
            if datum['data']['units'] == 'Degrees Celsius':
                temperature = datum['data']['measurement']
                break

        msg = 'Hey, all!  Your friendly **{}** sent a message: _{}_.'
        if temperature is not None:
            msg += '  Additionally, the temperature of your beer is now **{}** &#176;C'

        spark.post_to_spark(TEAM_NAME, BEER_ROOM_NAME,
                            msg.format(us, message, temperature))
    else:
        mac_address = j['assets'][0]['macAddresses'][0]

        url = CMX_URL

        headers = {
            'Accept': 'image/jpeg, application/json'
        }

        loc_image = None

        response = None

        try:
            response = requests.request(
                'GET', url, headers=headers, params={'tag': mac_address.lower(), 'marker': 'green', 'size': 1440}, stream=True)
            response.raise_for_status()
        except Exception:
            logging.error('Encountered error getting data from cmx: {}'.format(
                traceback.format_exc()))

        if response is not None and response.headers.get('content-type') == 'application/json':
            loc_image = None
        elif response is not None:
            loc_image = response.raw.data

        msg = '{} {}'.format(message, us)
        spark.post_to_spark(TEAM_NAME, OPI_ROOM_NAME, msg)

        if loc_image is not None:
            spark.post_to_spark_with_attach(TEAM_NAME, OPI_ROOM_NAME, '{}\'s location from CMX'.format(
                us), loc_image, '{}_location.jpg'.format(us), 'image/jpeg')

    print(json.dumps({'result': 'success'}))
