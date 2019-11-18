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


import requests
import json
import sys
import time
import os
import re
from subprocess import call

PI_USER = ''
PI_PASS = ''
PI = '10.66.200.11'
PAGE_SIZE = 1000


def get_devs():
    global PI_USER, PI_PASS, PI, PAGE_SIZE, room_id, SPARK_API, SPARK_TOKEN, TEXT_BAD, TEXT_GOOD

    url = "https://%s/webacs/api/v1/data/InventoryDetails.json?.full=true&.maxResults=%d" % (
        PI, PAGE_SIZE)
    headers = {
        'Connection': 'close'
    }

    devices = []
    dets = []
    done = False
    first = 0
    while not done:
        code = 401
        i = 0
        nurl = url + "&.firstResult=" + str(first * PAGE_SIZE)
        while code != 200 and i < 40:
            response = requests.request("GET", nurl, auth=(
                PI_USER, PI_PASS), headers=headers, verify=False)
            code = response.status_code
            if code != 200:
                i += 1
                time.sleep(3)
        if code == 200:
            j = json.loads(response.text)
            if int(j['queryResponse']['@last']) + 1 == int(j['queryResponse']['@count']):
                done = True
            else:
                first += 1

            for dev in j['queryResponse']['entity']:
                det_dic = {}
                if 'ipAddress' not in dev['inventoryDetailsDTO']['summary']:
                    continue
                det_dic['ip'] = dev['inventoryDetailsDTO'][
                    'summary']['ipAddress']
                det_dic['serial'] = 'N/A'
                if 'udiDetails' in dev['inventoryDetailsDTO']:
                    for udi in dev['inventoryDetailsDTO']['udiDetails']['udiDetail']:
                        if 'productId' in udi:
                            if re.search(r'^WS-C', udi['productId']):
                                det_dic['serial'] = udi['udiSerialNr']

                dets.append(det_dic)

    first = 0
    done = False
    url = "https://%s/webacs/api/v1/data/Devices.json?.full=true&.maxResults=%d" % (
        PI, PAGE_SIZE)

    while not done:
        code = 401
        i = 0
        nurl = url + "&.firstResult=" + str(first * PAGE_SIZE)
        while code != 200 and i < 40:
            response = requests.request("GET", nurl, auth=(
                PI_USER, PI_PASS), headers=headers, verify=False)
            code = response.status_code
            if code != 200:
                i += 1
                time.sleep(3)
        if code == 200:
            j = json.loads(response.text)
            if int(j['queryResponse']['@last']) + 1 == int(j['queryResponse']['@count']):
                done = True
            else:
                first += 1

            for dev in j['queryResponse']['entity']:
                dev_dic = {}
                if 'ipAddress' not in dev['devicesDTO']:
                    continue
                if 'deviceName' in dev['devicesDTO']:
                    dev_dic['name'] = dev['devicesDTO']['deviceName']
                else:
                    dev_dic['name'] = dev['devicesDTO']['ipAddress']
                dev_dic['ip'] = dev['devicesDTO']['ipAddress']
                if 'deviceType' not in dev['devicesDTO']:
                    continue
                dev_dic['serial'] = 'N/A'
                for det in dets:
                    if det['ip'] == dev_dic['ip']:
                        dev_dic['serial'] = det['serial']
                dev_dic['type'] = dev['devicesDTO']['deviceType']

                devices.append(dev_dic)

    return devices

devs = get_devs()
print "Name,IP,Type,Serial Number"
for dev in devs:
    print dev['name'] + "," + dev['ip'] + "," + dev['type'] + "," + dev['serial']
