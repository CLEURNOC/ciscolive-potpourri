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
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import json
import sys
import re
import os
import CLEUCreds

TOOL = 'tool.ciscolive.local'
DNS_BASE = 'https://dc1-dns.ciscolive.local:8443/web-services/rest/resource/'
DOMAIN = 'ciscolive.local'
CNR_HEADERS = {
    'authorization': CLEUCreds.JCLARKE_BASIC,
    'accept': 'application/json',
    'content-type': 'application/json'
}
CACHE_FILE = 'dns_records.dat'


def get_devs():
    global DOMAIN

    url = "http://{}/get/switches/json".format(TOOL)

    devices = []
    response = requests.request('GET', url)
    code = response.status_code
    if code == 200:
        j = response.json()

        for dev in j:
            dev_dic = {}
            if dev['IPAddress'] == '0.0.0.0':
                continue
            if not re.search(r'^0', dev['Hostname']):
                continue
            dev_dic['name'] = dev['Hostname']
            dev_dic['aliases'] = [unicode('{}.{}.'.format(
                dev['Name'], DOMAIN)), unicode('{}.{}.'.format(dev['AssetTag'], DOMAIN))]

            dev_dic['ip'] = dev['IPAddress']

            devices.append(dev_dic)

    return devices


def add_entry(url, hname, dev):
    global CNR_HEADERS, DOMAIN

    try:
        host_obj = {
            'addrs': {
                'stringItem': [
                    dev['ip']
                ]
            },
            'aliases': {
                'stringItem': [

                ]
            },
            'name': hname,
            'zoneOrigin': DOMAIN
        }
        for alias in dev['aliases']:
            host_obj['aliases']['stringItem'].append(alias)

        response = requests.request(
            'PUT', url, headers=CNR_HEADERS, json=host_obj, verify=False)
        response.raise_for_status()
        print('Added entry for {} ==> {} with aliases {}'.format(
            hname, dev['ip'], str(dev['aliases'])))
    except Exception as e:
        sys.stderr.write(
            'Error adding entry for {}: {}\n'.format(hname, e))

if __name__ == '__main__':

    prev_records = []

    if os.path.exists(CACHE_FILE):
        fd = open(CACHE_FILE, 'r')
        prev_records = json.load(fd)
        fd.close()

    devs = get_devs()
    for record in prev_records:
        found_record = False
        for dev in devs:
            hname = dev['name'].replace('.{}'.format(DOMAIN), '')
            if record == hname:
                found_record = True
                break
        if found_record:
            continue

        url = DNS_BASE + 'CCMHost' + '/{}'.format(record)
        try:
            response = requests.request('DELETE', url, headers=CNR_HEADERS, params={
                                        'zoneOrigin': DOMAIN}, verify=False)
            response.raise_for_status()
        except Exception as e:
            sys.stderr.write('Failed to delete entry for {}'.format(record))

    records = []
    for dev in devs:
        hname = dev['name'].replace('.{}'.format(DOMAIN), '')

        records.append(hname)
        url = DNS_BASE + 'CCMHost' + '/{}'.format(hname)
        response = requests.request('GET', url, headers=CNR_HEADERS, params={
                                    'zoneOrigin': DOMAIN}, verify=False)
        if response.status_code == 404:
            iurl = DNS_BASE + 'CCMHost'
            response = requests.request('GET', iurl, params={'zoneOrigin': DOMAIN, 'addrs': dev[
                                        'ip'] + '$'}, headers=CNR_HEADERS, verify=False)
            cur_entry = []
            if response.status_code != 404:
                cur_entry = response.json()

            if len(cur_entry) > 0:
                print('Found entry for {}: {}'.format(
                    dev['ip'], response.status_code))
                cur_entry = response.json()
                if len(cur_entry) > 1:
                    print(
                        'ERROR: Found multiple entries for IP {}'.format(dev['ip']))
                    continue

                print('Found old entry for IP {} => {}'.format(
                    dev['ip'], cur_entry[0]['name']))

                durl = DNS_BASE + 'CCMHost' + \
                    '/{}'.format(cur_entry[0]['name'])
                try:
                    response = requests.request('DELETE', durl, params={
                                                'zoneOrigin': DOMAIN}, headers=CNR_HEADERS, verify=False)
                    response.raise_for_status()
                except Exception as e:
                    sys.stderr.write('Failed to delete stale entry for {} ({})\n'.format(
                        cur_entry[0]['name'], dev['ip']))
                    continue

            add_entry(url, hname, dev)
        else:
            cur_entry = response.json()
            create_new = True
            for addr in cur_entry['addrs']['stringItem']:
                if addr == dev['ip']:
                    if 'aliases' in dev and 'aliases' in cur_entry:
                        if (len(dev['aliases']) > 0 and 'stringItem' not in cur_entry['aliases']) or (len(dev['aliases']) != len(cur_entry['aliases']['stringItem'])):
                            break
                        common = set(dev['aliases']) & set(
                            cur_entry['aliases']['stringItem'])
                        if len(common) != len(dev['aliases']):
                            break
                        create_new = False
                        break
                    elif ('aliases' in dev and 'aliases' not in cur_entry) or ('aliases' in cur_entry and 'aliases' not in dev):
                        break
                    else:
                        create_new = False
                        break

            if create_new:
                print('Deleting entry for {}'.format(hname))
                try:
                    response = requests.request('DELETE', url, headers=CNR_HEADERS, params={
                                                'zoneOrigin': DOMAIN}, verify=False)
                    response.raise_for_status()
                except Exception as e:
                    sys.stderr.write(
                        'Error deleting entry for {}: {}\n'.format(hname, e))

                add_entry(url, hname, dev)
            else:
                print('Not creating a new entry for {} as it already exists'.format(
                      dev['name']))

    fd = open(CACHE_FILE, 'w')
    json.dump(records, fd, indent=4)
    fd.close()
