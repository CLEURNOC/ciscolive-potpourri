#!/usr/local/bin/python2
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

import sys
import json
from sparker import Sparker
import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import time
import traceback
import socket
import logging
import CLEUCreds

CMX_GW = 'http://cl-freebsd.ciscolive.network:8002/api/v0.1/cmx'
DNS_BASE = 'https://dc1-dns.ciscolive.network:8443/web-services/rest/resource/'
DOMAIN = 'ciscolive.network'

CNR_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': CLEUCreds.JCLARKE_BASIC
}

ALLOWED_TO_CREATE = ['jclarke@cisco.com',
                     'ksekula@cisco.com', 'ayourtch@cisco.com', 'rkamerma@cisco.com', 'thulsdau@cisco.com',
                     'lhercot@cisco.com', 'pweijden@cisco.com', 'udiedric@cisco.com']

spark = Sparker(token=CLEUCreds.SPARK_TOKEN, logit=True)

SPARK_TEAM = 'CL19 NOC Team'
SPARK_ROOM = 'DNS Queries'


def check_for_alias(alias):
    global DNS_BASE, DOMAIN, CNR_HEADERS

    url = DNS_BASE + 'CCMRRSet' + '/{}'.format(alias)

    response = requests.request(
        'GET', url, params={'zoneOrigin': DOMAIN}, headers=CNR_HEADERS, verify=False)
    if response.status_code == 404:
        return None

    res = {}
    j = response.json()

    hostname = ''

    for rr in j['rrs']['stringItem']:
        m = re.search(r'^IN CNAME (.+)', rr)
        if m:
            hostname = m.group(1)
            break

    res['hostname'] = hostname

    return res


def create_alias(hostname, alias):
    global DNS_BASE, DOMAIN, CNR_HEADERS

    url = DNS_BASE + 'CCMRRSet' + '/{}'.format(alias)

    if re.search(r'\.', hostname) and not hostname.endswith('.'):
        hostname += '.'

    if not hostname.endswith('.'):
        hostname += '.' + DOMAIN + '.'

    rr_obj = {
        'name': alias,
        'zoneOrigin': DOMAIN,
        'rrs': {
            'stringItem': [
                'IN CNAME {}'.format(hostname)
            ]
        }
    }

    response = requests.request(
        'PUT', url, headers=CNR_HEADERS, json=rr_obj, verify=False)
    response.raise_for_status()


def delete_alias(alias):
    global DNS_BASE, DOMAIN, CNR_HEADERS

    url = DNS_BASE + 'CCMRRSet' + '/{}'.format(alias)

    response = requests.request('DELETE', url, params={
                                'zoneOrigin': DOMAIN}, headers=CNR_HEADERS, verify=False)
    response.raise_for_status()


def delete_record(hostname):
    global DNS_BASE, DOMAIN, CNR_HEADERS

    url = DNS_BASE + 'CCMHost' + '/{}'.format(hostname)

    response = requests.request('DELETE', url, params={
                                'zoneOrigin': DOMAIN}, headers=CNR_HEADERS, verify=False)
    response.raise_for_status()


def check_for_record(hostname):
    global DNS_BASE, DOMAIN, CNR_HEADERS

    url = DNS_BASE + 'CCMHost' + '/{}'.format(hostname)

    response = requests.request(
        'GET', url, params={'zoneOrigin': DOMAIN}, headers=CNR_HEADERS, verify=False)
    if response.status_code == 404:
        return None

    res = {}
    j = response.json()

    res['ip'] = j['addrs']['stringItem'][0]

    return res


def create_record(hostname, ip, aliases):
    global DNS_BASE, DOMAIN, CNR_HEADERS

    url = DNS_BASE + 'CCMHost' + '/{}'.format(hostname)
    host_obj = {
        'addrs': {
            'stringItem': [
                ip
            ]
        },
        'name': hostname,
        'zoneOrigin': DOMAIN
    }

    if aliases is not None:
        aliases = re.sub(r'\s+', '', aliases)
        alist = aliases.split(',')

        alist = [x + '.' + DOMAIN +
                 '.' if not x.endswith('.') else x for x in alist]
        host_obj['aliases'] = {
            'stringItem': alist
        }

    response = requests.request(
        'PUT', url, headers=CNR_HEADERS, json=host_obj, verify=False)
    response.raise_for_status()


if __name__ == '__main__':
    print('Content-type: application/json\r\n\r\n')

    output = sys.stdin.read()

    j = json.loads(output)

    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s : %(message)s',
                        filename='/var/log/dns-hook.log', level=logging.DEBUG)
    logging.debug(json.dumps(j, indent=4))

    message_from = j['data']['personEmail']

    if message_from == 'livenocbot@sparkbot.io':
        logging.debug('Person email is our bot')
        print('{"result":"success"}')
        sys.exit(0)

    tid = spark.get_team_id(SPARK_TEAM)
    if tid is None:
        logging.error('Failed to get Spark Team ID')
        print('{"result":"fail"}')
        sys.exit(0)

    rid = spark.get_room_id(tid, SPARK_ROOM)
    if rid is None:
        logging.error('Failed to get Spark Room ID')
        print('{"result":"fail"}')
        sys.exit(0)

    if rid != j['data']['roomId']:
        logging.error('Spark Room ID is not the same as in the message ({} vs. {})'.format(
            rid, j['data']['roomId']))
        print('{"result":"fail"}')
        sys.exit(0)

    mid = j['data']['id']

    msg = spark.get_message(mid)
    if msg is None:
        logging.error('Did not get a message')
        print('{"result":"error"}')
        sys.exit(0)

    txt = msg['text']
    found_hit = False

    if re.search(r'\bhelp\b', txt, re.I):
        spark.post_to_spark(
            SPARK_TEAM, SPARK_ROOM, 'To create a new DNS entry, tell me things like, `Create record for HOST with IP and alias ALIAS`, `Create entry for HOST with IP`, `Add a DNS record for HOST with IP`')
        found_hit = True

    try:
        m = re.search(
            r'(remove|delete)\s+.*?(alias|cname)\s+([\w\-\.]+)', txt, re.I)

        if not found_hit and m:
            found_hit = True
            if message_from not in ALLOWED_TO_CREATE:
                spark.post_to_spark(
                    SPARK_TEAM, SPARK_ROOM, 'I\'m sorry, {}.  I can\'t do that for you.'.format(message_from))
            else:
                res = check_for_alias(m.group(3))
                if res is None:
                    spark.post_to_spark(
                        SPARK_TEAM, SPARK_ROOM, 'I didn\'t find an alias {}'.format(m.group(3)))
                else:
                    try:
                        delete_alias(m.group(3))
                        spark.post_to_spark(
                            SPARK_TEAM, SPARK_ROOM, 'Alias {} deleted successfully.'.format(m.group(3)))
                    except Exception as e:
                        spark.post_to_spark(
                            SPARK_TEAM, SPARK_ROOM, 'Failed to delete alias {}: {}'.format(m.group(3), e))

        m = re.search(
            r'(remove|delete)\s+.*?for\s+([\w\-\.]+)', txt, re.I)

        if not found_hit and m:
            found_hit = True
            if message_from not in ALLOWED_TO_CREATE:
                spark.post_to_spark(
                    SPARK_TEAM, SPARK_ROOM, 'I\'m sorry, {}.  I can\'t do that for you.'.format(message_from))
            else:
                res = check_for_record(m.group(2))
                if res is None:
                    spark.post_to_spark(
                        SPARK_TEAM, SPARK_ROOM, 'I didn\'t find a DNS record for {}.'.format(m.group(2)))
                else:
                    try:
                        delete_record(m.group(2))
                        spark.post_to_spark(
                            SPARK_TEAM, SPARK_ROOM, 'DNS record for {} deleted successfully.'.format(m.group(2)))
                    except Exception as e:
                        spark.post_to_spark(
                            SPARK_TEAM, SPARK_ROOM, 'Failed to delete DNS record for {}: {}'.format(m.group(2), e))

        m = re.search(
            r'(make|create|add)\s+.*?for\s+([\w\-\.]+)\s+.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(\s+.*?(alias(es)?|cname(s)?)\s+([\w\-\.]+(\s*,\s*[\w\-\.,\s]+)?))?', txt, re.I)
        if not found_hit and m:
            found_hit = True
            if message_from not in ALLOWED_TO_CREATE:
                spark.post_to_spark(
                    SPARK_TEAM, SPARK_ROOM, 'I\'m sorry, {}.  I can\'t do that for you.'.format(message_from))
            else:
                res = check_for_record(m.group(2))
                if res is not None:
                    spark.post_to_spark(
                        SPARK_TEAM, SPARK_ROOM, '_{}_ is already in DNS as **{}**'.format(m.group(2), res['ip']))
                else:
                    hostname = re.sub(r'\.{}'.format(DOMAIN), '', m.group(2))
                    try:
                        create_record(m.group(2), m.group(3), m.group(8))
                        spark.post_to_spark(
                            SPARK_TEAM, SPARK_ROOM, 'Successfully created record for {}.'.format(m.group(2)))
                    except Exception as e:
                        spark.post_to_spark(
                            SPARK_TEAM, SPARK_ROOM, 'Failed to create record for {}: {}'.format(m.group(2), e))

        m = re.search(
            r'(make|create|add)\s+(alias(es)?|cname(s)?)\s+([\w\-\.]+(\s*,\s*[\w\-\.,\s]+)?)\s+(for|to)\s+([\w\-\.]+)', txt, re.I)
        if not found_hit and m:
            found_hit = True
            if message_from not in ALLOWED_TO_CREATE:
                spark.post_to_spark(
                    SPARK_TEAM, SPARK_ROOM, 'I\'m sorry, {}.  I can\'t do that for you.'.format(message_from))
            else:
                aliases = m.group(5)
                aliases = re.sub(r'\s+', '', aliases)
                alist = aliases.split(',')
                already_exists = False
                for alias in alist:
                    res = check_for_alias(alias)
                    if res is not None:
                        already_exists = True
                        spark.post_to_spark(
                            SPARK_TEAM, SPARK_ROOM, '_{}_ is already an alias for **{}**'.format(alias, res['hostname']))
                    res = check_for_record(alias)
                    if res is not None:
                        already_exists = True
                        spark.post_to_spark(
                            SPARK_TEAM, SPARK_ROOM, '_{}_ is already a hostname with IP **{}**'.format(alias, res['ip']))

                if not already_exists:
                    success = True
                    for alias in alist:
                        try:
                            create_alias(m.group(8), alias)
                        except Exception as e:
                            spark.post_to_spark(
                                SPARK_TEAM, SPARK_ROOM, 'Failed to create alias {}: {}'.format(alias, e))
                            success = False

                    if success:
                        spark.post_to_spark(
                            SPARK_TEAM, SPARK_ROOM, 'Successfully created alias(es) {} for {}'.format(aliases, m.group(8)))

        if not found_hit:
            spark.post_to_spark(SPARK_TEAM, SPARK_ROOM,
                                'Sorry, I didn\'t get that.  Please ask me to create or delete a DNS entry; or just ask for "help".')
    except Exception as e:
        logging.error('Error in obtaining data: {}'.format(
            traceback.format_exc()))
        spark.post_to_spark(SPARK_TEAM, SPARK_ROOM,
                            'Whoops, I encountered an error:<br>\n```\n{}\n```'.format(traceback.format_exc()))

    print('{"result":"success"}')
