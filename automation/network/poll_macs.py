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


import os
import re
import sys
import time
import json
import paramiko
import CLEUCreds


CACHE_FILE = '/home/jclarke/mac_counts.dat'
CACHE_FILE_TMP = CACHE_FILE + '.tmp'

commands = [
  {
    'command': 'show mac address-table count | inc Dynamic Address Count',
    'pattern': r'Dynamic Address Count:\s+(\d+)',
    'metric': 'totalMacs',
    'devices': ['core1-l3c', 'core2-l3c']
  },
  {
    'command': 'show mac address-table dynamic | inc Total',
    'pattern': r'Total.*: (\d+)',
    'metric': 'totalMacs',
    'devicePatterns': [
      {
        'pattern': '10.127.0.{}',
        'range': {
          'min': 1,
          'max': 60
        }
      }
    ]
  },
  {
    'command': 'show ip arp summary | inc IP ARP',
    'pattern': r'(\d+) IP ARP entries',
    'metric': 'arpEntries',
    'devicePatterns': [
      {
        'pattern': '10.127.0.{}',
        'range': {
          'min': 1,
          'max': 60
        }
      }
    ]
  }
]


def get_results(ssh_client, ip, command, pattern, metric):
    response = ''
    try:
        ssh_client.connect(ip, username=CLEUCreds.NET_USER, password=CLEUCreds.NET_PASS,
                           timeout=5, allow_agent=False, look_for_keys=False)
        chan = ssh_client.invoke_shell()
        output = ''
        try:
            chan.sendall('term length 0\n')
            chan.sendall('term width 0\n')
            chan.sendall('{}\n'.format(command))
            j = 0
            while j < 10:
                if chan.recv_ready():
                    break
                time.sleep(.5)
                j += 1
            while chan.recv_ready():
                output += chan.recv(65535)
        except Exception as ie:
            response = '{}{{idf="{}"}}'.format(metric, ip)
            sys.stderr.write(
                'Failed to get MACs from {}: {}\n'.format(ip, ie))
            return response

        m = re.search(pattern, output)
        if m:
            response = '{}{{idf="{}"}} {}'.format(metric, ip, m.group(1))
        else:
            response = '{}{{idf="{}"}} 0'.format(metric, ip)
    except Exception as e:
        ssh_client.close()
        sys.stderr.write('Failed to connect to {}: {}\n'.format(ip, e))
        return ''

    ssh_client.close()

    return response


def get_metrics():

    response = []

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for command in commands:
        if 'devices' in command:
            for device in command['devices']:
                response.append(get_results(ssh_client, device, command['command'], command['pattern'], command['metric']))
        else:
            for pattern in command['devicePatterns']:
                if 'range' in pattern:
                    for i in range(pattern['range']['min'], pattern['range']['max']):
                        response.append(get_results(ssh_client, pattern['pattern'].format(str(i)), command[
                                        'command'], command['pattern'], command['metric']))
                else:
                    for sub in pattern['subs']:
                        response.append(get_results(ssh_client, pattern['pattern'].format(sub), command[
                                        'command'], command['pattern'], command['metric']))

    return response

if __name__ == '__main__':
    response=get_metrics()

    fd=open(CACHE_FILE_TMP, 'w')
    json.dump(response, fd, indent=4)
    fd.close()

    os.rename(CACHE_FILE_TMP, CACHE_FILE)
