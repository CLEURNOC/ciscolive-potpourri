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


import dns
import dns.resolver
from sparker import Sparker
import os
from subprocess import Popen, PIPE
import shlex
import json

SPARK_ROOM = 'Core Alarms'
SPARK_TEAM = 'CL17-Infra_team'
CACHE_FILE = '/home/jclarke/dns_cache.dat'


def report_error(server, obj):
    global SPARK_ROOM, SPARK_TEAM
    spark = Sparker()

    msg = 'DNS failure to {}\n\n'
    msg += '```\n'
    msg += '{}\n'
    msg += '```'

    res = spark.post_to_spark(SPARK_TEAM, SPARK_ROOM, msg.format(server, obj))
    if not res:
        print('Error posting to Spark!')


def report_good(msg):
    global SPARK_ROOM, SPARK_TEAM
    spark = Sparker()

    res = spark.post_to_spark(SPARK_TEAM, SPARK_ROOM, msg)
    if not res:
        print('Error posting to Spark!')


dns_servers = ['10.100.253.6', '10.100.253.106']
rdns = '2a01:4f8:120:7261:216:3eff:fe44:2015'

curr_state = {}

prev_state = {}
if os.path.exists(CACHE_FILE):
    fd = open(CACHE_FILE, 'r')
    prev_state = json.load(fd)
    fd.close()

res = os.system('/usr/local/sbin/fping6 -q -r0 {}'.format(rdns))
if res != 0:
    if rdns in prev_state and prev_state[rdns]:
        proc = Popen(shlex.split(
            '/usr/sbin/traceroute6 -q 1 -n -m 30 {}'.format(rdns)), stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate()
        report_error(
            rdns, 'Remote DNS server is not pingable; current traceroute:\n{}'.format(out))
    curr_state[rdns] = False
else:
    curr_state[rdns] = True
    if rdns in prev_state and not prev_state[rdns]:
        proc = Popen(shlex.split(
            '/usr/sbin/traceroute6 -q 1 -n -m 30 {}'.format(rdns)), stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate()
        report_good('{} is pingable again; current traceroute:\n```\n{}\n```'.format(rdns, out))


for ds in dns_servers:
    resolv = dns.resolver.Resolver()
    resolv.timeout = 2
    resolv.lifetime = 2
    resolv.nameservers = [ds]

    try:
        ans = resolv.query('ciscolive-test.local', 'AAAA')
        if ans.response.rcode() != dns.rcode.NOERROR:
            curr_state[ds] = False
            if ds in prev_state and prev_state[ds]:
                report_error(ds, ans.response)
        else:
            curr_state[ds] = True
            if ds in prev_state and not prev_state[ds]:
                report_good('{} is now resolving fine'.format(ds, ds))
    except Exception as e:
        curr_state[ds] = False
        if ds in prev_state and prev_state[ds]:
            report_error(ds, e)

fd = open(CACHE_FILE, 'w')
json.dump(curr_state, fd, indent=4)
fd.close()
