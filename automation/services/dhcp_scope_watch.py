#!/usr/bin/env python2
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
from subprocess import Popen, PIPE
import re
import shlex
import requests
import os
from multiprocessing import Pool
import CLEUCreds

SPARK_TEAM = 'CL19 NOC Team'
SPARK_ROOM = 'DHCP Scope Alarms'

THRESHOLD = '75'
CACHE_FILE = '/home/jclarke/dhcp_scope.dat'
STATS_FILE = '/home/jclarke/dhcp_scope_stats.dat'

DHCP_SERVER = '10.100.253.9'


def parse_result(out):
    matches = re.findall(r'([\w-]+=[^;]+);(?=\s|$)', out)
    res = {}
    for m in matches:
        if m == '':
            continue
        k, v = m.split('=')
        res[k] = v
    return res


def get_results(scope):
    global DHCP_SERVER

    if scope != '100 Ok' and scope != '':
        proc = Popen(shlex.split(
            'ssh -2 root@{} /root/nrcmd.sh -r scope {} getUtilization'.format(DHCP_SERVER, scope)), stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate()
        if not re.search(r'^100', out):
            return None
        outd = parse_result(out)
        if 'active-dynamic' not in outd or 'total-dynamic' not in outd or 'free-dynamic' not in outd:
            return None

        util = (float(outd['active-dynamic']) /
                float(outd['total-dynamic'])) * 100.0
        #print('Util for {0} is {1:.2f}% utilized'.format(scope, util))

        return (scope, {'util': util, 'active-dynamic': outd['active-dynamic'], 'total-dynamic': outd['total-dynamic']})


def get_metrics(pool):
    global DHCP_SERVER

    response = {}

    proc = Popen(shlex.split(
        'ssh -2 root@{} /root/nrcmd.sh -r scope listnames'.format(DHCP_SERVER)), stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    if not re.search(r'^100', out):
        sys.exit(0)
    scopes = out.split('\n')

    results = [pool.apply_async(get_results, [s]) for s in scopes]
    for res in results:
        retval = res.get()
        if retval is not None:
            response[retval[0]] = retval[1]

    return response


if __name__ == '__main__':
    prev_state = {}
    curr_state = {}
    stats = {}

    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    if os.path.exists(CACHE_FILE):
        fd = open(CACHE_FILE, 'r')
        prev_state = json.load(fd)
        fd.close()

    pool = Pool(20)
    metrics = get_metrics(pool)

    for scope, stat in metrics.items():
        stats[scope] = {'perc': stat['util']}
        if stat['util'] >= float(THRESHOLD):
            curr_state[scope] = True
            if scope not in prev_state or (scope in prev_state and not prev_state[scope]):
                spark.post_to_spark(
                    SPARK_TEAM, SPARK_ROOM, '**WARNING**: Scope **{0}** is now **{1:.2f}%** utilized ({2} of {3} free addresses remain); suppressing future alerts until resolved'.format(scope, stat['util'], stat['free-dynamic'], stat['total-dynamic']))
        else:
            curr_state[scope] = False
            if scope in prev_state and prev_state[scope]:
                spark.post_to_spark(SPARK_TEAM, SPARK_ROOM, '_INFO_: Scope **{0}** is now only **{1:.2f}%** utilized ({2} free addresses out of {3})'.format(
                    scope, stat['util'], stat['free-dynamic'], stat['total-dynamic']))

    fd = open(CACHE_FILE, 'w')
    json.dump(curr_state, fd, indent=4)
    fd.close()

    fd = open(STATS_FILE, 'w')
    json.dump(stats, fd, indent=4)
    fd.close()
