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

import netsnmp
import os
import json
from sparker import Sparker
import CLEUCreds

CACHE_FILE = '/home/jclarke/errors_cache.dat'
THRESHOLD = 1
WINDOW = 12
REARM = 6


SPARK_TEAM = 'CL19 NOC Team'
SPARK_ROOM = 'Data Center Alarms'

devices = ['dc1-fcsw-1', 'dc1-fcsw-2', 'dc2-fcsw-1', 'dc2-fcsw-2',
           'dc1-ethsw-1', 'dc1-ethsw-2', 'dc2-ethsw-1', 'dc2-ethsw-2']

ignore_interfaces = {}

prev_state = {}
curr_state = {}

if __name__ == '__main__':

    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    if os.path.exists(CACHE_FILE):
        fd = open(CACHE_FILE, 'r')
        prev_state = json.load(fd)
        fd.close()

    for device in devices:

        swent = {}

        vars = netsnmp.VarList(netsnmp.Varbind('ifDescr'), netsnmp.Varbind('ifInErrors'), netsnmp.Varbind(
            'ifOutErrors'), netsnmp.Varbind('ifInDiscards'), netsnmp.Varbind('ifOutDiscards'), netsnmp.Varbind('ifAlias'))
        netsnmp.snmpwalk(vars,
                         Version=3,
                         DestHost=device,
                         SecLevel='authPriv',
                         SecName='CLEUR',
                         AuthProto='SHA',
                         AuthPass=CLEUCreds.SNMP_AUTH_PASS,
                         PrivProto='DES',
                         PrivPass=CLEUCreds.SNMP_PRIV_PASS)
        for var in vars:
            if var.iid not in swent:
                swent[var.iid] = {}
                swent[var.iid]['count'] = 0
                swent[var.iid]['suppressed'] = False

            swent[var.iid][var.tag] = var.val

        curr_state[device] = swent
        if not device in prev_state:
            continue

        for ins, vard in curr_state[device].items():
            if not ins in prev_state[device]:
                continue
            if not 'ifDescr' in vard:
                continue
            if not 'ifAlias' in vard:
                vard['ifAlias'] = ''
            if 'count' in prev_state[device][ins]:
                curr_state[device][ins]['count'] = prev_state[device][ins]['count']

            if 'suppressed' in prev_state[device][ins]:
                curr_state[device][ins]['suppressed'] = prev_state[
                    device][ins]['suppressed']
            if_descr = vard['ifDescr']
            if_alias = vard['ifAlias']
            if device in ignore_interfaces and if_descr in ignore_interfaces[device]:
                continue
            found_error = False
            for k, v in vard.items():
                if k == 'ifDescr' or k == 'ifAlias' or k == 'count' or k == 'suppressed':
                    continue
                if k in prev_state[device][ins]:
                    diff = int(v) - int(prev_state[device][ins][k])
                    if diff >= THRESHOLD:
                        found_error = True
                        if curr_state[device][ins]['count'] < WINDOW and not curr_state[device][ins]['suppressed']:
                            spark.post_to_spark(
                                SPARK_TEAM, SPARK_ROOM, '**WARNING**: Interface **{}** ({}) on device _{}_ has seen an increase of **{}** {} since the last poll (previous: {}, current: {}).'.format(if_descr, if_alias, device, diff, k, prev_state[device][ins][k], v))
                        elif not curr_state[device][ins]['suppressed']:
                            curr_state[device][ins]['suppressed'] = True
                            spark.post_to_spark(
                                SPARK_TEAM, SPARK_ROOM, 'Suppressing alarms for interface **{}** ({}) on device _{}_'.format(if_descr, if_alias, device))
            if not found_error:
                if curr_state[device][ins]['count'] > 0:
                    curr_state[device][ins]['count'] -= 1
                    if curr_state[device][ins]['count'] < REARM and curr_state[device][ins]['suppressed']:
                        spark.post_to_spark(
                            SPARK_TEAM, SPARK_ROOM, 'Interface **{}** ({}) on device _{}_ is no longer seeing an increase of errors'.format(if_descr, if_alias, device))
                        curr_state[device][ins]['suppressed'] = False
            else:
                curr_state[device][ins]['count'] += 1

    fd = open(CACHE_FILE, 'w')
    json.dump(curr_state, fd, indent=4)
    fd.close()
