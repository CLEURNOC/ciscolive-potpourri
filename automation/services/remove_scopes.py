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
from subprocess import Popen, PIPE
import re
import shlex
import os

DHCP_SERVER = '10.100.253.9'

if __name__ == '__main__':
    match = None
    ans = None
    if len(sys.argv) == 2:
        match = sys.argv[1]
        ans = raw_input(
            'Really delete all scopes that match "{}" (y/N): '.format(match))
    else:
        ans = raw_input('Really delete all scopes (y/N): ')

    if not re.search(r'^[yY]', ans):
        print('Exiting...')
        sys.exit(0)

    proc = Popen(shlex.split(
        'ssh -2 root@{} /root/nrcmd.sh -r scope listnames'.format(DHCP_SERVER)), stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    if not re.search(r'^100', out):
        print('Query for scopes failed: "{}"'.format(out))
        sys.exit(1)
    scopes = out.split('\n')
    for scope in scopes:
        if scope != '100 Ok' and re.search(r'^\w', scope):
            scope = scope.strip()
            delete = True
            if match is not None and not re.search(match, scope):
                delete = False
            if delete:
                print('Deleting scope {}'.format(scope))
                proc = Popen(shlex.split(
                    'ssh -2 root@{} /root/nrcmd.sh -r scope {} delete'.format(DHCP_SERVER, scope)), stdout=PIPE, stderr=PIPE)
                if not re.search(r'^100', out):
                    print('ERROR: Deleting scope {} failed: {}'.format(scope, out))
            else:
                print('Skipping scope {} as it did not match "{}"'.format(scope, match))
