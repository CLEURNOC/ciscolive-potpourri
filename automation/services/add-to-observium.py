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
import json
from subprocess import Popen, PIPE
import shlex
import CLEUCreds

MONITORING = 'cl-monitoring.ciscolive.network'
DEV_FILE = '/home/jclarke/ping-devs.json'

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: {} <DEV> [<DEV> [...]]'.format(sys.argv[0]))
        sys.exit(1)

    devs = []
    changed_devs = False
    try:
        fd = open(DEV_FILE, 'r')
        devs = json.load(fd)
        fd.close()
    except:
        pass

    for dev in sys.argv[1:]:
        if dev not in devs:
            devs.append(dev)
            changed_devs = True

            print('=== Adding device {} to Observium ==='.format(dev))
            proc = Popen(shlex.split(
                'ssh -2 {} /usr/local/www/observium/add_device.php {} ap v3 CLEUR {} {} sha des'.format(MONITORING, dev, CLEUCreds.SNMP_AUTH_PASS, CLEUCreds.SNMP_PRIV_PASS)), stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate()
            print(out)
            print(err)
            print('=== DONE. ===')

    if changed_devs:
        fd = open(DEV_FILE, 'w')
        json.dump(devs, fd)
        fd.close()
