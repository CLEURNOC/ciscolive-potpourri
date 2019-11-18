#!/usr/local/bin/python3.6
# -*- coding: utf-8 -*-
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
import os
from subprocess import Popen, PIPE
import shlex

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: {} <TEAM NAME>'.format(sys.argv[0]))
        sys.exit(1)

    msg = '_<a href="https://cl-monitoring.ciscolive.network:8080">Observium</a> on cl-monitoring_<br><br>**Notification Type:** {}<br><br>**Element:** {}<br>**Host:** {}<br>**State:** {}<br><br>**Date/Time:** {}<br>'.format(
        os.environ['OBSERVIUM_ALERT_STATE'], os.environ['OBSERVIUM_ENTITY_LINK'], os.environ['OBSERVIUM_DEVICE_LINK'], os.environ['OBSERVIUM_TITLE'], os.environ['OBSERVIUM_ALERT_TIMESTAMP'], os.environ['OBSERVIUM_ALERT_TIMESTAMP'])
    proc = Popen(shlex.split('/usr/local/bin/notify-by-spark.py -r {}'.format(
        sys.argv[1])), stdin=PIPE, stdout=PIPE, stderr=PIPE)
    out, err = proc.stdin.write(msg)
    proc.communicate()
    proc.stdin.close()

    print(out)
    print(err)
