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
sys.path.append('/home/jclarke')
from sparker import Sparker
import CLEUCreds
import re

SPARK_TEAM = 'CL19 NOC Team'
SPARK_ROOM = 'Err Disable Alarms'

if __name__ == '__main__':
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    while True:
        output = ''
        for line in sys.stdin.readline():
            output += line

        host, msghdr, msg = output.split('~')
        hname = msghdr.replace(': ', '')
        hpart = ''
        if hname != '' and hname != 'GMT':
            hpart = '({}) '.format(hname)


        m = re.search(r': ([^,]+), putting ([^\s]+) in err-disable state', msg)
        if m:
            spark.post_to_spark(
                SPARK_TEAM, SPARK_ROOM, 'Port **{}** on **{}** **{}**has been put in an err-disable state because {}'.format(m.group(2), host, hpart, m.group(1)))
        else:
            m = re.search(
                r'recover from .+? err-disable state on (\S+)', msg)
            if m:
                spark.post_to_spark(
                    SPARK_TEAM, SPARK_ROOM, 'Port **{}** on **{}** **{}**is recovering from err-disable'.format(m.group(1), host, hpart))
