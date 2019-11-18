#!/usr/local/bin/python
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
import netsnmp
import syslog
import re
import CLEUCreds

MSG = 'Needs investigation: {} (SN: {}) {}'

if __name__ == '__main__':
    syslog.openlog(facility=syslog.LOG_LOCAL3)

    vars = netsnmp.VarList(netsnmp.Varbind(
        'entPhysicalClass'), netsnmp.Varbind('entPhysicalSerialNum'))

    chassis_index = -1
    csn = ''

    netsnmp.snmpwalk(vars,
                     Version=3,
                     DestHost=os.environ['OBSERVIUM_DEVICE_HOSTNAME'],
                     SecLevel='authPriv',
                     SecName='CLEUR',
                     AuthProto='SHA',
                     AuthPass=CLEUCreds.SNMP_AUTH_PASS,
                     PrivProto='DES',
                     PrivPass=CLEUCreds.SNMP_PRIV_PASS)

    for var in vars:
        if chassis_index == -1:
            if var.tag == 'entPhysicalClass':
                if int(var.val) == 3:
                    chassis_index = int(var.iid)
        elif var.tag == 'entPhysicalSerialNum':
            if int(var.iid) == chassis_index:
                csn = var.val

    msg = MSG.format(os.environ['OBSERVIUM_DEVICE_HOSTNAME'],
                     csn, os.environ['OBSERVIUM_ALERT_MESSAGE'])

    syslog.syslog(syslog.LOG_ERR, msg)
