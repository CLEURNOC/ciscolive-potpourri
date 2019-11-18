#!/usr/bin/python
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


from pyad import *
import sys
import re
import time
import smtplib
import random
import string
from email.mime.text import MIMEText


AD_DN_BASE = 'cn=Users, dc=ad, dc=ciscolive, dc=network'
DEFAULT_GROUP = 'NOC Users'
AD_DOMAIN = 'ad.ciscolive.network'

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.stderr.write('usage: {} GROUP FILE\n'.format(sys.argv[0]))
        sys.exit(1)

    #pyad.set_defaults(ldap_server=AD_DC, username=AD_USERNAME, password=AD_PASSWORD, ssl=True)
    ou = adcontainer.ADContainer.from_dn(AD_DN_BASE)
    fd = open(sys.argv[2])
    contents = fd.readlines()
    fd.close()
    group = sys.argv[1]

    MSG = 'Created CLEU account for {}.\r\n\r\n'
    MSG += 'Login to the CL-NOC SSID and https://tool.ciscolive.network with the following:\r\n\r\n'
    MSG += 'Username: {}\r\n'
    MSG += 'Password: {}\r\n'

    SUBJECT = 'New CLEU network account'

    for line in contents:
        line = line.strip()
        name, email, username = line.split(',')
        try:
            ad_user = aduser.ADUser.from_dn('cn={}, {}'.format(
                name, AD_DN_BASE))
            if ad_user is not None:
                sys.stderr.write(
                    'Not creating {} as they already exist.\n'.format(username))
                continue
        except Exception:
            pass
        password = ''.join(random.choice(string.ascii_uppercase + string.digits +
                           string.ascii_lowercase + '@!%^#:*') for _ in range(8))
        try:
            new_user = aduser.ADUser.create(
                name, ou, password=password)
        except Exception as e:
            sys.stderr.write(
                "Failed to create user {}: {}\n".format(username, e))
            continue
        new_user.update_attribute('mail', email)
        try:
            new_user.update_attribute('sAMAccountName', username)
            new_user.update_attribute(
                'userPrincipalName', '{}@{}'.format(username, AD_DOMAIN))
        except Exception as e:
            new_user.delete()
            sys.stderr.write(
                'Error adding user {} (maybe duplicate?) ({})\n'.format(username, e))
            continue

        def_group = adgroup.ADGroup.from_cn(group)
        def_group.add_members([new_user])
        print('Added user {}'.format(username))
        msg = MIMEText(MSG.format(name, username, password))
        msg['Subject'] = SUBJECT
        msg['From'] = 'jclarke@cisco.com'
        msg['To'] = email
        msg['Bcc'] = ','.join(['jclarke@cisco.com'])

        sm = smtplib.SMTP('10.100.253.13')
        sm.sendmail('jclarke@cisco.com', [
                    email, 'jclarke@cisco.com'], msg.as_string())
        sm.quit()
        time.sleep(1)
