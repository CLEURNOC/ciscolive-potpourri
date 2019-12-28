#!/usr/bin/python
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

from pyad import *
import sys
import re
import sparker
import CLEUCreds
import time
from cleu.config import Config as C

DEFAULT_GROUP = 'CL NOC Users'

if __name__ == '__main__':
    spark = sparker.Sparker(token=CLEUCreds.SPARK_TOKEN)
    members = spark.get_members(C.WEBEX_TEAM)
    #pyad.set_defaults(ldap_server=AD_DC, username=AD_USERNAME, password=AD_PASSWORD, ssl=True)
    ou = adcontainer.ADContainer.from_dn(C.AD_DN_BASE)
    if members is not None:
        for member in members:
            m = re.search(r'([^@]+)@cisco.com$', member['personEmail'])
            if m:
                names = member['personDisplayName'].split(' ')
                fullname = names[0] + ' ' + names[-1]
                try:
                    ad_user = aduser.ADUser.from_dn('cn={}, {}'.format(
                        fullname, AD_DN_BASE))
                    if ad_user is not None:
                        sys.stderr.write(
                            'Not creating {} ({}) as they already exist.\n'.format(m.group(1), fullname))
                        continue
                except Exception:
                    pass
                try:
                    new_user = aduser.ADUser.create(
                        fullname, ou, password=CLEUCreds.DEFAULT_USER_PASSWORD)
                except Exception as e:
                    sys.stderr.write(
                        "Failed to create user {}: {}\n".format(m.group(1), e))
                    continue
                new_user.update_attribute('mail', member['personEmail'])
                try:
                    new_user.update_attribute('sAMAccountName', m.group(1))
                    new_user.update_attribute(
                        'userPrincipalName', '{}@{}'.format(m.group(1), C.AD_DOMAIN))
                except Exception:
                    try:
                        new_user.delete()
                        sys.stderr.write(
                            'Error adding user {} (maybe duplicate?)\n'.format(m.group(1)))
                        continue
                    except:
                        pass

                try:
                    new_user.force_pwd_change_on_login()
                except Exception as e:
                    sys.stderr.write(
                        'Error setting password policy for user {}: {}'.format(m.group(1), e))
                def_group = adgroup.ADGroup.from_cn(DEFAULT_GROUP)
                def_group.add_members([new_user])
                print('Added user {}'.format(m.group(1)))
                time.sleep(1)
    else:
        sys.stderr.write(
            'Unable to get members from Webex Teams.\nMake sure the bot is part of the Webex team.\n')
