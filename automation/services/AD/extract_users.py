#!/usr/bin/env python
#
# Copyright (c) 2017-2025  Joe Clarke <jclarke@cisco.com>
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

from __future__ import print_function
import sys
import re
import sparker  # type: ignore
import CLEUCreds  # type: ignore
import csv
from cleu.config import Config as C  # type: ignore

DEFAULT_GROUP = "CL NOC Users"

if __name__ == "__main__":
    spark = sparker.Sparker(token=CLEUCreds.SPARK_TOKEN)
    members = spark.get_members(C.WEBEX_TEAM)
    # pyad.set_defaults(ldap_server=AD_DC, username=AD_USERNAME, password=AD_PASSWORD, ssl=True)
    with open("users.csv", "w", newline="") as fd:
        user_writer = csv.writer(fd)
        user_writer.writerow(["Username", "First Name", "Last Name"])
        if members:
            for member in members:
                m = re.search(r"([^@]+)@cisco.com$", member["personEmail"])
                if m:
                    names = member["personDisplayName"].split(" ")
                    user_writer.writerow([m.group(1), names[0], names[-1]])
        else:
            sys.stderr.write("Unable to get members from Webex Teams.\nMake sure the bot is part of the Webex team.\n")
