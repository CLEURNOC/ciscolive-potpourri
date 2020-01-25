#!//usr/bin/env python3
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

from __future__ import print_function
from builtins import input
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys
import re
from netaddr import IPAddress
import CLEUCreds
from cleu.config import Config as C

DHCP_BASE = C.DHCP_BASE + "Reservation"

HEADERS = {"authorization": CLEUCreds.JCLARKE_BASIC, "accept": "application/json", "content-type": "application/json"}

if __name__ == "__main__":
    url = DHCP_BASE
    ans = eval(input("Are you sure you want to clean reservations (y/N): "))
    if not re.search(r"^[yY]", ans):
        print("Exiting...")
        sys.exit(0)
    try:
        response = requests.request("GET", url, headers=HEADERS, verify=False)
        response.raise_for_status()
    except Exception as e:
        sys.stderr.write("Failed to get list of reservations: {}\n".format(e))
        sys.exit(1)

    reservations = response.json()
    for lease in reservations:
        url = "{}/{}".format(DHCP_BASE, lease["ipaddr"])
        try:
            response = requests.request("DELETE", url, headers=HEADERS, verify=False)
            response.raise_for_status()
        except Exception as e:
            sys.stderr.write("Error deleting reservation for {}: {}\n".format(lease["ipaddr"], e))
            continue

        print("Deleted reservation for {}.".format(lease["ipaddr"]))
