#!/usr/bin/env python3
#
# Copyright (c) 2017-2020  Joe Clarke <jclarke@cisco.com>
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

from builtins import str
from builtins import range
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys
import CLEUCreds
from cleu.config import Config as C

IDF_CNT = 99
ADDITIONAL_IDFS = (252, 253, 254)

IDF_OVERRIDES = {
    252: {"first_ip": 160, "last_ip": "250"},
    253: {"first_ip": 160, "last_ip": "250"},
    254: {"first_ip": 160, "last_ip": "250"},
}

SCOPE_BASE = C.DHCP_BASE + "Scope"


HEADERS = {"authorization": CLEUCreds.JCLARKE_BASIC, "accept": "application/json", "content-type": "application/json"}

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.stderr.write("usage: {} VLAN <IDF|CORE> START\n".format(sys.argv[0]))
        sys.exit(1)

    vlan = sys.argv[1]
    type = sys.argv[2].upper()
    start = sys.argv[3]

    if type != "CORE" and type != "IDF":
        sys.stderr.write("usage: {} VLAN <IDF|CORE> START\n".format(sys.argv[0]))
        sys.exit(1)

    idf_set = ()

    istart = 1
    prefix = "IDF-" + str(istart).zfill(3)
    rs = 1
    cnt = IDF_CNT

    if type == "CORE":
        prefix = "CORE-"
        rs = 0
        cnt = 0

    first_scope_name = "{}-{}".format(prefix, vlan.upper())

    url = "{}/{}".format(SCOPE_BASE, first_scope_name)

    try:
        response = requests.request("GET", url, headers=HEADERS, verify=False)
        response.raise_for_status()
    except Exception as e:
        sys.stderr.write("Failed to get first scope details for {}: {}\n".format(first_scope_name, e))
        sys.exit(1)

    first_scope = response.json()
    end = first_scope["rangeList"]["RangeItem"][0]["end"].split(".")[3]
    subnet = ".".join(first_scope["subnet"].split(".")[0:2])

    policy = first_scope["policy"]
    embedded_policy = None
    if "embeddedPolicy" in first_scope:
        embedded_policy = first_scope["embeddedPolicy"]

    for i in range(rs, cnt + 1):
        idf_set += (i,)

    if type != "CORE":
        idf_set += ADDITIONAL_IDFS

    for i in idf_set:
        rstart = "{}.{}.{}".format(subnet, i, start)
        eoctet = i
        if type == "CORE":
            eoctet = 255

        if i in IDF_OVERRIDES:
            end = IDF_OVERRIDES[i]["last_ip"]

        rend = "{}.{}.{}".format(subnet, eoctet, end)

        prefix = "IDF-" + str(i).zfill(3)

        if embedded_policy is not None:
            embedded_policy = {"optionList": {"OptionItem": [{"number": "3", "value": "{}.{}.{}".format(subnet, eoctet, str(254))}]}}

        if type == "CORE":
            prefix = "CORE-"

        scope_name = "{}-{}".format(prefix, vlan.upper())

        url = "{}/{}".format(SCOPE_BASE, scope_name)

        try:
            # print('Changing {} to start: {}, end: {}'.format(
            #    scope_name, start, end))

            payload = {"rangeList": {"RangeItem": [{"start": rstart, "end": rend}]}, "policy": policy}
            if embedded_policy is not None:
                payload["embeddedPolicy"] = embedded_policy

            response = requests.request("PUT", url, json=payload, headers=HEADERS, verify=False)
            response.raise_for_status()
        except Exception as e:
            sys.stderr.write("Failed to update scope details for {}: {}\n".format(scope_name, e))
            continue
