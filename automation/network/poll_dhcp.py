#!/usr/bin/env python
#
# Copyright (c) 2017-2023  Joe Clarke <jclarke@cisco.com>
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

import os
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

CACHE_FILE = "/home/jclarke/dhcp_metrics.dat"
CACHE_FILE_TMP = CACHE_FILE + ".tmp"

CNR_HEADERS = {"Accept": "application/json"}
CNR_AUTH = (CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD)


def get_metrics():
    global CNR_HEADERS, CNR_AUTH

    res = []

    for server in C.CDNS_SERVERS:
        url = "https://{}:8443/web-services/rest/stats/DHCPServer".format(server)

        try:
            response = requests.request(
                "GET", url, params={"nrClass": "DHCPServerActivityStats"}, auth=CNR_AUTH, headers=CNR_HEADERS, verify=False
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to get stats {e}")
            continue

        j = response.json()
        for key in j.keys():
            if type(j[key]) is not dict:
                res.append('{}{{server="{}"}} {}'.format(key, server, j[key]))

    return res


if __name__ == "__main__":
    response = get_metrics()

    with open(CACHE_FILE_TMP, "w") as fd:
        json.dump(response, fd, indent=4)

    os.rename(CACHE_FILE_TMP, CACHE_FILE)
