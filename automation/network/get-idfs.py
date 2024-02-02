#!/usr/bin/env python
#
# Copyright (c) 2017-2024  Joe Clarke <jclarke@cisco.com>
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


import requests
import json
import re
from cleu.config import Config as C  # type: ignore

OUTPUT = "/home/jclarke/idf-devices.json"


def get_devs():
    url = "http://{}/get/switches/json".format(C.TOOL)

    devs = []
    response = requests.get(url)
    code = 200
    code = response.status_code
    if code == 200:
        j = response.json()

        for dev in j:
            if dev["IPAddress"] == "0.0.0.0" or not dev["Reachable"]:
                continue

            if not re.search(r"[xX]\d+-", dev["Hostname"]):
                continue

            devs.append(dev)

    return devs


if __name__ == "__main__":
    idfs = get_devs()
    with open(OUTPUT, "w") as fd:
        json.dump(idfs, indent=2)
