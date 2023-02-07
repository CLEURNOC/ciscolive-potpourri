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

from __future__ import print_function
import sys
import json
from sparker import MessageType  # type: ignore
import requests
import html
import re
import os
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import logging
from cleu.config import Config as C  # type: ignore

DNAC_WEBHOOK = "https://webexapis.com/v1/webhooks/incoming/Y2lzY29zcGFyazovL3VzL1dFQkhPT0svZjAxZDhmNmUtODM3OS00Mzg3LWI4MDUtNzI0YzNjYzEyMzU2"

HEADERS = {"Content-Type": "application/json"}

if __name__ == "__main__":
    print("Content-type: application/json\r\n\r\n")

    output = sys.stdin.read()

    j = json.loads(output)

    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s : %(message)s", filename="/var/log/dnac-hook.log", level=logging.DEBUG
    )
    logging.debug(json.dumps(j, indent=4))

    # seen_issues[det["issueId"]] = det["issueMessage"]
    if "Assurance Issue Status" not in j["details"]:
        print("{}")
        exit(0)

    mt = MessageType(MessageType.WARNING)
    verb = "has an"
    if j["details"]["Assurance Issue Status"] != "active":
        mt = MessageType(MessageType.GOOD)
        verb = "no longer has an"
    elif j["details"]["Assurance Issue Priority"] == "P1":
        mt = MessageType(MessageType.BAD)

    link = j["ciscoDnaEventLink"]
    link = html.unescape(link)

    link = re.sub(r"\<DNAC_IP_ADDRESS\>", os.environ["REMOTE_ADDR"], link)

    message = (
        f'{mt.value} Device **{j["details"]["Device"]}** {verb} <a href="{link}">issue</a> : {j["details"]["Assurance Issue Details"]}'
    )

    print(requests.post(DNAC_WEBHOOK, headers=HEADERS, json={"markdown": message}))
