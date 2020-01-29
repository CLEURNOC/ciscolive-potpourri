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

import os
import re
import sys
import time
import json
import string
import random
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import CLEUCreds
from sparker import Sparker, MessageType
from cleu.config import Config as C

ROOM = "DNA Alarms"
CACHE_FILE = "/home/jclarke/dna_issues.json"


def get_identity_token():
    url = C.SDA_BASE + "/api/system/v1/identitymgmt/login"

    try:
        response = requests.request("GET", url, headers={"Authorization": CLEUCreds.JCLARKE_BASIC}, verify=False)
        response.raise_for_status()
    except Exception as e:
        print("ERROR: Failed to login to DNAC: {}".format(getattr(e, "message", repr(e))))
        return None

    jwt = response.headers.get("Set-Cookie")
    if jwt:
        m = re.search(r"X-JWT-ACCESS-TOKEN=([^;]+)", jwt)
        if m:
            return m.group(1)

    return None


def main():
    global ROOM, CACHE_FILE

    jwt = get_identity_token()
    if not jwt:
        print("No cookies")
        sys.exit(1)

    prev_state = {}
    cookies = {
        "X-JWT-ACCESS-TOKEN": jwt,
        "JSESSIONID": ("".join(random.choice(string.ascii_lowercase) for i in range(16))),
        "cisco-dna-core-shell-actionItemModal": "false",
    }
    try:
        with open(CACHE_FILE) as fd:
            prev_state = json.load(fd)
    except Exception as e:
        pass

    end_time = int(time.time() * 1000)
    if "start_time" not in prev_state:
        start_time = end_time - 86400000
    else:
        start_time = prev_state["start_time"]

    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    url = C.SDA_BASE + "/api/assurance/v1/issue/global-category?startTime={}&endTime={}&limit=10".format(start_time, end_time)

    payload = {"sortBy": {"priority": "ASC"}, "issueStatus": "active", "filters": {}}

    i = 0
    seen_groups = {}
    seen_issues = {}

    while True:
        try:
            response = requests.request(
                "POST",
                url + "&page={}".format(i),
                cookies=cookies,
                json=payload,
                headers={"content-type": "application/json", "accept": "application/json"},
                verify=False,
            )
            response.raise_for_status()
        except Exception as e:
            print("ERROR: Failed to get issue list from DNAC: {}".format(getattr(e, "message", repr(e))))
            break

        j = response.json()

        if "response" in j:
            for issue in j["response"]:
                if issue["groupName"] in seen_groups:
                    continue

                seen_groups[issue["groupName"]] = True

                iurl = C.SDA_BASE + "/api/assurance/v1/issue/category-detail?startTime={}&endTime={}&limit=25&page=0".format(
                    start_time, end_time
                )
                ipayload = {"groupName": issue["groupName"], "filters": {}, "issueStatus": "active"}

                try:
                    response = requests.request(
                        "POST",
                        iurl,
                        json=ipayload,
                        cookies=cookies,
                        headers={"content-type": "application/json", "accept": "application/json"},
                        verify=False,
                    )
                    response.raise_for_status()
                except Exception as e:
                    print("ERROR: Failed to fetch issue details for group {}: {}".format(j["groupName"], getattr(e, "message", repr(e))))
                    break

                details = response.json()

                for det in details["response"]:
                    seen_issues[det["issueId"]] = det["issueMessage"]
                    mt = MessageType.WARNING
                    if det["priority"] == "P1":
                        mt = MessageType.BAD
                    spark.post_to_spark(C.WEBEX_TEAM, ROOM, det["issueMessage"], mt)

        if not j["pagination"]["next"]:
            break

        i += 1

    if "issues" in prev_state:
        for issue in prev_state["issues"]:
            if issue not in seen_issues:
                spark.post_to_spark(C.WEBEX_TEAM, ROOM, prev_state["issues"][issue], MessageType.GOOD)

    prev_state["start_time"] = end_time
    prev_state["groups"] = seen_issues

    with open(CACHE_FILE, "w") as fd:
        json.dump(prev_state, fd, indent=4)


if __name__ == "__main__":
    main()
