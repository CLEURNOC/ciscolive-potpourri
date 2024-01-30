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

import sys
import json
from sparker import Sparker, MessageType  # type: ignore
from subprocess import Popen, PIPE
import re
import shlex
import os
from multiprocessing import Pool
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

SPARK_ROOM = "DHCP Scope Alarms"

THRESHOLD = "75"
CACHE_FILE = "/home/jclarke/dhcp_scope.dat"
STATS_FILE = "/home/jclarke/dhcp_scope_stats.dat"


def get_results(scope):
    global DHCP_SERVER

    scope = scope.strip()

    if scope != "100 Ok" and scope != "":
        url = f"https://{C.DHCP_SERVER}:8443/web-services/rest/stats/CurrentUtilization/{scope}"
        try:
            r = requests.get(
                url, auth=(CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD), headers={"Accept": "application/json"}, verify=False
            )
            r.raise_for_status()
        except Exception as e:
            sys.stderr.write(f"ERROR: Failed to query {scope}: {e}")
            return None

        outd = r.json()

        util = (float(outd["activeDynamic"]) / float(outd["totalDynamic"])) * 100.0
        # print('Util for {0} is {1:.2f}% utilized'.format(scope, util))

        return (
            scope,
            {
                "util": util,
                "free-dynamic": outd["freeDynamic"],
                "active-dynamic": outd["activeDynamic"],
                "total-dynamic": outd["totalDynamic"],
            },
        )


def get_metrics(pool):
    global DHCP_SERVER

    response = {}

    proc = Popen(shlex.split("ssh -2 root@{} /root/nrcmd.sh -r scope listnames".format(C.DHCP_SERVER)), stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    outs = out.decode("utf-8")
    errs = err.decode("utf-8")
    if not re.search(r"^100", outs):
        sys.stderr.write(f"Error getting scopes: {outs} {errs}\n")
        sys.exit(0)

    scopes = outs.split("\n")

    results = [pool.apply_async(get_results, [s]) for s in scopes[1:]]
    for res in results:
        retval = res.get()
        if retval is not None:
            response[retval[0]] = retval[1]

    return response


if __name__ == "__main__":
    prev_state = {}
    curr_state = {}
    stats = {}

    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as fd:
            prev_state = json.load(fd)

    pool = Pool(20)
    metrics = get_metrics(pool)

    for scope, stat in metrics.items():
        stats[scope] = {"perc": stat["util"]}
        if stat["util"] >= float(THRESHOLD):
            curr_state[scope] = stat["util"]
            if scope not in prev_state or (scope in prev_state and stat["util"] - prev_state[scope] >= 1.0):
                curr_state[scope] = stat["util"]
                spark.post_to_spark(
                    C.WEBEX_TEAM,
                    SPARK_ROOM,
                    "Scope **{0}** is now **{1:.2f}%** utilized ({2} of {3} free addresses remain); suppressing future alerts until resolved or utilization increases".format(
                        scope, stat["util"], stat["free-dynamic"], stat["total-dynamic"]
                    ),
                    MessageType.WARNING,
                )
        else:
            curr_state[scope] = False
            if scope in prev_state and prev_state[scope]:
                spark.post_to_spark(
                    C.WEBEX_TEAM,
                    SPARK_ROOM,
                    "Scope **{0}** is now only **{1:.2f}%** utilized ({2} free addresses out of {3})".format(
                        scope, stat["util"], stat["free-dynamic"], stat["total-dynamic"]
                    ),
                    MessageType.GOOD,
                )

    with open(CACHE_FILE, "w") as fd:
        json.dump(curr_state, fd, indent=4)

    with open(STATS_FILE, "w") as fd:
        json.dump(stats, fd, indent=4)
