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


import dns
import dns.resolver
from sparker import Sparker  # type: ignore
import os
import json
from cleu.config import Config as C  # type: ignore

SPARK_ROOM = "DNS Alarms"
CACHE_FILE = "/home/jclarke/dns_cache.dat"


def report_error(server, addr, q, obj):
    global SPARK_ROOM
    spark = Sparker()

    msg = "DNS failure to {} for {} query for {}\n\n"
    msg += "```\n"
    msg += "{}\n"
    msg += "```"

    res = spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, msg.format(server, q, addr, obj))
    if not res:
        print("Error posting to Spark!")


def report_good(msg):
    global SPARK_ROOM
    spark = Sparker()

    res = spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, msg)
    if not res:
        print("Error posting to Spark!")


dns_servers = [
    "10.100.253.6",
    "10.100.254.6",
    "2a11:d940:2:64fd::6",
    "2a11:d940:2:64fe::6",
]

dns64_servers = [
    "10.100.253.64",
    "10.100.254.64",
    "2a11:d940:2:64fd::100",
    "2a11:d940:2:64fe::100",
]

targets = ["cl-freebsd.ciscolive.network", "google.com"]
dns64_targets = ["github.com", "slack.com"]


curr_state = {}

prev_state = {}
if os.path.exists(CACHE_FILE):
    fd = open(CACHE_FILE, "r")
    prev_state = json.load(fd)
    fd.close()


for ds in dns_servers + dns64_servers:
    resolv = dns.resolver.Resolver()
    resolv.timeout = 2
    resolv.lifetime = 2
    resolv.nameservers = [ds]

    curr_state[ds] = {}

    for addr in targets:
        curr_state[ds][addr] = {}
        try:
            for q in ("A", "AAAA"):
                ans = resolv.query(addr, q)
                if ans.response.rcode() != dns.rcode.NOERROR:
                    curr_state[ds][addr][q] = False
                    if ds in prev_state and addr in prev_state[ds] and q in prev_state[ds][addr] and prev_state[ds][addr][q]:
                        report_error(ds, addr, q, ans.response)
                else:
                    curr_state[ds][addr][q] = True
                    if ds in prev_state and addr in prev_state[ds] and q in prev_state[ds][addr] and not prev_state[ds][addr][q]:
                        report_good("{} is now resolving a {} record for {} correctly".format(ds, q, addr))
        except Exception as e:
            curr_state[ds][addr][q] = False
            if ds in prev_state and addr in prev_state[ds] and q in prev_state[ds][addr] and prev_state[ds][addr][q]:
                report_error(ds, e)

for ds in dns64_servers:
    resolv = dns.resolver.Resolver()
    resolv.timeout = 2
    resolv.lifetime = 2
    resolv.nameservers = [ds]

    for addr in dns64_targets:
        try:
            for q in "AAAA":
                ans = resolv.query(addr, q)
                if ans.response.rcode() != dns.rcode.NOERROR:
                    curr_state[ds][addr][q] = False
                    if ds in prev_state and addr in prev_state[ds] and q in prev_state[ds][addr] and prev_state[ds][addr][q]:
                        report_error(ds, addr, q, ans.response)
                else:
                    curr_state[ds][addr][q] = True
                    if ds in prev_state and addr in prev_state[ds] and q in prev_state[ds][addr] and not prev_state[ds][addr][q]:
                        report_good("{} is now resolving a {} record for {} correctly".format(ds, q, addr))
        except Exception as e:
            curr_state[ds][addr][q] = False
            if ds in prev_state and addr in prev_state[ds] and q in prev_state[ds][addr] and prev_state[ds][addr][q]:
                report_error(ds, e)

fd = open(CACHE_FILE, "w")
json.dump(curr_state, fd, indent=4)
fd.close()
