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

from sparker import Sparker, MessageType  # type: ignore
import CLEUCreds  # type: ignore
import re
import os
import json
import time
from cleu.config import Config as C  # type: ignore

SPARK_ROOM = "Err Disable Alarms"

CACHE_FILE = "/home/jclarke/err_disable_cache.json"


def make_tool_link(switch, port):
    return '<a href="{}switchname={}&portname={}">**{}**</a>'.format(
        C.TOOL_BASE,
        switch,
        port,
        port,
    )


if __name__ == "__main__":
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    curr_ports = {}

    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as fd:
            curr_ports = json.load(fd)

    while True:
        output = ""
        for line in sys.stdin.readline():
            output += line

        host, msghdr, msg = output.split("~")
        hname = msghdr.replace(": ", "")
        hpart = ""
        if hname != "" and hname != "GMT" and hname != "CET":
            hpart = "({})".format(hname)

        m = re.search(r": ([^,]+), putting ([^\s]+) in err-disable state", msg)
        if m:
            spark.post_to_spark(
                C.WEBEX_TEAM,
                SPARK_ROOM,
                "Port {} on **{}** **{}** has been put in an err-disable state because {}".format(
                    make_tool_link(host, m.group(2)), host, hpart, m.group(1)
                ),
                MessageType.WARNING,
            )

            curr_ports[f"{host}:{m.group(2)}"] = int(time.time() * 1000)
        else:
            m = re.search(r"recover from .+? err-disable state on (\S+)", msg)
            if m:
                if f"{host}:{m.group(1)}" in curr_ports:
                    # Only send an up if we haven't seen another down for 5 seconds.
                    if int(time.time() * 1000) - curr_ports[f"{host}:{m.group(1)}"] >= 5000:
                        spark.post_to_spark(
                            C.WEBEX_TEAM,
                            SPARK_ROOM,
                            "Port {} on **{}** **{}** is recovering from err-disable".format(make_tool_link(host, m.group(1)), host, hpart),
                            MessageType.GOOD,
                        )

                        del curr_ports[f"{host}:{m.group(1)}"]

        with open(CACHE_FILE, "w") as fd:
            json.dump(curr_ports, fd)
