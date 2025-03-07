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

from __future__ import print_function

import paramiko
import os
from sparker import Sparker, MessageType  # type: ignore
import time
import re
import json
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

SPARK_ROOM = "Core Alarms"

CACHE_FILE = "/home/jclarke/nat_limit.dat"


def send_command(chan, command):
    chan.sendall(command + "\n")
    time.sleep(0.5)
    output = ""
    i = 0
    while i < 60:
        r = chan.recv(65535)
        if len(r) == 0:
            raise EOFError("Remote host has closed the connection")
        r = r.decode("utf-8", "ignore")
        output += r
        if re.search(r"[#>]$", r.strip()):
            break
        time.sleep(1)

    return output


if __name__ == "__main__":
    prev_state = {}
    curr_state = {}

    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as fd:
            prev_state = json.load(fd)

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    routers = ["CORE1-EDGE", "CORE2-EDGE", "CORE1-NAT64", "CORE2-NAT64"]

    for router in routers:
        try:
            ssh_client.connect(
                router,
                username=CLEUCreds.NET_USER,
                password=CLEUCreds.NET_PASS,
                timeout=60,
                allow_agent=False,
                look_for_keys=False,
            )
            chan = ssh_client.invoke_shell()
            try:
                send_command(chan, "term length 0")
                send_command(chan, "term width 0")
            except Exception:
                pass
            output = ""
            try:
                output = send_command(chan, "show ip nat limit all-host | inc [0-9] +[1-9][0-9]+[^0-9]+$")
            except Exception as ie:
                print(f"Failed to get NAT limit from {router}: {ie}")
                continue

            for line in output.split("\n"):
                m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+(\d+)", line)
                if m:
                    host = m.group(1)
                    misses = m.group(2)
                    if host not in prev_state:
                        spark.post_to_spark(
                            C.WEBEX_TEAM,
                            SPARK_ROOM,
                            "Host **{}** has exceeded its NAT connection limit **{}** times".format(host, misses),
                            MessageType.BAD,
                        )

                    curr_state[host] = int(misses)

            for host, misses in list(prev_state.items()):
                if host not in curr_state:
                    spark.post_to_spark(
                        C.WEBEX_TEAM, SPARK_ROOM, "Host **{}** has aged out of the NAT limit exceeded table".format(host), MessageType.GOOD
                    )
        except Exception as e:
            ssh_client.close()
            print(f"Failed to get NAT limits from {router}: {e}")
            continue

        ssh_client.close()

    with open(CACHE_FILE, "w") as fd:
        json.dump(curr_state, fd, indent=4)
