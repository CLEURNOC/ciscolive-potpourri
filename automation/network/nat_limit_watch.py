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

from __future__ import print_function
from future import standard_library

standard_library.install_aliases()
import paramiko
import os
from sparker import Sparker, MessageType
import time
from subprocess import Popen, PIPE, call
import shlex
import re
import json
import argparse
import CLEUCreds
import shutil
from cleu.config import Config as C

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
        fd = open(CACHE_FILE, "r")
        prev_state = json.load(fd)
        fd.close()

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    routers = ["CORE1-EDGE", "CORE2-EDGE"]

    for router in routers.items():
        try:
            ssh_client.connect(
                router, username=CLEUCreds.NET_USER, password=CLEUCreds.NET_PASS, timeout=60, allow_agent=False, look_for_keys=False,
            )
            chan = ssh_client.invoke_shell()
            try:
                send_command(chan, "term length 0")
                send_command(chan, "term width 0")
            except:
                pass
            output = ""
            try:
                output = send_command(chan, "show ip nat limit all-host | inc [0-9] +[1-9][0-9]+[^0-9]+$")
            except Exception as ie:
                print("Failed to get NAT limit from {}: {}".format(router, ie))
                continue

            for line in output.split("\n"):
                m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+(\d+)", line)
                if m:
                    host = m.group(1)
                    misses = m.group(2)
                    if (host in prev_state and prev_state[host] < int(misses)) or host not in prev_state:
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
            print("Failed to get NAT limits from {}: {}".format(router, e))
            continue

        ssh_client.close()

    fd = open(CACHE_FILE, "w")
    json.dump(curr_state, fd, indent=4)
    fd.close()
