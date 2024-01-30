#!/usr/bin/env python3
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

from __future__ import division
from past.utils import old_div  # type: ignore
import re
import sys
import time
import json
import paramiko
from sparker import Sparker, MessageType  # type: ignore
import traceback
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore


devices = ["CORE1-WA", "CORE2-WA"]
ROOM_NAME = "Core Alarms"
CACHE_FILE = "/home/jclarke/tcam_util.json"

spark = None


def send_command(chan, command):
    chan.sendall(command + "\n")
    i = 0
    output = ""
    while i < 10:
        if chan.recv_ready():
            break
        i += 1
        time.sleep(i * 0.5)
    while chan.recv_ready():
        r = chan.recv(131070).decode("utf-8")
        output = output + r

    return output


def get_results(dev, cache):
    global ROOM_NAME, spark
    commands = ["show platform hardware fed active fwd-asic resource tcam utilization"]

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    output = ""

    try:
        ssh_client.connect(dev, username=CLEUCreds.NET_USER, password=CLEUCreds.NET_PASS, timeout=5, allow_agent=False, look_for_keys=False)
        chan = ssh_client.invoke_shell()
        try:
            send_command(chan, "term width 0")
            send_command(chan, "term length 0")
            for cmd in commands:
                try:
                    output = send_command(chan, cmd)
                except Exception as iie:
                    sys.stderr.write("Failed to get result for {} from {}: {}\n".format(cmd, dev, iie))
                    traceback.print_exc()

        except Exception as ie:
            sys.stderr.write("Failed to setup SSH on {}: {}\n".format(dev, ie))
            traceback.print_exc()
    except Exception as e:
        sys.stderr.write("Failed to connect to {}: {}\n".format(dev, e))

    ssh_client.close()

    ready = False

    cache[dev] = {}

    cached_elements = None

    for line in output.split("\n"):
        line = line.strip()
        if re.search(r"^-+$", line):
            ready = True
            continue
        if not ready:
            continue
        if len(line) == 0:
            break
        line = re.sub(r"\s+", " ", line)
        elements = line.split(" ")
        if len(elements) < 9:
            cached_elements = elements
            continue

        if cached_elements:
            elements = cached_elements + elements
            cached_elements = None

        used = elements[-6]
        max = elements[-7]
        metric = " ".join(elements[0:-7])
        metric = metric.strip()
        m = re.search(r"(\d+)(/\d+)?", used)
        used = float(m.group(1))
        m = re.search(r"(\d+)(/\d+)?", max)
        max = float(m.group(1))
        perc = float(old_div(used, max)) * 100.0
        # if metric == 'Directly or indirectly connected routes':
        #    perc = 76.0
        if perc >= 75.0:
            msg = "{} on {} is {}% used".format(metric, dev, perc)
            spark.post_to_spark(C.WEBEX_TEAM, ROOM_NAME, msg, MessageType.BAD)

        cache[dev][metric] = perc


if __name__ == "__main__":
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    cache = {}

    for dev in devices:
        get_results(dev, cache)

    fd = open(CACHE_FILE, "w")
    json.dump(cache, fd, indent=4)
    fd.close()
