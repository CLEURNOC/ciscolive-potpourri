#!/usr/bin/env python3
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

from __future__ import division
import re
import sys
import time
import json
import paramiko
import random
from multiprocessing import Pool
from sparker import Sparker, MessageType  # type: ignore
import traceback
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore


IDF_FILE = "/home/jclarke/idf-devices.json"
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


def get_results(dev):
    global ROOM_NAME, spark
    commands = ["show platform hardware fed switch active fwd-asic resource tcam utilization"]

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
    cache = {"device": dev}

    for line in output.split("\n"):
        # IP Route Table         TCAM         I        8192     6876   83.94%
        if m := re.search(r"IP Route Table\s+TCAM\s+IO?\s+(\d+)\s+(\d+)\s+([\d.]+)%", line):

            max = float(m.group(1))
            used = float(m.group(2))
            perc = float(m.group(3))
            # if metric == 'Directly or indirectly connected routes':
            #    perc = 76.0
            if perc >= 90.0:
                msg = "IP Route Table TCAM on {} is {}% used (max: {}, used: {})".format(dev, perc, max, used)
                spark.post_to_spark(C.WEBEX_TEAM, ROOM_NAME, msg, MessageType.BAD)

            cache["max"] = max
            cache["used"] = used
            cache["perc"] = perc

            break

    return cache


def get_metrics(pool):
    response = []

    with open(IDF_FILE, "r") as fd:
        devices = json.load(fd)

    results = [pool.apply_async(get_results, [d]) for d in devices]
    for res in results:
        retval = res.get()
        if retval:
            response += retval

    return response


if __name__ == "__main__":
    time.sleep(random.randrange(90))

    pool = Pool(20)
    response = get_metrics(pool)
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    fd = open(CACHE_FILE, "w")
    json.dump(response, fd, indent=2)
    fd.close()
