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
CACHE_FILE = "/home/jclarke/object_counts.json"

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


def get_results(dev, command, cache):
    global ROOM_NAME, spark

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    output = ""

    try:
        ssh_client.connect(dev, username=CLEUCreds.NET_USER, password=CLEUCreds.NET_PASS, timeout=5, allow_agent=False, look_for_keys=False)
        chan = ssh_client.invoke_shell()
        try:
            send_command(chan, "term width 0")
            send_command(chan, "term length 0")
            try:
                output = send_command(chan, command)
            except Exception as iie:
                sys.stderr.write("Failed to get result for {} from {}: {}\n".format(command, dev, iie))
                traceback.print_exc()

        except Exception as ie:
            sys.stderr.write("Failed to setup SSH on {}: {}\n".format(dev, ie))
            traceback.print_exc()
    except Exception as e:
        sys.stderr.write("Failed to connect to {}: {}\n".format(dev, e))

    ssh_client.close()
    dev_obj = {dev: {}}

    for line in output.split("\n"):
        if m := re.search(r"([^\s]+):\s(\d+)", line):

            metric = m.group(1).replace("-", "_").lower()
            value = int(m.group(2))
            if metric != "total_objects":
                if dev in cache and metric in cache[dev] and cache[dev][metric] < value and value > 0:
                    msg = f"Metric **{metric}** has changed from {cache[dev][metric]} to {value} on **{dev}**"
                    spark.post_to_spark(C.WEBEX_TEAM, ROOM_NAME, msg, MessageType.BAD)

            dev_obj[dev][metric] = value

    return dev_obj


def get_metrics(pool):
    response = {}

    try:
        with open(CACHE_FILE, "r") as fd:
            cache = json.load(fd)
    except Exception:
        cache = {}

    with open(IDF_FILE, "r") as fd:
        idfs = json.load(fd)

    results = [pool.apply_async(get_results, [d, "show platform software object-manager switch active f0 statistics", cache]) for d in idfs]
    for res in results:
        retval = res.get()
        if retval:
            response = response | retval

    cores = [
        "core1-core",
        "core2-core",
        "core1-wa",
        "core2-wa",
        "core1-edge",
        "core2-edge",
        "core1-nat64",
        "core2-nat64",
        "mer1-dist-a",
        "mer1-dist-b",
        "mer2-dist-a",
        "mer2-dist-b",
        "mer4-dist-a",
        "mer4-dist-b",
    ]

    results = [pool.apply_async(get_results, [d, "show platform software object-manager f0 statistics", cache]) for d in cores]
    for res in results:
        retval = res.get()
        if retval:
            response = response | retval

    return response


if __name__ == "__main__":
    time.sleep(random.randrange(90))
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    pool = Pool(20)
    response = get_metrics(pool)

    with open(CACHE_FILE, "w") as fd:
        json.dump(response, fd, indent=2)
