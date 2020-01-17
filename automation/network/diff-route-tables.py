#!/usr/bin/env python3
#
# Copyright (c) 2017-2019  Joe Clarke <jclarke@cisco.com>
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

import paramiko
import os
from sparker import Sparker, MessageType
import time
from subprocess import Popen, PIPE
import shlex
import re
import json
import CLEUCreds
from cleu.config import Config as C

routers = {}

commands = {"ip_route": "show ip route", "ipv6_route": "show ipv6 route"}

cache_dir = "/home/jclarke/routing-tables"
ROUTER_FILE = "/home/jclarke/routers.json"

WEBEX_ROOM = "Core Alarms"

if __name__ == "__main__":
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        fd = open(ROUTER_FILE, "r")
        routers = json.load(fd)
        fd.close()
    except:
        pass

    for router, ip in routers.items():
        try:
            ssh_client.connect(
                ip, username=CLEUCreds.NET_USER, password=CLEUCreds.NET_PASS, timeout=60, allow_agent=False, look_for_keys=False,
            )
            chan = ssh_client.invoke_shell()
            for fname, command in commands.items():
                output = ""
                try:
                    chan.sendall("term length 0\n")
                    chan.sendall("term width 0\n")
                    chan.sendall("{}\n".format(command))
                    i = 0
                    while i < 10:
                        if chan.recv_ready():
                            break
                        time.sleep(0.5)
                        i += 1
                    while chan.recv_ready():
                        output = output + chan.recv(65535).decode("utf-8")
                except Exception as ie:
                    print("Failed to get {} from {}: {}".format(command, router, ie))
                    continue

                fpath = "{}/{}-{}".format(cache_dir, fname, router)
                curr_path = fpath + ".curr"
                prev_path = fpath + ".prev"
                fd = open(curr_path, "w")
                output = re.sub(r"\r", "", output)
                output = re.sub(r"([\d\.]+) (\[[^\n]+)", "\\1\n          \\2", output)
                fd.write(re.sub(r"(via [\d\.]+), [^,\n]+([,\n])", "\\1\\2", output))
                fd.close()

                if os.path.exists(prev_path):
                    proc = Popen(shlex.split("/usr/bin/diff -E -b -B -w -u {} {}".format(prev_path, curr_path)), stdout=PIPE, stderr=PIPE,)
                    out, err = proc.communicate()
                    rc = proc.returncode

                    if rc != 0:
                        spark.post_to_spark(
                            C.WEBEX_TEAM,
                            WEBEX_ROOM,
                            "Routing table diff ({}) on **{}**:\n```\n{}\n```".format(command, router, re.sub(cache_dir + "/", "", out)),
                            MessageType.BAD,
                        )
                        time.sleep(1)
                        # print('XXX: Out = \'{}\''.format(out))

                os.rename(curr_path, prev_path)

        except Exception as e:
            ssh_client.close()
            print("Failed to get routing tables from {}: {}".format(router, e))
            continue

        ssh_client.close()
