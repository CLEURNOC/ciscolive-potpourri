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

routers = {}

commands = {"ip_route": "show ip route", "ipv6_route": "show ipv6 route"}

cache_dir = "/home/jclarke/routing-tables"
ROUTER_FILE = "/home/jclarke/routers.json"

WEBEX_ROOM = "Core Alarms"


def send_command1(chan, command):
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


def send_command(chan, command):
    chan.sendall(command + "\n")
    output = ""
    while True:
        if chan.recv_ready():
            r = chan.recv(65535)
            if len(r) == 0:
                raise EOFError("Channel was closed by remote host")
            output += r.decode("utf-8", "ignore")
        else:
            break

    # Drain any remaining buffer.
    time.sleep(1)
    if chan.recv_ready():
        output += chan.recv(65535).decode("utf-8", "ignore")

    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Usage:")

    # script arguments
    parser.add_argument("--git-repo", "-g", metavar="<GIT_REPO_PATH>", help="Optional path to a git repo to store updates")
    parser.add_argument("--git-branch", "-b", metavar="<BRANCH_NAME>", help="Branch name to use to commit in git")
    parser.add_argument(
        "--notify",
        "-n",
        metavar="<ROUTER_NAME>",
        help="Only notify on routers with a given name (can be specified more than once)",
        action="append",
    )
    args = parser.parse_args()

    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        fd = open(ROUTER_FILE, "r")
        routers = json.load(fd)
        fd.close()
    except Exception as e:
        print("ERROR: Failed to load routers file {}: {}".format(ROUTER_FILE, e))

    do_push = False

    for router, ip in list(routers.items()):
        try:
            ssh_client.connect(
                ip, username=CLEUCreds.NET_USER, password=CLEUCreds.NET_PASS, timeout=60, allow_agent=False, look_for_keys=False,
            )
            chan = ssh_client.invoke_shell()
            try:
                send_command(chan, "term length 0")
                send_command(chan, "term width 0")
            except:
                pass
            for fname, command in list(commands.items()):
                output = ""
                try:
                    output = send_command(chan, command)
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
                    proc = Popen(shlex.split("/usr/bin/diff -b -B -w -u {} {}".format(prev_path, curr_path)), stdout=PIPE, stderr=PIPE,)
                    out, err = proc.communicate()
                    rc = proc.returncode

                    if rc != 0:
                        if (args.notify and router in args.notify) or not args.notify:
                            spark.post_to_spark(
                                C.WEBEX_TEAM,
                                WEBEX_ROOM,
                                "Routing table diff ({}) on **{}**:\n```\n{}\n```".format(
                                    command, router, re.sub(cache_dir + "/", "", out.decode("utf-8"))
                                ),
                                MessageType.BAD,
                            )
                            time.sleep(1)

                        if args.git_repo:
                            if os.path.isdir(args.git_repo):
                                try:
                                    gfile = re.sub(r"\.curr", ".txt", os.path.basename(curr_path))
                                    shutil.copyfile(curr_path, args.git_repo + "/" + gfile)
                                    os.chdir(args.git_repo)
                                    call("git add {}".format(gfile), shell=True)
                                    call('git commit -m "Routing table update" {}'.format(gfile), shell=True)
                                    do_push = True
                                except Exception as ie:
                                    print("ERROR: Failed to commit to git repo {}: {}".format(args.git_repo, ie))
                            else:
                                print("ERROR: Git repo {} is not a directory".format(args.git_repo))
                        # print('XXX: Out = \'{}\''.format(out))

                os.rename(curr_path, prev_path)

        except Exception as e:
            ssh_client.close()
            print("Failed to get routing tables from {}: {}".format(router, e))
            continue

        ssh_client.close()

    if do_push:
        if not args.git_branch:
            print("ERROR: Cannot push without a branch")
        else:
            os.chdir(args.git_repo)
            call("git pull origin {}".format(args.git_branch), shell=True)
            call("git push origin {}".format(args.git_branch), shell=True)
