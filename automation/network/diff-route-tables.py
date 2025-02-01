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
import random
from subprocess import Popen, PIPE, call, DEVNULL, STDOUT
import shlex
import re
import json
import argparse
import traceback
import CLEUCreds  # type: ignore
import shutil
from cleu.config import Config as C  # type: ignore

routers = {}

commands = {"ip_route": "show ip route", "ipv6_route": "show ipv6 route"}

cache_dir = "/home/jclarke/routing-tables"

# TODO: Integrate with NetBox to get edge routers
ROUTER_FILE = "/home/jclarke/routers.json"

WEBEX_ROOM = "Edge Routing Diffs"


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


def main():
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
        print(f"ERROR: Failed to load routers file {ROUTER_FILE}: {e}")

    do_push = False

    for router, ip in list(routers.items()):
        try:
            ssh_client.connect(
                ip,
                username=CLEUCreds.NET_USER,
                password=CLEUCreds.NET_PASS,
                timeout=60,
                allow_agent=False,
                look_for_keys=False,
            )
            chan = ssh_client.invoke_shell()
            chan.settimeout(20)

            try:
                send_command(chan, "term length 0")
                send_command(chan, "term width 0")
            except Exception:
                pass
            for fname, command in list(commands.items()):
                output = ""
                try:
                    output = send_command(chan, command)
                except Exception as ie:
                    print(f"Failed to get {command} from {router}: {ie}")
                    continue

                fpath = f"{cache_dir}/{fname}-{router}"
                curr_path = fpath + ".curr"
                prev_path = fpath + ".prev"
                if len(output) < 600:
                    # we got a truncated file
                    continue

                with open(curr_path, "w") as fd:
                    output = re.sub(r"\r", "", output)
                    output = re.sub(r"([\d\.]+) (\[[^\n]+)", "\\1\n          \\2", output)
                    fd.write(re.sub(r"(via [\d\.]+), [^,\n]+([,\n])", "\\1\\2", output))

                if os.path.exists(prev_path):
                    proc = Popen(
                        shlex.split("/usr/bin/diff -b -B -w -u {} {}".format(prev_path, curr_path)),
                        stdout=PIPE,
                        stderr=PIPE,
                        text=True,
                    )
                    out, _ = proc.communicate()
                    rc = proc.returncode

                    if rc != 0:
                        if (args.notify and router in args.notify) or not args.notify:
                            spark.post_to_spark(
                                C.WEBEX_TEAM,
                                WEBEX_ROOM,
                                "Routing table diff ({}) on **{}**:\n```\n{}\n```".format(
                                    command, router, re.sub(cache_dir + "/", "", out)
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
                                    call(f"git add {gfile}", shell=True, stdout=DEVNULL)
                                    call(f'git commit -m "Routing table update" {gfile}', shell=True, stdout=DEVNULL)
                                    do_push = True
                                except Exception as ie:
                                    print(f"ERROR: Failed to commit to git repo {args.git_repo}: {ie}")
                                    traceback.print_exc()
                            else:
                                print(f"ERROR: Git repo {args.git_repo} is not a directory")
                        # print('XXX: Out = \'{}\''.format(out))

                os.rename(curr_path, prev_path)

        except Exception as e:
            ssh_client.close()
            print(f"Failed to get routing tables from {router}: {e}")
            traceback.print_exc()
            continue

        ssh_client.close()

    if do_push:
        if not args.git_branch:
            print("ERROR: Cannot push without a branch")
        else:
            os.chdir(args.git_repo)
            call(f"git pull origin {args.git_branch}", shell=True, stdout=DEVNULL, stderr=DEVNULL)
            proc = Popen(shlex.split(f"git push origin {args.git_branch}"), stdout=PIPE, stderr=STDOUT, text=True)
            out, _ = proc.communicate()
            rc = proc.returncode
            if rc != 0:
                print(f"ERROR: Failed to push to git: {out}")


if __name__ == "__main__":
    # Add jitter.
    time.sleep(random.randrange(150))

    main()
