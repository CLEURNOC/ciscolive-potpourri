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

import sys
import re
import subprocess
import os
import json
import argparse


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Convert Ansible hosts file to JSON")
    parser.add_argument("--output-file", "-o", metavar="<OUTPUT_FILE_PATH>", help="Path to the file to store the JSON", required=True)
    parser.add_argument(
        "--playbook",
        "-p",
        metavar="<PLAYBOOK_NAME>",
        help="Name of playbook to use to generate file (default: add-to-librenms-playbook.yml)",
        default="add-to-librenms-playbook.yml",
    )
    parser.add_argument("--limit", metavar="<LIMIT_STRING>", help="Optional set of hosts or groups to limit")
    args = parser.parse_args()

    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "300"

    command = [
        "ansible-playbook",
        "-i",
        "inventory/hosts",
        "--list-hosts",
        "-e",
        "ansible_python_interpreter={}".format(sys.executable),
        args.playbook,
    ]

    if args.limit:
        command += ["--limit", args.limit]

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    hosts = ""
    for c in iter(lambda: p.stdout.read(1), b""):
        hosts += c.decode("utf-8")

    p.poll()

    hlist = []
    reading_hosts = False
    for h in hosts.split("\n"):
        if not reading_hosts and re.search(r"hosts \(\d+\):", h):
            reading_hosts = True
            continue
        if not reading_hosts:
            continue
        h = h.strip()
        if h == "":
            continue
        hlist.append(h.strip())

    fd = None

    if args.output_file == "-":
        fd = sys.stdout
    else:
        fd = open(args.output_file, "w")

    json.dump(hlist, fd, indent=4)
    fd.write("\n")
    if args.output_file == "-":
        fd.flush()
    else:
        fd.close()


if __name__ == "__main__":
    main()
