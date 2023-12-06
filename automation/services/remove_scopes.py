#!/usr/bin/env python
#
# Copyright (c) 2017-2022  Joe Clarke <jclarke@cisco.com>
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
from subprocess import Popen, PIPE
import re
import shlex
from cleu.config import Config as C  # type: ignore

if __name__ == "__main__":
    match = None
    ans = None
    if len(sys.argv) == 2:
        match = sys.argv[1]
        ans = input(f'Really delete all scopes that match "{match}" (y/N): ')
    else:
        ans = input("Really delete all scopes (y/N): ")

    if not re.search(r"^[yY]", ans):
        print("Exiting...")
        sys.exit(0)

    proc = Popen(shlex.split(f"ssh -2 root@{C.DHCP_SERVER} /root/nrcmd.sh -r scope listnames"), stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    if not re.search(r"^100", out.decode("utf-8")):
        print('Query for scopes failed: "{}"'.format(out.decode("utf-8")))
        sys.exit(1)
    scopes = out.decode("utf-8").split("\n")
    for scope in scopes:
        scope = scope.strip()
        if scope != "100 Ok" and re.search(r"^\w", scope):
            delete = True
            if match and not re.search(match, scope):
                delete = False
            if delete:
                print(f"Deleting scope {scope}")
                proc = Popen(
                    shlex.split(f"ssh -2 root@{C.DHCP_SERVER} /root/nrcmd.sh -r scope '\\\"{scope}\\\"' delete"), stdout=PIPE, stderr=PIPE
                )
                out, err = proc.communicate()
                if not re.search(r"^10[01]", out.decode("utf-8")):
                    print(f"ERROR: Deleting scope {scope} failed: {out.decode('utf-8')}")
            else:
                print(f'Skipping scope {scope} as it did not match "{match}"')
