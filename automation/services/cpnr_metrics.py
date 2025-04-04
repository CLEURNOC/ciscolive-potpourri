#!/usr/bin/env python
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

from flask import Flask  # type: ignore
from flask import Response  # type: ignore
from gevent.pywsgi import WSGIServer  # type: ignore
from subprocess import run
import shlex
import re
from cleu.config import Config as C  # type: ignore


# CACHE_FILE = "/home/jclarke/cpnr_metrics.dat"
PORT = 8085

app = Flask("CPNR Stats Fetcher")

COMMANDS = {"df -h /": {"pattern": r"(\d+)%", "metrics": ["diskUtilization"]}}


@app.route("/metrics")
def get_metrics():
    global COMMANDS

    output = ""
    for server in C.CPNR_SERVERS:
        for command in list(COMMANDS.keys()):
            res = run(shlex.split(f"ssh -2 root@{server} {command}"), capture_output=True, text=True)
            if res.returncode != 0:
                print("ERROR: Failed to execute %s on %s: out='%s', err='%s'" % (command, server, res.stdout.strip(), res.stderr.strip()))
                continue

            if m := re.search(COMMANDS[command]["pattern"], res.stdout.strip()):
                i = 1
                for metric in COMMANDS[command]["metrics"]:
                    output += f'{metric}{{server="{server}"}} {m.group(i)}\n'
                    i += 1

    return Response(output, mimetype="text/plain")


if __name__ == "__main__":
    #    app.run(host='10.100.253.13', port=8081, threaded=True)
    http_server = WSGIServer((C.WSGI_SERVER, PORT), app)
    http_server.serve_forever()
