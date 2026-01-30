#!/usr/bin/env python
#
# Copyright (c) 2026  Ezgi Agcagul <eagcagul@cisco.com>
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

import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore
from sparker import MessageType, Sparker  # type: ignore

# --- CONFIGURATION ---
SPARK_ROOM = "Data Centre Alarms"
# ---------------------

if __name__ == "__main__":
    # Initialize Webex connection
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    while True:
        # Read from syslog-ng pipe
        line = sys.stdin
        if not line:
            continue

        try:
            line = line.strip()
            if not line:
                continue

            # Send the normal message to Webex
            formatted_msg = "**NEXUS DASHBOARD ALERT**\n{}".format(line)

            mtype = MessageType.WARNING
            if re.search(r"critical", line, re.IGNORECASE):
                mtype = MessageType.BAD

            spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, formatted_msg, mtype)

        except Exception:
            # Ignore errors to keep the pipe open
            continue
