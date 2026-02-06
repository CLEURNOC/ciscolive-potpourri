#!/usr/bin/env python
#
# Copyright (c) 2026  Joe Clarke <jclarke@cisco.com>
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

from __future__ import annotations

import re
import sys
import requests

import CLEUCreds  # type: ignore

WEBHOOK_URL = CLEUCreds.RAI_WEBHOOK_URL


def process_syslog_line(line: str) -> None:
    """Process a single syslog line and send alerts if needed."""
    try:
        host, msghdr, msg = line.split("~", 2)
    except ValueError:
        print(f"Warning: Invalid syslog format: {line.strip()}", file=sys.stderr)
        return

    # Check for port going into err-disable state
    if match := re.search(r"AP Event: AP Name: ([A-Z0-9-]+) Mac: ([a-fA-F0-9.]+) Session-IP: ([\d.]+).*(Disjoined|Joined)", msg):
        if match.group(3).startswith("192.168."):
            ap_name, mac, session_ip, activity = match.groups()
            if activity == "Disjoined":
                sev = "🚨🚨"
            else:
                sev = "✅"

            payload = {
                "markdown": f"{sev} **AP {activity} Event**: AP **{ap_name}** with MAC **{mac}** and Session IP **{session_ip}** has {activity.lower()} controller {host}."
            }

            response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status()


if __name__ == "__main__":

    try:
        for line in sys.stdin:
            process_syslog_line(line.strip())
    except KeyboardInterrupt:
        print("\nShutting down gracefully...", file=sys.stderr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
