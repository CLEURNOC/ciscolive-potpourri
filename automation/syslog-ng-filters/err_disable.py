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

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Dict

from sparker import Sparker, MessageType  # type: ignore
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

SPARK_ROOM = "Err Disable Alarms"
CACHE_FILE = Path("/home/jclarke/err_disable_cache.json")
DEBOUNCE_MS = 30000  # 30 seconds


def make_tool_link(switch: str, port: str) -> str:
    """Generate a clickable link to the port management tool."""
    return f'<a href="{C.TOOL_BASE}switchname={switch}&portname={port}">**{port}**</a>'


def load_cache() -> Dict[str, int]:
    """Load port cache from disk."""
    if not CACHE_FILE.exists():
        return {}

    try:
        return json.loads(CACHE_FILE.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: Failed to load cache: {e}", file=sys.stderr)
        return {}


def save_cache(cache: Dict[str, int]) -> None:
    """Save port cache to disk."""
    try:
        CACHE_FILE.write_text(json.dumps(cache, indent=2))
    except OSError as e:
        print(f"Warning: Failed to save cache: {e}", file=sys.stderr)


def get_current_time_ms() -> int:
    """Get current time in milliseconds."""
    return int(time.time() * 1000)


def process_syslog_line(line: str, spark: Sparker, curr_ports: Dict[str, int]) -> None:
    """Process a single syslog line and send alerts if needed."""
    try:
        host, msghdr, msg = line.split("~", 2)
    except ValueError:
        print(f"Warning: Invalid syslog format: {line.strip()}", file=sys.stderr)
        return

    hname = msghdr.replace(": ", "")
    hpart = f"({hname})" if hname and hname not in ("GMT", "CET") else ""

    # Check for port going into err-disable state
    if match := re.search(r": ([^,]+), putting ([^\s]+) in err-disable state", msg):
        reason, port = match.groups()
        port_key = f"{host}:{port}"

        spark.post_to_spark(
            C.WEBEX_TEAM,
            SPARK_ROOM,
            f"Port {make_tool_link(host, port)} on **{host}** **{hpart}** has been put in an err-disable state because {reason}",
            MessageType.WARNING,
        )
        curr_ports[port_key] = get_current_time_ms()

    # Check for port recovering from err-disable state
    elif match := re.search(r"recover from .+? err-disable state on (\S+)", msg):
        port = match.group(1)
        port_key = f"{host}:{port}"

        if port_key in curr_ports:
            # Only send recovery alert if debounce period has passed (30 seconds)
            if get_current_time_ms() - curr_ports[port_key] >= DEBOUNCE_MS:
                spark.post_to_spark(
                    C.WEBEX_TEAM,
                    SPARK_ROOM,
                    f"Port {make_tool_link(host, port)} on **{host}** **{hpart}** is recovering from err-disable",
                    MessageType.GOOD,
                )
                del curr_ports[port_key]


if __name__ == "__main__":
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)
    curr_ports = load_cache()

    try:
        for line in sys.stdin:
            process_syslog_line(line.strip(), spark, curr_ports)
            save_cache(curr_ports)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...", file=sys.stderr)
        save_cache(curr_ports)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        save_cache(curr_ports)
        sys.exit(1)
