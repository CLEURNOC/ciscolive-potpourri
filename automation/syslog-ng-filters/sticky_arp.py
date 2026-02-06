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

import json
import re
import sys
import time
from pathlib import Path
from typing import Dict

from sparker import Sparker, MessageType  # type: ignore
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

SPARK_ROOM = "Sticky ARP Alarms"
CACHE_FILE = Path("/home/jclarke/sticky_arp_cache.json")
FOUR_HOURS_MS = 4 * 60 * 60 * 1000


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


def process_syslog_line(line: str, spark: Sparker, curr_arps: Dict[str, int]) -> None:
    """Process a single syslog line and send alerts if needed."""
    try:
        host, _, msg = line.split("~", 2)
    except ValueError:
        print(f"Warning: Invalid syslog format: {line.strip()}", file=sys.stderr)
        return

    # Check for port going into err-disable state
    if match := re.search(r"Attempt to overwrite Sticky ARP entry: ([\d.]+), hw: ([a-fA-F0-9.]+) by hw: ([a-fA-F0-9.]+)", msg):
        arp, orig_mac, new_mac = match.groups()
        now_ms = get_current_time_ms()
        last_seen_ms = curr_arps.get(arp)

        if last_seen_ms is not None and now_ms - last_seen_ms < FOUR_HOURS_MS:
            return

        spark.post_to_spark(
            C.WEBEX_TEAM,
            SPARK_ROOM,
            f"ARP entry for {arp} on **{host}** is stuck on MAC **{orig_mac}**, attempted overwrite by **{new_mac}**",
            MessageType.WARNING,
        )
        curr_arps[arp] = now_ms


if __name__ == "__main__":
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)
    curr_arps = load_cache()

    try:
        for line in sys.stdin:
            process_syslog_line(line.strip(), spark, curr_arps)
            save_cache(curr_arps)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...", file=sys.stderr)
        save_cache(curr_arps)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        save_cache(curr_arps)
        sys.exit(1)
