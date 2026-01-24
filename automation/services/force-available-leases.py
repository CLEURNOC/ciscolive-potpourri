#!/usr/bin/env python

# Copyright (c) 2017-2026  Joe Clarke <jclarke@cisco.com>
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
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

import argparse
import ipaddress
import re

import CLEUCreds  # type: ignore
import requests
from cleu.config import Config as C  # type: ignore
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def force_leases_available(subnet: str) -> None:
    """Force all leases to be available."""
    dhcp_url = f"{C.DHCP_BASE}/Lease"
    headers = {"accept": "application/json", "content-type": "application/json"}
    auth = (CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD)

    addresses = list(ipaddress.ip_network(subnet, strict=False).hosts())
    total = len(addresses)

    for idx, host in enumerate(addresses, 1):
        ip_str = str(host)
        lease_url = f"{dhcp_url}/{ip_str}"

        # Display progress bar
        bar_length = 40
        filled = int(bar_length * idx / total)
        bar = "█" * filled + "░" * (bar_length - filled)
        percent = idx * 100 // total
        print(f"\r[{bar}] {percent}% ({idx}/{total}) {ip_str}", end="", flush=True)

        try:
            resp = requests.delete(lease_url, headers=headers, auth=auth, verify=False)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"\nError forcing lease available for {ip_str}: {e.response.text if e.response else str(e)}")
            continue

    print()  # New line after progress bar completes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Force all DHCP leases to be available.")
    parser.add_argument(
        "--subnet",
        type=lambda s: s if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", s) else None,
        help="Force available all leases in this subnet (CIDR notation).",
        required=True,
    )
    args = parser.parse_args()
    if args.subnet is None:
        print("ERROR: Invalid subnet format. Please use CIDR notation (e.g., 192.168.1.0/24).")
        exit(1)
    else:
        (_, length) = args.subnet.split("/")
        if int(length) < 16:
            confirm = input(
                f"WARNING: You are about to force available all leases in a large subnet ({args.subnet}). "
                "This may have significant impact. Are you sure you want to continue? (yes/no): "
            )
            if not confirm.lower().startswith("y"):
                print("Operation cancelled by user.")
                exit(0)

    force_leases_available(args.subnet)
