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

"""
Update DHCP scope ranges for all IDF scopes of a given VLAN.

This script iterates through all IDF-### scopes for a specified VLAN name
and updates the DHCP range to use new starting and ending octets.

Example:
    script.py --vlan SESSION-RECORDING --start 200 --end 253

This will update all scopes like IDF-001-SESSION-RECORDING to have a DHCP range
from 10.9.1.200 to 10.9.1.253 (assuming the VLAN subnet is 10.9.1.0/24).
"""

import argparse
from builtins import range, str

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys

import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

IDF_CNT = 242

SCOPE_BASE = C.DHCP_BASE + "/Scope"

HEADERS = {"accept": "application/json", "content-type": "application/json"}


def get_scope_details(scope_name):
    """
    Retrieve scope details from CPNR.

    Args:
        scope_name: Name of the scope to retrieve

    Returns:
        dict: Scope details as JSON, or None if scope doesn't exist
    """
    url = f"{SCOPE_BASE}/{scope_name}"

    try:
        response = requests.request(
            "GET", url, auth=(CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD), headers=HEADERS, verify=False
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except Exception as e:
        sys.stderr.write(f"Failed to get scope details for {scope_name}: {e}\n")
        return None


def update_scope_range(scope_name, start_octet, end_octet, dry_run=False):
    """
    Update the DHCP range for a scope.

    Args:
        scope_name: Name of the scope to update
        start_octet: Starting octet for the DHCP range (last octet)
        end_octet: Ending octet for the DHCP range (last octet)
        dry_run: If True, only print what would be done

    Returns:
        bool: True if successful, False otherwise
    """
    # Get current scope details
    scope = get_scope_details(scope_name)
    if scope is None:
        sys.stderr.write(f"Scope {scope_name} does not exist, skipping\n")
        return False

    # Extract subnet information to build new range
    subnet_parts = scope["subnet"].split("/")[0].split(".")
    start_ip = f"{subnet_parts[0]}.{subnet_parts[1]}.{subnet_parts[2]}.{start_octet}"
    end_ip = f"{subnet_parts[0]}.{subnet_parts[1]}.{subnet_parts[2]}.{end_octet}"

    if dry_run:
        print(f"[DRY RUN] Would update {scope_name}:")
        print(f"  Current range: {scope['rangeList']['RangeItem'][0]['start']} - {scope['rangeList']['RangeItem'][0]['end']}")
        print(f"  New range: {start_ip} - {end_ip}")
        return True

    # Build payload with new range
    payload = {
        "rangeList": {"RangeItem": [{"start": start_ip, "end": end_ip}]},
        "policy": scope["policy"],
    }

    # Preserve embedded policy if it exists
    if "embeddedPolicy" in scope:
        payload["embeddedPolicy"] = scope["embeddedPolicy"]

    url = f"{SCOPE_BASE}/{scope_name}"

    try:
        response = requests.request(
            "PUT", url, json=payload, auth=(CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD), headers=HEADERS, verify=False
        )
        response.raise_for_status()
        print(f"✓ Updated {scope_name}: {start_ip} - {end_ip}")
        return True
    except Exception as e:
        sys.stderr.write(f"Failed to update scope {scope_name}: {e}\n")
        if hasattr(e, "response") and hasattr(e.response, "text"):
            sys.stderr.write(f"Response: {e.response.text}\n")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Update DHCP scope ranges for all IDF scopes of a given VLAN",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --vlan SESSION-RECORDING --start 200 --end 253
  %(prog)s --vlan GUEST --start 50 --end 250 --dry-run
  %(prog)s --vlan WIRELESS --start 100 --end 200 --idf-start 1 --idf-end 50
        """,
    )

    parser.add_argument(
        "--vlan",
        required=True,
        help="VLAN name for the scopes (e.g., SESSION-RECORDING, GUEST)",
    )

    parser.add_argument(
        "--start",
        type=int,
        required=True,
        help="Starting octet for the DHCP range (1-254)",
    )

    parser.add_argument(
        "--end",
        type=int,
        required=True,
        help="Ending octet for the DHCP range (1-254)",
    )

    parser.add_argument(
        "--idf-start",
        type=int,
        default=1,
        help="Starting IDF number (default: 1)",
    )

    parser.add_argument(
        "--idf-end",
        type=int,
        default=IDF_CNT,
        help=f"Ending IDF number (default: {IDF_CNT})",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without making actual changes",
    )

    args = parser.parse_args()

    # Validate octet ranges
    if not (1 <= args.start <= 254):
        sys.stderr.write("Error: Start octet must be between 1 and 254\n")
        sys.exit(1)

    if not (1 <= args.end <= 254):
        sys.stderr.write("Error: End octet must be between 1 and 254\n")
        sys.exit(1)

    if args.start >= args.end:
        sys.stderr.write("Error: Start octet must be less than end octet\n")
        sys.exit(1)

    # Validate IDF range
    if args.idf_start < 1 or args.idf_end > IDF_CNT:
        sys.stderr.write(f"Error: IDF range must be between 1 and {IDF_CNT}\n")
        sys.exit(1)

    if args.idf_start > args.idf_end:
        sys.stderr.write("Error: IDF start must be less than or equal to IDF end\n")
        sys.exit(1)

    # Normalize VLAN name (uppercase and replace spaces with dashes)
    vlan_name = args.vlan.upper().replace(" ", "-")

    if args.dry_run:
        print("=" * 60)
        print("DRY RUN MODE - No changes will be made")
        print("=" * 60)

    print(f"\nUpdating DHCP ranges for VLAN: {vlan_name}")
    print(f"New range: .{args.start} - .{args.end}")
    print(f"Processing IDFs: {args.idf_start} to {args.idf_end}\n")

    success_count = 0
    skip_count = 0
    fail_count = 0

    for i in range(args.idf_start, args.idf_end + 1):
        scope_name = f"IDF-{str(i).zfill(3)}-{vlan_name}"

        result = update_scope_range(scope_name, args.start, args.end, args.dry_run)

        if result:
            success_count += 1
        elif result is False:
            # None means skipped, False means failed
            fail_count += 1
        else:
            skip_count += 1

    print("\n" + "=" * 60)
    print("Summary:")
    print(f"  Successfully updated: {success_count}")
    print(f"  Failed: {fail_count}")
    print(f"  Skipped (not found): {skip_count}")
    print("=" * 60)

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
