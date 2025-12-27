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

"""Remove devices from LibreNMS matching a specific pattern."""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass
from typing import Any

import click
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


@dataclass
class LibreNMSClient:
    """Client for LibreNMS API operations."""

    api_token: str
    dns_domain: str

    @property
    def base_url(self) -> str:
        """Get base API URL."""
        return f"https://librenms.{self.dns_domain}/api/v0"

    @property
    def headers(self) -> dict[str, str]:
        """Get API headers."""
        return {"X-Auth-Token": self.api_token}

    def get_all_devices(self) -> list[dict[str, Any]]:
        """Fetch all devices from LibreNMS."""
        url = f"{self.base_url}/devices"

        try:
            response = requests.get(url, headers=self.headers, timeout=30, verify=False)
            response.raise_for_status()
            data = response.json()
            return data.get("devices", [])
        except requests.exceptions.RequestException as e:
            click.echo(f"ERROR: Failed to fetch devices from LibreNMS: {e}", err=True)
            return []

    def delete_device(self, device_identifier: str | int) -> tuple[bool, str]:
        """
        Delete a device from LibreNMS.

        Args:
            device_identifier: Device hostname or ID

        Returns:
            Tuple of (success, message)
        """
        url = f"{self.base_url}/devices/{device_identifier}"

        try:
            response = requests.delete(url, headers=self.headers, timeout=30, verify=False)
            response.raise_for_status()

            result = response.json()
            status = result.get("status", "")
            message = result.get("message", "")

            if status == "ok":
                return True, message
            else:
                return False, message

        except requests.exceptions.RequestException as e:
            error_msg = f"Request failed: {e}"
            if hasattr(e, "response") and e.response is not None:
                error_msg += f"\nResponse: {e.response.text}"
            return False, error_msg


def match_pattern(hostname: str, pattern: str, use_regex: bool) -> bool:
    """
    Check if hostname matches the given pattern.

    Args:
        hostname: Device hostname
        pattern: Pattern to match
        use_regex: If True, use regex matching; otherwise use simple substring matching

    Returns:
        True if hostname matches pattern
    """
    if use_regex:
        try:
            return bool(re.search(pattern, hostname, re.IGNORECASE))
        except re.error as e:
            click.echo(f"ERROR: Invalid regex pattern: {e}", err=True)
            return False
    else:
        return pattern.lower() in hostname.lower()


@click.command()
@click.option(
    "--pattern",
    "-p",
    required=True,
    help="Pattern to match device hostnames (case-insensitive)",
)
@click.option(
    "--regex",
    "-r",
    is_flag=True,
    help="Treat pattern as a regular expression instead of substring",
)
@click.option(
    "--dry-run",
    "-n",
    is_flag=True,
    help="Show what would be deleted without actually deleting",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Skip confirmation prompt",
)
@click.option(
    "--delay",
    "-d",
    default=1,
    type=int,
    help="Delay in seconds between deletions (default: 1)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed progress",
)
def remove_devices(
    pattern: str,
    regex: bool,
    dry_run: bool,
    force: bool,
    delay: int,
    verbose: bool,
) -> None:
    """
    Remove devices from LibreNMS matching a specific pattern.

    Examples:

        # Remove all devices containing "test" (case-insensitive)
        python remove-librenms-devices.py --pattern test

        # Remove devices matching regex pattern (dry-run)
        python remove-librenms-devices.py --pattern "^lab-.*-sw[0-9]+" --regex --dry-run

        # Force remove devices with "temp" without confirmation
        python remove-librenms-devices.py --pattern temp --force
    """
    # Initialize LibreNMS client
    client = LibreNMSClient(
        api_token=CLEUCreds.LIBRENMS_TOKEN,
        dns_domain=C.DNS_DOMAIN,
    )

    # Fetch all devices
    click.echo("Fetching devices from LibreNMS...")
    all_devices = client.get_all_devices()

    if not all_devices:
        click.echo("No devices found in LibreNMS or failed to fetch devices.", err=True)
        sys.exit(1)

    if verbose:
        click.echo(f"Total devices in LibreNMS: {len(all_devices)}")

    # Filter devices matching pattern
    matching_devices = []
    for device in all_devices:
        hostname = device.get("hostname", "")
        device_id = device.get("device_id")

        if hostname and match_pattern(hostname, pattern, regex):
            matching_devices.append({"hostname": hostname, "device_id": device_id})

    # Show matching devices
    if not matching_devices:
        click.echo(f"\nNo devices found matching pattern: {pattern}")
        sys.exit(0)

    click.echo(f"\nFound {len(matching_devices)} device(s) matching pattern '{pattern}':")
    click.echo("-" * 60)
    for idx, device in enumerate(matching_devices, 1):
        click.echo(f"{idx}. {device['hostname']} (ID: {device['device_id']})")
    click.echo("-" * 60)

    # Dry-run mode
    if dry_run:
        click.echo("\n[DRY RUN] No devices were deleted.")
        sys.exit(0)

    # Confirmation prompt
    if not force:
        click.echo("\n⚠️  WARNING: This action cannot be undone!")
        if not click.confirm(f"Do you want to delete these {len(matching_devices)} device(s)?"):
            click.echo("Aborted.")
            sys.exit(0)

    # Delete devices
    click.echo("\nDeleting devices...")
    success_count = 0
    failure_count = 0

    with click.progressbar(
        matching_devices,
        label="Progress",
        show_eta=True,
        item_show_func=lambda d: d["hostname"] if d else "",
    ) as bar:
        for device in bar:
            hostname = device["hostname"]
            device_id = device["device_id"]

            success, message = client.delete_device(hostname)

            if success:
                success_count += 1
                if verbose:
                    click.echo(f"\n✓ Deleted: {hostname}")
            else:
                failure_count += 1
                click.echo(f"\n✗ Failed to delete {hostname}: {message}", err=True)

            # Delay between deletions to avoid overwhelming the API
            if delay > 0 and device != matching_devices[-1]:
                time.sleep(delay)

    # Summary
    click.echo("\n" + "=" * 60)
    click.echo("SUMMARY")
    click.echo("=" * 60)
    click.echo(f"Total devices processed: {len(matching_devices)}")
    click.echo(f"Successfully deleted:    {success_count}")
    click.echo(f"Failed:                  {failure_count}")
    click.echo("=" * 60)

    sys.exit(0 if failure_count == 0 else 1)


if __name__ == "__main__":
    remove_devices()
