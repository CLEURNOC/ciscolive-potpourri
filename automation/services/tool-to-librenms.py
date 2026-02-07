#!/usr/bin/env python
#
# Copyright (c) 2017-2026  Joe Clarke <jclarke@cisco.com>
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

import argparse
import json
import logging
import os
import re
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import CLEUCreds  # type: ignore
import requests
from cleu.config import Config as C  # type: ignore
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set up logging
logger = logging.getLogger("tool-to-librenms")
loglevel = logging.DEBUG if os.getenv("DEBUG", "false").lower() == "true" else logging.INFO
logger.setLevel(loglevel)
# Configure handler with format for this module only
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False

CACHE_FILE = Path("/home/jclarke/monitored_devs.json")


@dataclass
class LibreNMSManager:
    """Manages LibreNMS device synchronization."""

    api_token: str
    dns_domain: str
    snmp_auth_pass: str
    snmp_priv_pass: str

    @property
    def _headers(self) -> dict[str, str]:
        """Get API headers."""
        return {"X-Auth-Token": self.api_token}

    def _should_monitor_device(self, device: dict[str, Any]) -> bool:
        """Check if a device should be monitored in LibreNMS."""
        # Skip unreachable or invalid IP devices
        if device.get("IPAddress") == "0.0.0.0" or not device.get("Reachable"):
            return False

        hostname = device.get("Hostname", "")

        # Must match standard naming convention
        if not re.match(r"^[0-9A-Za-z]{3}-", hostname):
            return False

        # Exclude certain device types
        excluded_patterns = [
            r".*CORE.*",
            r"^WLC",
            r".*MER[124]-dist.*",
            r".*EDGE.*",
        ]

        return not any(re.search(pattern, hostname, re.I) for pattern in excluded_patterns)

    def get_devices_from_tool(self, tool_url: str) -> list[dict[str, Any]]:
        """Fetch device list from the Tool."""
        url = f"http://{tool_url}/get/switches/json"

        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            devices = response.json()
            return [dev for dev in devices if self._should_monitor_device(dev)]
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch devices from Tool: {e}", exc_info=True)
            return []

    def delete_device(self, device_name: str) -> requests.Response:
        """Delete a device from LibreNMS."""
        url = f"https://librenms.{self.dns_domain}/api/v0/devices/{device_name}"
        return requests.delete(url, headers=self._headers, timeout=30)

    def device_exists(self, hostname: str) -> bool:
        """Check if a device exists in LibreNMS."""
        url = f"https://librenms.{self.dns_domain}/api/v0/inventory/{hostname}"
        try:
            response = requests.get(url, headers=self._headers, timeout=30)
            response.raise_for_status()
            return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                return False
            logger.error(f"Error checking device status for {hostname}: {e.response.text}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Error checking device status for {hostname}: {e}", exc_info=True)
            traceback.print_exc()
            return False

    def add_device(self, hostname: str) -> bool:
        """Add a device to LibreNMS."""
        url = f"https://librenms.{self.dns_domain}/api/v0/devices"
        payload = {
            "hostname": hostname,
            "version": "v3",
            "authlevel": "authPriv",
            "authname": "CLEUR",
            "authpass": self.snmp_auth_pass,
            "authalgo": "sha",
            "cryptopass": self.snmp_priv_pass,
            "cryptoalgo": "aes",
        }

        try:
            response = requests.post(url, headers=self._headers, json=payload, timeout=30)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to add {hostname} to LibreNMS: {e}", exc_info=True)
            if hasattr(e, "response") and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            return False


def load_device_cache(cache_file: Path) -> dict[str, str]:
    """Load device cache from disk."""
    if not cache_file.exists():
        return {}

    try:
        return json.loads(cache_file.read_text())
    except Exception as e:
        logger.error(f"Failed to load cache from {cache_file}: {e}", exc_info=True)
        return {}


def save_device_cache(cache_file: Path, devices: dict[str, str]) -> None:
    """Save device cache to disk atomically."""
    # Create backup
    backup_file = cache_file.with_suffix(f"{cache_file.suffix}.bak")
    if cache_file.exists():
        try:
            backup_file.write_text(cache_file.read_text())
        except Exception as e:
            logger.warning(f"Failed to create backup: {e}", exc_info=True)

    # Atomic write
    temp_file = cache_file.with_suffix(f"{cache_file.suffix}.tmp")
    try:
        temp_file.write_text(json.dumps(devices, indent=2))
        temp_file.replace(cache_file)
    except Exception as e:
        logger.error(f"Failed to save cache: {e}", exc_info=True)
        if temp_file.exists():
            temp_file.unlink()


def main() -> int:
    """Synchronize devices from Tool to LibreNMS."""
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Add devices from the Tool to LibreNMS")
    parser.add_argument("--force", "-f", action="store_true", help="Force re-adding all devices")
    parser.add_argument("--log", "-l", action="store_true", help="Log progress to stdout")
    args = parser.parse_args()

    # Load cached devices
    cached_devices = load_device_cache(CACHE_FILE)

    # Initialize LibreNMS manager
    manager = LibreNMSManager(
        api_token=CLEUCreds.LIBRENMS_TOKEN,
        dns_domain=C.DNS_DOMAIN,
        snmp_auth_pass=CLEUCreds.SNMP_AUTH_PASS,
        snmp_priv_pass=CLEUCreds.SNMP_PRIV_PASS,
    )

    # Fetch current devices from Tool
    tool_devices = manager.get_devices_from_tool(C.TOOL)
    if not tool_devices:
        logger.warning("No devices retrieved from Tool")
        return 1

    changes_made = False
    total_devices = len(tool_devices)

    for idx, device in enumerate(tool_devices, start=1):
        asset_tag = device.get("AssetTag")
        hostname = device.get("Hostname")

        if not asset_tag or not hostname:
            continue

        # Handle hostname change for existing asset
        if asset_tag in cached_devices and cached_devices[asset_tag] != hostname:
            old_hostname = cached_devices[asset_tag]
            if args.log:
                logger.info(f"=== Deleting renamed device {old_hostname} from LibreNMS ({idx}/{total_devices}) ===")

            response = manager.delete_device(old_hostname)
            if response.status_code > 299:
                logger.warning(f"Failed to remove {old_hostname}: {response.text}")

            if args.log:
                logger.info("=== DONE ===")

            del cached_devices[asset_tag]
            changes_made = True
            time.sleep(3)

        # Add new device or force re-add
        should_add = asset_tag not in cached_devices or args.force

        if should_add:
            # Force deletion if --force flag is set
            if args.force:
                if args.log:
                    logger.info(f"=== Force deleting device {hostname} from LibreNMS ({idx}/{total_devices}) ===")

                response = manager.delete_device(hostname)
                if response.status_code > 299:
                    logger.warning(f"Failed to remove {hostname}: {response.text}")

                if args.log:
                    logger.info("=== DONE ===")
                time.sleep(3)

            # Check if device already exists
            if manager.device_exists(hostname):
                cached_devices[asset_tag] = hostname
                changes_made = True
                continue

            # Add the device
            if args.log:
                logger.info(f"=== Adding device {hostname} to LibreNMS ({idx}/{total_devices}) ===")

            if manager.add_device(hostname):
                cached_devices[asset_tag] = hostname
                changes_made = True
                if args.log:
                    logger.info("=== DONE ===")
            else:
                logger.error(f"Failed to add {hostname}")

    # Save cache if changes were made
    if changes_made:
        save_device_cache(CACHE_FILE, cached_devices)
        if args.log:
            logger.info(f"Synchronization complete. {len(cached_devices)} devices cached.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
