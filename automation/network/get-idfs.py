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

"""IDF Device Collector.

This script retrieves IDF (Intermediate Distribution Frame) devices from the Tool
API and saves them to a JSON file for use by other automation scripts.
"""

import json
import logging
import re
import shutil
import sys
from pathlib import Path

import requests
from cleu.config import Config as C  # type: ignore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

OUTPUT = Path("/home/jclarke/idf-devices.json")
IDF_PATTERN = re.compile(r"[xX]\d+-")


def get_idf_devices() -> list[str]:
    """Retrieve IDF device hostnames from Tool API.

    Returns:
        List of IDF device hostnames that are reachable with valid IP addresses
    """
    url = f"http://{C.TOOL}/get/switches/json"

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        devices = response.json()
        idf_devices: list[str] = []

        for device in devices:
            # Skip devices without valid IP or that are unreachable
            if device.get("IPAddress") == "0.0.0.0" or not device.get("Reachable"):
                continue

            # Only include IDF devices (match pattern like X1-, X2-, x10-, etc.)
            if hostname := device.get("Hostname"):
                if IDF_PATTERN.search(hostname):
                    idf_devices.append(hostname)

        logger.info(f"Retrieved {len(idf_devices)} IDF devices from Tool API")
        return idf_devices

    except requests.RequestException as e:
        logger.error(f"Failed to retrieve devices from Tool API: {e}")
        raise
    except (KeyError, ValueError) as e:
        logger.error(f"Failed to parse device data: {e}")
        raise


def save_devices_atomic(output_file: Path, devices: list[str]) -> None:
    """Save device list to file atomically to prevent truncation.

    Uses atomic write pattern: write to temp file, validate, then replace original.
    Creates backup before replacement.

    Args:
        output_file: Path to output JSON file
        devices: List of device hostnames to save
    """
    # Ensure parent directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Create backup of existing file if it exists
    if output_file.exists():
        backup_file = output_file.with_suffix(output_file.suffix + ".bak")
        try:
            shutil.copy2(output_file, backup_file)
            logger.debug(f"Created backup at {backup_file}")
        except Exception as e:
            logger.warning(f"Failed to create backup: {e}")

    # Write to temporary file first
    temp_file = output_file.with_suffix(output_file.suffix + ".tmp")
    try:
        with temp_file.open("w") as fd:
            json.dump(devices, fd, indent=2, ensure_ascii=False)

        # Verify the temp file is valid JSON
        with temp_file.open("r") as fd:
            json.load(fd)

        # Atomically replace the output file
        temp_file.replace(output_file)
        logger.info(f"Successfully saved {len(devices)} devices to {output_file}")

    except Exception as e:
        logger.error(f"Failed to save devices to {output_file}: {e}")
        # Clean up temp file if it exists
        if temp_file.exists():
            temp_file.unlink()
        raise


def main() -> None:
    """Main entry point for IDF device collection."""
    try:
        logger.info("Starting IDF device collection")
        idf_devices = get_idf_devices()
        save_devices_atomic(OUTPUT, idf_devices)
        logger.info("IDF device collection completed successfully")

    except KeyboardInterrupt:
        logger.info("Collection interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Collection failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
