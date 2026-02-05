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
API, saves them in JSON and Rancid router.db formats, and sends Webex notifications
when the IDF list changes.
"""

import json
import logging
import re
import shutil
import sys
from pathlib import Path

import requests

import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore
from sparker import Sparker  # type: ignore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

OUTPUT_JSON = Path("/home/jclarke/idf-devices.json")
FULL_NAME_OUTPUT_JSON = Path("/home/jclarke/idf-devices-full.json")
OUTPUT_RANCID = Path("/home/jclarke/idf-devices.db")
IDF_PATTERN = re.compile(r"[xX]\d+-")
NOTIFICATION_EMAIL = "jclarke@cisco.com"


def extract_idf_name(hostname: str) -> str | None:
    """Extract IDF name from hostname (first two dash-separated components).

    Example: H01-X013-S0696 -> H01-X013

    Args:
        hostname: Full device hostname

    Returns:
        IDF name (first two components) or None if invalid format
    """
    parts = hostname.split("-")
    if len(parts) >= 2:
        return f"{parts[0]}-{parts[1]}"
    return None


def get_idf_devices() -> tuple[list[str], list[str]]:
    """Retrieve IDF device hostnames from Tool API.

    Returns:
        Tuple of lists: unique IDF names (first two dash-separated components) and full hostnames
    """
    url = f"http://{C.TOOL}/get/switches/json"

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        devices = response.json()
        idf_names: set[str] = set()
        idf_names_full: set[str] = set()

        for device in devices:
            # Skip devices without valid IP or that are unreachable
            if device.get("IPAddress") == "0.0.0.0" or not device.get("Reachable"):
                continue

            # Only include IDF devices (match pattern like X1-, X2-, x10-, etc.)
            if hostname := device.get("Hostname"):
                if IDF_PATTERN.search(hostname):
                    # Extract first two components (e.g., H01-X013)
                    if idf_name := extract_idf_name(hostname):
                        idf_names.add(idf_name)
                        idf_names_full.add(hostname)

        idf_list = sorted(idf_names)
        idf_full_names = sorted(idf_names_full)
        logger.info(f"Retrieved {len(idf_list)} unique IDF devices from Tool API")
        return (idf_list, idf_full_names)

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


def save_rancid_format_atomic(output_file: Path, devices: list[str]) -> None:
    """Save device list in Rancid router.db format atomically.

    Rancid router.db format: hostname;device_type;state
    Example: switch01;cisco;up

    Args:
        output_file: Path to output Rancid format file
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
            for device in sorted(devices):
                # Rancid format: hostname;device_type;state
                fd.write(f"{device};cisco;up\n")

        # Atomically replace the output file
        temp_file.replace(output_file)
        logger.info(f"Successfully saved {len(devices)} devices to {output_file} in Rancid format")

    except Exception as e:
        logger.error(f"Failed to save Rancid format to {output_file}: {e}")
        # Clean up temp file if it exists
        if temp_file.exists():
            temp_file.unlink()
        raise


def load_previous_devices(json_file: Path) -> set[str]:
    """Load previous device list from JSON file.

    Args:
        json_file: Path to JSON file with previous device list

    Returns:
        Set of device hostnames from previous run, empty set if file doesn't exist
    """
    if not json_file.exists():
        return set()

    try:
        with json_file.open("r") as fd:
            devices = json.load(fd)
            return set(devices)
    except Exception as e:
        logger.warning(f"Failed to load previous devices: {e}")
        return set()


def send_change_notification(
    spark: Sparker,
    added: set[str],
    removed: set[str],
    total: int,
) -> None:
    """Send Webex notification about IDF list changes.

    Args:
        spark: Sparker instance for sending messages
        added: Set of newly added devices
        removed: Set of removed devices
        total: Total number of devices in current list
    """
    if not added and not removed:
        return

    message_parts = ["**IDF Device List Change Detected**\n"]
    message_parts.append(f"Total IDF devices: **{total}**\n")

    if added:
        message_parts.append(f"\n**Added ({len(added)}):**")
        for device in sorted(added):
            message_parts.append(f"- {device}")

    if removed:
        message_parts.append(f"\n**Removed ({len(removed)}):**")
        for device in sorted(removed):
            message_parts.append(f"- {device}")

    message = "\n".join(message_parts)

    try:
        spark.post_to_spark(
            team=None,
            room=None,
            msg=message,
            person=NOTIFICATION_EMAIL,
        )
        logger.info(f"Sent change notification to {NOTIFICATION_EMAIL}")
    except Exception as e:
        logger.error(f"Failed to send Webex notification: {e}")


def main() -> None:
    """Main entry point for IDF device collection."""
    try:
        logger.info("Starting IDF device collection")

        # Load previous device list
        previous_devices = load_previous_devices(OUTPUT_JSON)

        # Get current IDF devices
        (idf_devices, idf_full_names) = get_idf_devices()
        current_devices = set(idf_devices)

        # Detect changes
        added_devices = current_devices - previous_devices
        removed_devices = previous_devices - current_devices

        if added_devices or removed_devices:
            logger.info(f"Device list changed: {len(added_devices)} added, " f"{len(removed_devices)} removed")

            # Send Webex notification
            spark = Sparker(token=CLEUCreds.SPARK_TOKEN)
            send_change_notification(
                spark,
                added_devices,
                removed_devices,
                len(idf_devices),
            )
        else:
            logger.info("No changes detected in IDF device list")

        # Save outputs
        save_devices_atomic(OUTPUT_JSON, idf_devices)
        save_devices_atomic(FULL_NAME_OUTPUT_JSON, idf_full_names)
        save_rancid_format_atomic(OUTPUT_RANCID, idf_devices)

        logger.info("IDF device collection completed successfully")

    except KeyboardInterrupt:
        logger.info("Collection interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Collection failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
