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

"""Network Interface Error Monitor.

This script polls network devices via SNMP for interface errors and discards,
tracks error trends over time, and sends Webex notifications when thresholds
are exceeded or errors clear.
"""

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import netsnmp  # type: ignore

import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore
from sparker import MessageType, Sparker  # type: ignore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Constants
CACHE_FILE_BASE = Path("/home/jclarke/errors_cache")
THRESHOLD = 1
WINDOW = 12
REARM = 6
SUPPRESS_TIMER_MINUTES = 15
IF_UP = 1


@dataclass
class InterfaceState:
    """State tracking for a single interface."""

    ifDescr: str = ""
    ifAlias: str = ""
    ifInErrors: str = "0"
    ifOutErrors: str = "0"
    ifInDiscards: str = "0"
    ifOutDiscards: str = "0"
    ifOperStatus: str = "0"
    count: int = 0
    suppressed: bool = False
    suppressed_when: int = 0


@dataclass
class MonitorConfig:
    """Configuration for error monitoring."""

    name: str
    device_file: Path
    webex_room: str
    ignore_interfaces_file: Path | None = None
    ignore_patterns: list[str] = field(default_factory=list)
    no_discards: bool = False
    cache_file: Path = field(init=False)
    suppress_seconds: int = field(init=False)

    def __post_init__(self):
        self.cache_file = CACHE_FILE_BASE.parent / f"{CACHE_FILE_BASE.name}_{self.name}.dat"
        self.suppress_seconds = SUPPRESS_TIMER_MINUTES * 60


def load_json_file(file_path: Path) -> dict | list:
    """Load JSON data from a file.

    Args:
        file_path: Path to JSON file

    Returns:
        Parsed JSON data

    Raises:
        SystemExit: If file cannot be loaded
    """
    try:
        with file_path.open("r") as fd:
            return json.load(fd)
    except Exception as e:
        logger.error(f"Failed to load {file_path}: {e}")
        sys.exit(1)


def load_cache(cache_file: Path) -> dict[str, dict[str, dict]]:
    """Load cached interface state from file.

    Args:
        cache_file: Path to cache file

    Returns:
        Dictionary mapping devices to interface states
    """
    if not cache_file.exists():
        logger.info(f"Cache file {cache_file} does not exist, starting fresh")
        return {}

    try:
        with cache_file.open("r") as fd:
            state = json.load(fd)
            logger.info(f"Loaded cache with {len(state)} devices")
            return state
    except Exception as e:
        logger.error(f"Failed to load cache file {cache_file}: {e}")
        return {}


def save_cache_atomic(cache_file: Path, state: dict) -> None:
    """Save interface state to cache file atomically.

    Args:
        cache_file: Path to cache file
        state: Interface state dictionary
    """
    temp_file = cache_file.with_suffix(".tmp")

    try:
        # Write to temporary file
        with temp_file.open("w") as fd:
            json.dump(state, fd, indent=4)

        # Atomic replace
        temp_file.replace(cache_file)
        logger.debug(f"Saved cache with {len(state)} devices")

    except Exception as e:
        logger.error(f"Failed to save cache file {cache_file}: {e}")
        if temp_file.exists():
            temp_file.unlink()


def poll_device_snmp(
    device: str,
    poll_discards: bool,
) -> dict[str, dict[str, str]]:
    """Poll interface statistics from a device via SNMPv3.

    Args:
        device: Device hostname or IP
        poll_discards: Whether to poll discard counters

    Returns:
        Dictionary mapping interface IDs to their statistics
    """
    interface_data: dict[str, dict[str, str]] = {}

    # Build SNMP variable list
    if poll_discards:
        vars = netsnmp.VarList(
            netsnmp.Varbind("ifDescr"),
            netsnmp.Varbind("ifInErrors"),
            netsnmp.Varbind("ifOutErrors"),
            netsnmp.Varbind("ifInDiscards"),
            netsnmp.Varbind("ifOutDiscards"),
            netsnmp.Varbind("ifAlias"),
            netsnmp.Varbind("ifOperStatus"),
        )
    else:
        vars = netsnmp.VarList(
            netsnmp.Varbind("ifDescr"),
            netsnmp.Varbind("ifInErrors"),
            netsnmp.Varbind("ifOutErrors"),
            netsnmp.Varbind("ifAlias"),
            netsnmp.Varbind("ifOperStatus"),
        )

    try:
        netsnmp.snmpwalk(
            vars,
            Version=3,
            DestHost=device,
            SecLevel="authPriv",
            SecName="CLEUR",
            AuthProto="SHA",
            AuthPass=CLEUCreds.SNMP_AUTH_PASS,
            PrivProto="AES",
            PrivPass=CLEUCreds.SNMP_PRIV_PASS,
        )

        for var in vars:
            if var.iid not in interface_data:
                interface_data[var.iid] = {
                    "count": 0,
                    "suppressed": False,
                    "suppressed_when": 0,
                }
            interface_data[var.iid][var.tag] = var.val

        logger.debug(f"Polled {len(interface_data)} interfaces from {device}")

    except Exception as e:
        logger.error(f"Failed to poll {device} via SNMP: {e}")

    return interface_data


def should_ignore_interface(
    device: str,
    if_descr: str,
    if_alias: str,
    ignore_interfaces: dict[str, list[str]],
    ignore_patterns: list[re.Pattern],
) -> bool:
    """Determine if an interface should be ignored.

    Args:
        device: Device hostname
        if_descr: Interface description
        if_alias: Interface alias
        ignore_interfaces: Mapping of devices to ignored interface names

    Returns:
        True if interface should be ignored
    """
    # Check if the ifDescr is in ignore patterns
    for pattern in ignore_patterns:
        if pattern.search(if_descr):
            return True

    # Check explicit ignore list
    if device in ignore_interfaces and if_descr in ignore_interfaces[device]:
        return True

    # Check for "ignore" in alias
    if re.search(r"ignore", if_alias, re.I):
        return True

    return False


def check_interface_errors(
    device: str,
    if_id: str,
    curr_data: dict[str, str],
    prev_data: dict[str, str],
    now: int,
    config: MonitorConfig,
    spark: Sparker,
    ignore_interfaces: dict[str, list[str]],
    ignore_patterns: list[re.Pattern],
) -> dict[str, str | int | bool]:
    """Check for interface errors and send notifications.

    Args:
        device: Device hostname
        if_id: Interface ID
        curr_data: Current interface data
        prev_data: Previous interface data
        now: Current timestamp
        config: Monitor configuration
        spark: Sparker instance
        ignore_interfaces: Interfaces to ignore
        ignore_patterns: Compiled regex patterns to ignore interfaces

    Returns:
        Updated interface state
    """
    if_descr = curr_data.get("ifDescr", "")
    if_alias = curr_data.get("ifAlias", "")

    # Skip if interface should be ignored
    if should_ignore_interface(device, if_descr, if_alias, ignore_interfaces, ignore_patterns):
        return curr_data

    # Initialize counters from previous state
    if "count" in prev_data:
        curr_data["count"] = prev_data["count"]
    if "suppressed" in prev_data:
        # Check if suppression timer expired
        if prev_data.get("suppressed") and "suppressed_when" in prev_data and now - prev_data["suppressed_when"] >= config.suppress_seconds:
            curr_data["suppressed"] = False
            curr_data["suppressed_when"] = 0
            curr_data["count"] = 0
        else:
            curr_data["suppressed"] = prev_data["suppressed"]

    # Check for error increases
    found_error = False
    for metric, curr_value in curr_data.items():
        # Skip non-counter fields
        if metric in {"ifDescr", "ifAlias", "ifOperStatus", "count", "suppressed", "suppressed_when"}:
            continue

        if metric in prev_data:
            diff = int(curr_value) - int(prev_data[metric])

            if diff >= THRESHOLD:
                found_error = True

                # Send alert if not suppressed and within window
                if curr_data["count"] < WINDOW and not curr_data["suppressed"]:
                    try:
                        spark.post_to_spark(
                            C.WEBEX_TEAM,
                            config.webex_room,
                            f"Interface **{if_descr}** ({if_alias}) on device _{device}_ has seen an increase of **{diff}** {metric} (previous: {prev_data[metric]}, current: {curr_value}).",
                            MessageType.WARNING,
                        )
                    except Exception as e:
                        logger.error(f"Failed to send error notification for {device}/{if_descr}: {e}")

                # Suppress if exceeding window
                elif not curr_data["suppressed"]:
                    curr_data["suppressed"] = True
                    curr_data["suppressed_when"] = now
                    try:
                        spark.post_to_spark(
                            C.WEBEX_TEAM,
                            config.webex_room,
                            f"Suppressing alarms for interface **{if_descr}** ({if_alias}) on device _{device}_ for {SUPPRESS_TIMER_MINUTES} minutes",
                        )
                    except Exception as e:
                        logger.error(f"Failed to send suppression notification for {device}/{if_descr}: {e}")

    # Update error count
    if not found_error:
        if curr_data["count"] > 0:
            curr_data["count"] -= 1

            # Send recovery notification if rearmed
            if curr_data["count"] < REARM and curr_data["suppressed"]:
                try:
                    spark.post_to_spark(
                        C.WEBEX_TEAM,
                        config.webex_room,
                        f"Interface **{if_descr}** ({if_alias}) on device _{device}_ is no longer seeing an increase of errors",
                        MessageType.GOOD,
                    )
                except Exception as e:
                    logger.error(f"Failed to send recovery notification for {device}/{if_descr}: {e}")

                curr_data["suppressed"] = False
                curr_data["suppressed_when"] = 0
    else:
        curr_data["count"] += 1

    return curr_data


def main() -> int:
    """Main entry point for error monitor.

    Returns:
        Exit code (0 for success)
    """
    parser = argparse.ArgumentParser(description="Poll interface errors from network devices via SNMP")
    parser.add_argument(
        "--name",
        "-n",
        metavar="<NAME>",
        help="Name of the poller (used for cache file)",
        required=True,
    )
    parser.add_argument(
        "--device-file",
        "-f",
        type=Path,
        metavar="<DEVICE_FILE>",
        help="Path to JSON file containing device list",
        required=True,
    )
    parser.add_argument(
        "--webex-room",
        "-r",
        metavar="<ROOM_NAME>",
        help="Webex room name for notifications",
        required=True,
    )
    parser.add_argument(
        "--ignore-interfaces-file",
        "-i",
        type=Path,
        metavar="<IGNORE_FILE>",
        help="Path to JSON file mapping devices to ignored interfaces",
    )
    parser.add_argument(
        "--ignore-patterns",
        "-p",
        metavar="<PATTERN>",
        action="append",
        help="Regex pattern to ignore interfaces (can be specified multiple times)",
    )
    parser.add_argument(
        "--no-discards",
        action="store_true",
        help="Skip polling ifIn/OutDiscards (default: discards are polled)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Initialize configuration
    config = MonitorConfig(
        name=args.name,
        device_file=args.device_file,
        webex_room=args.webex_room,
        ignore_interfaces_file=args.ignore_interfaces_file,
        no_discards=args.no_discards,
        ignore_patterns=args.ignore_patterns,
    )

    # Load devices
    devices = load_json_file(config.device_file)
    if not isinstance(devices, list):
        logger.error("Device file must contain a JSON array")
        return 1

    # Load ignore list
    ignore_interfaces: dict[str, list[str]] = {}
    if config.ignore_interfaces_file:
        ignore_interfaces = load_json_file(config.ignore_interfaces_file)

    # Compile ignore patterns
    compiled_patterns: list[re.Pattern] = []
    if config.ignore_patterns:
        for pattern_str in config.ignore_patterns:
            try:
                pattern = re.compile(pattern_str)
                compiled_patterns.append(pattern)
            except re.error as e:
                logger.error(f"Invalid regex pattern '{pattern_str}': {e}")

    # Load previous state
    prev_state = load_cache(config.cache_file)

    # Initialize Sparker
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    # Current state
    curr_state: dict[str, dict[str, dict]] = {}
    now = int(time.time())
    poll_discards = not config.no_discards

    # Poll each device
    for device in devices:
        logger.info(f"Polling {device}")

        interface_data = poll_device_snmp(device, poll_discards)
        curr_state[device] = interface_data

        # Skip if no previous data for this device
        if device not in prev_state:
            continue

        # Check each interface
        for if_id, curr_data in interface_data.items():
            # Skip if no previous data for this interface
            if if_id not in prev_state[device]:
                continue

            # Skip if no interface description
            if "ifDescr" not in curr_data:
                continue

            # Skip if interface is not up
            if "ifOperStatus" not in curr_data or int(curr_data["ifOperStatus"]) != IF_UP:
                continue

            # Ensure ifAlias exists
            if "ifAlias" not in curr_data:
                curr_data["ifAlias"] = ""

            # Check for errors and update state
            curr_state[device][if_id] = check_interface_errors(
                device,
                if_id,
                curr_data,
                prev_state[device][if_id],
                now,
                config,
                spark,
                ignore_interfaces,
                compiled_patterns,
            )

    # Save current state
    save_cache_atomic(config.cache_file, curr_state)

    logger.info("Error monitoring completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
