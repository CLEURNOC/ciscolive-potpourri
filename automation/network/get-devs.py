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

"""Network device reachability monitor with Webex alerting.

This script monitors network devices for reachability changes via ICMP ping
and sends alerts to Webex Teams when devices become unreachable or recover.
"""

import json
import logging
import re
import shutil
import socket
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from multiprocessing import Pool
from multiprocessing.pool import Pool as PoolType
from pathlib import Path
from subprocess import DEVNULL, run
from typing import TypedDict

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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

CACHE_FILE = Path("/home/jclarke/cached_devs.dat")
PING_DEVS_FILE = Path("/home/jclarke/ping-devs.json")
ROOM_NAME = "Device Alarms"
FPING_PATH = "/usr/local/sbin/fping"


class ReachabilityState(str, Enum):
    """Device reachability states."""

    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"


class DeviceDict(TypedDict, total=False):
    """Type definition for device dictionary."""

    name: str
    ip: str
    ipv6: str
    reachability: str
    reachability_v6: str


class MessageTemplate(TypedDict):
    """Type definition for message template."""

    msg: str
    type: MessageType


@dataclass
class DeviceMonitorConfig:
    """Configuration for device monitoring."""

    cache_file: Path
    ping_devs_file: Path
    room_name: str
    fping_path: str
    excluded_patterns: list[str] = field(default_factory=lambda: [r"^VHS-"])
    ping_retries: int = 2
    ping_retry_delay: float = 0.5

    messages: dict[str, MessageTemplate] = field(
        default_factory=lambda: {
            "BAD": {
                "msg": "Pinger detected that device {name} (IP: {ip}){location} is no longer reachable",
                "type": MessageType.BAD,
            },
            "GOOD": {
                "msg": "Pinger has detected that device {name} (IP: {ip}){location} is now reachable again",
                "type": MessageType.GOOD,
            },
        }
    )


@dataclass
class DeviceMonitor:
    """Monitors network device reachability."""

    config: DeviceMonitorConfig
    spark: Sparker
    previous_devices: list[DeviceDict] = field(default_factory=list)
    additional_devices: list[str] = field(default_factory=list)

    @staticmethod
    def _check_state_changed(
        device: DeviceDict,
        prev_devices: list[DeviceDict],
        current_state: ReachabilityState,
        is_ipv6: bool = False,
    ) -> bool:
        """Check if device reachability state changed from previous run.

        Args:
            device: Current device information
            prev_devices: List of devices from previous run
            current_state: Current reachability state
            is_ipv6: Whether checking IPv6 reachability

        Returns:
            True if state changed and message should be sent
        """
        prop = "reachability_v6" if is_ipv6 else "reachability"

        for prev_dev in prev_devices:
            if prev_dev["name"] == device["name"]:
                return prop in prev_dev and prev_dev[prop] != current_state.value

        return False

    @staticmethod
    def _is_known_device(device: DeviceDict, prev_devices: list[DeviceDict]) -> bool:
        """Check if device was seen in previous run.

        Args:
            device: Device to check
            prev_devices: List of devices from previous run

        Returns:
            True if device was previously known
        """
        return any(pd["name"] == device["name"] for pd in prev_devices)

    def _ping_host(self, host: str) -> bool:
        """Ping a host and return reachability status.

        Args:
            host: IP address or hostname to ping

        Returns:
            True if host is reachable
        """
        for attempt in range(self.config.ping_retries):
            result = run(
                [self.config.fping_path, "-q", "-r0", host],
                stdout=DEVNULL,
                stderr=DEVNULL,
                timeout=5,
            )

            if result.returncode == 0:
                return True

            if attempt < self.config.ping_retries - 1:
                time.sleep(self.config.ping_retry_delay)

        return False

    def _should_exclude_device(self, name: str, ip: str) -> bool:
        """Check if device should be excluded from monitoring.

        Args:
            name: Device name
            ip: Device IP address

        Returns:
            True if device should be excluded
        """
        return any(re.search(pattern, name) or re.search(pattern, ip) for pattern in self.config.excluded_patterns)

    def _send_alert(
        self,
        device_name: str,
        ip_address: str,
        location: str,
        is_reachable: bool,
    ) -> None:
        """Send Webex Teams alert for device state change.

        Args:
            device_name: Name of the device
            ip_address: IP address of the device
            location: Location information
            is_reachable: Current reachability state
        """
        msg_key = "GOOD" if is_reachable else "BAD"
        template = self.config.messages[msg_key]

        message = template["msg"].format(
            name=device_name,
            ip=ip_address,
            location=location,
        )

        try:
            self.spark.post_to_spark(
                C.WEBEX_TEAM,
                self.config.room_name,
                message,
                template["type"],
            )
        except Exception as e:
            logger.error(f"Failed to send alert for {device_name}: {e}")

    def ping_device(self, dev: dict[str, str]) -> DeviceDict | None:
        """Ping a device and check reachability, sending alerts on state changes.

        Args:
            dev: Device information dictionary

        Returns:
            Device dictionary with reachability status, or None if excluded
        """
        device: DeviceDict = {
            "name": dev["Hostname"],
            "ip": dev["IPAddress"],
        }

        # Skip invalid or excluded devices
        if device["ip"] == "0.0.0.0":
            return None

        if self._should_exclude_device(device["name"], device["ip"]):
            return None

        location = f" (Location: {dev['LocationDetail']})" if "LocationDetail" in dev else ""

        # Check IPv4 reachability
        is_reachable = self._ping_host(device["ip"])
        device["reachability"] = ReachabilityState.REACHABLE.value if is_reachable else ReachabilityState.UNREACHABLE.value

        # Determine if we should send IPv4 alert
        if is_reachable:
            should_alert = self._check_state_changed(device, self.previous_devices, ReachabilityState.REACHABLE)
        else:
            should_alert = self._is_known_device(device, self.previous_devices)

        if should_alert:
            self._send_alert(device["name"], device["ip"], location, is_reachable)

        # Check IPv6 reachability if available
        if "IPv6Address" in dev:
            device["ipv6"] = dev["IPv6Address"]
            is_reachable_v6 = self._ping_host(device["ipv6"])
            device["reachability_v6"] = ReachabilityState.REACHABLE.value if is_reachable_v6 else ReachabilityState.UNREACHABLE.value

            # Determine if we should send IPv6 alert
            if is_reachable_v6:
                should_alert_v6 = self._check_state_changed(device, self.previous_devices, ReachabilityState.REACHABLE, is_ipv6=True)
            else:
                should_alert_v6 = self._is_known_device(device, self.previous_devices)

            if should_alert_v6:
                self._send_alert(device["name"], device["ipv6"], location, is_reachable_v6)

        return device

    def _resolve_device(self, hostname: str) -> dict[str, str] | None:
        """Resolve device hostname to IP addresses.

        Args:
            hostname: Hostname to resolve

        Returns:
            Device record with IP addresses, or None if resolution failed
        """
        try:
            ipv4 = socket.gethostbyname(hostname)
            addr_info = socket.getaddrinfo(hostname, 0)

            device_rec = {
                "Hostname": hostname,
                "IPAddress": ipv4,
                "Reachable": True,
            }

            # Extract IPv6 addresses if available
            if v6_addrs := [addr for addr in addr_info if addr[0] == socket.AF_INET6]:
                device_rec["IPv6Address"] = v6_addrs[0][4][0]
                device_rec["Reachable_v6"] = True

            return device_rec

        except Exception as e:
            logger.error(f"Failed to resolve {hostname}: {e}")
            try:
                self.spark.post_to_spark(
                    C.WEBEX_TEAM,
                    self.config.room_name,
                    f"Failed to resolve {hostname}: {e}",
                    MessageType.WARNING,
                )
            except Exception as alert_error:
                logger.error(f"Failed to send resolution failure alert: {alert_error}")

            return None

    def get_devices(self, pool: PoolType) -> list[DeviceDict]:
        """Get all devices and check their reachability.

        Args:
            pool: Multiprocessing Pool for parallel pinging

        Returns:
            List of devices with reachability status
        """
        devices: list[DeviceDict] = []
        device_records: list[dict[str, str]] = []

        # Resolve all additional devices
        for hostname in self.additional_devices:
            if device_rec := self._resolve_device(hostname):
                device_records.append(device_rec)

        # Ping all devices in parallel
        if device_records:
            results = [pool.apply_async(self.ping_device, [dev]) for dev in device_records]

            for result in results:
                try:
                    if device := result.get(timeout=60):
                        devices.append(device)
                except Exception as e:
                    logger.error(f"Error getting ping result: {e}")

        return devices


def load_cache(cache_file: Path) -> list[DeviceDict]:
    """Load previous device states from cache file.

    Args:
        cache_file: Path to cache file

    Returns:
        List of previously cached devices
    """
    if not cache_file.exists():
        logger.info(f"Cache file {cache_file} does not exist, starting fresh")
        return []

    try:
        with cache_file.open("r") as fd:
            devices = json.load(fd)
            logger.info(f"Loaded {len(devices)} devices from cache")
            return devices
    except Exception as e:
        logger.error(f"Failed to load cache file {cache_file}: {e}")
        return []


def save_cache_atomic(cache_file: Path, devices: list[DeviceDict]) -> None:
    """Save device states to cache file atomically to prevent truncation.

    Uses atomic write pattern: write to temp file, then replace original.
    Creates backup before replacement.

    Args:
        cache_file: Path to cache file
        devices: List of devices to save
    """
    # Ensure parent directory exists
    cache_file.parent.mkdir(parents=True, exist_ok=True)

    # Create backup of existing cache if it exists
    if cache_file.exists():
        backup_file = cache_file.with_suffix(cache_file.suffix + ".bak")
        try:
            shutil.copy2(cache_file, backup_file)
            logger.debug(f"Created backup at {backup_file}")
        except Exception as e:
            logger.warning(f"Failed to create backup: {e}")

    # Write to temporary file first
    temp_file = cache_file.with_suffix(cache_file.suffix + ".tmp")
    try:
        with temp_file.open("w") as fd:
            json.dump(devices, fd, ensure_ascii=False, indent=4)

        # Verify the temp file is valid JSON
        with temp_file.open("r") as fd:
            json.load(fd)

        # Atomically replace the cache file
        temp_file.replace(cache_file)
        logger.info(f"Successfully saved {len(devices)} devices to cache")

    except Exception as e:
        logger.error(f"Failed to save cache file {cache_file}: {e}")
        # Clean up temp file if it exists
        if temp_file.exists():
            temp_file.unlink()
        raise


def load_additional_devices(ping_devs_file: Path) -> list[str]:
    """Load additional devices to monitor from configuration file.

    Args:
        ping_devs_file: Path to JSON file with device list

    Returns:
        List of device hostnames
    """
    if not ping_devs_file.exists():
        logger.warning(f"Additional devices file {ping_devs_file} does not exist")
        return []

    try:
        with ping_devs_file.open("r") as fd:
            devices = json.load(fd)
            logger.info(f"Loaded {len(devices)} additional devices to monitor")
            return devices
    except Exception as e:
        logger.error(f"Failed to load additional devices from {ping_devs_file}: {e}")
        return []


def main() -> None:
    """Main entry point for device reachability monitoring."""
    logger.info("Starting device reachability monitor")

    # Load configuration
    config = DeviceMonitorConfig(
        cache_file=CACHE_FILE,
        ping_devs_file=PING_DEVS_FILE,
        room_name=ROOM_NAME,
        fping_path=FPING_PATH,
    )

    # Load previous device states
    prev_devices = load_cache(config.cache_file)

    # Initialize Sparker
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    # Load additional devices to monitor
    additional_devices = load_additional_devices(config.ping_devs_file)

    # Create monitor instance
    monitor = DeviceMonitor(
        config=config,
        spark=spark,
        previous_devices=prev_devices,
        additional_devices=additional_devices,
    )

    # Monitor devices
    try:
        with Pool(20) as pool:
            devices = monitor.get_devices(pool)

        # Save results atomically
        save_cache_atomic(config.cache_file, devices)
        logger.info(f"Monitoring completed successfully for {len(devices)} devices")

    except KeyboardInterrupt:
        logger.info("Monitoring interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Monitoring failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
