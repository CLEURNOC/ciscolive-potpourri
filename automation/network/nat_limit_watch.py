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

"""NAT Limit Monitor.

This script monitors NAT connection limit violations on edge routers and
sends Webex notifications when hosts exceed their limits or age out.
"""

import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from sparker import MessageType, Sparker  # type: ignore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

SPARK_ROOM = "Core Alarms"
CACHE_FILE = Path("/home/jclarke/nat_limit.dat")

# Regex pattern for parsing NAT limit output
PATTERN_NAT_LIMIT = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+(\d+)")


@dataclass
class NATMonitorConfig:
    """Configuration for NAT limit monitoring."""

    cache_file: Path
    spark_room: str
    routers: dict[str, str] = field(
        default_factory=lambda: {
            # "CORE1-EDGE": "cisco_ios",
            # "CORE2-EDGE": "cisco_ios",
            "CORE1-NAT64": "cisco_ios",
            "CORE2-NAT64": "cisco_ios",
        }
    )


@dataclass
class RouterConnection:
    """Router connection parameters."""

    hostname: str
    username: str
    password: str
    device_type: str = "cisco_ios"
    timeout: int = 60


def load_cache(cache_file: Path) -> dict[str, int]:
    """Load cached NAT limit state from file.

    Args:
        cache_file: Path to cache file

    Returns:
        Dictionary mapping host IPs to miss counts
    """
    if not cache_file.exists():
        logger.info(f"Cache file {cache_file} does not exist, starting fresh")
        return {}

    try:
        with cache_file.open("r") as fd:
            state = json.load(fd)
            logger.info(f"Loaded {len(state)} hosts from cache")
            return state
    except Exception as e:
        logger.error(f"Failed to load cache file {cache_file}: {e}")
        return {}


def save_cache_atomic(cache_file: Path, state: dict[str, int]) -> None:
    """Save NAT limit state to cache file atomically.

    Args:
        cache_file: Path to cache file
        state: Dictionary mapping host IPs to miss counts
    """
    temp_file = cache_file.with_suffix(".tmp")

    try:
        # Write to temporary file
        with temp_file.open("w") as fd:
            json.dump(state, fd, indent=4)

        # Atomic replace
        temp_file.replace(cache_file)
        logger.debug(f"Saved {len(state)} hosts to cache")

    except Exception as e:
        logger.error(f"Failed to save cache file {cache_file}: {e}")
        if temp_file.exists():
            temp_file.unlink()


def get_nat_limits(connection: RouterConnection) -> dict[str, int]:
    """Retrieve NAT limit violations from router.

    Args:
        connection: Router connection parameters

    Returns:
        Dictionary mapping host IPs to miss counts
    """
    device_params = {
        "device_type": connection.device_type,
        "host": connection.hostname,
        "username": connection.username,
        "password": connection.password,
        "timeout": connection.timeout,
    }

    nat_violations = {}

    try:
        with ConnectHandler(**device_params) as ssh:
            logger.debug(f"Connected to {connection.hostname}")
            output = ssh.send_command(
                "show ip nat limit all-host | inc [0-9] +[1-9][0-9]+[^0-9]+$",
                read_timeout=30,
            )

            for line in output.splitlines():
                if match := PATTERN_NAT_LIMIT.match(line.strip()):
                    host = match.group(1)
                    misses = int(match.group(2))
                    nat_violations[host] = misses
                    logger.debug(f"Found NAT limit violation: {host} with {misses} misses")

    except NetmikoTimeoutException:
        logger.error(f"Connection timeout to {connection.hostname}")
    except NetmikoAuthenticationException:
        logger.error(f"Authentication failed for {connection.hostname}")
    except Exception as e:
        logger.error(f"Failed to get NAT limits from {connection.hostname}: {e}")

    return nat_violations


def notify_new_violations(
    spark: Sparker,
    room: str,
    prev_state: dict[str, int],
    curr_state: dict[str, int],
) -> None:
    """Send notifications for new NAT limit violations.

    Args:
        spark: Sparker instance
        room: Webex room name
        prev_state: Previous state from cache
        curr_state: Current state from routers
    """
    for host, misses in curr_state.items():
        if host not in prev_state:
            logger.info(f"New NAT limit violation: {host} with {misses} misses")
            try:
                spark.post_to_spark(
                    C.WEBEX_TEAM,
                    room,
                    f"Host **{host}** has exceeded its NAT connection limit **{misses}** times",
                    MessageType.BAD,
                )
            except Exception as e:
                logger.error(f"Failed to send Webex notification for {host}: {e}")


def notify_aged_out(
    spark: Sparker,
    room: str,
    prev_state: dict[str, int],
    curr_state: dict[str, int],
) -> None:
    """Send notifications for hosts that aged out.

    Args:
        spark: Sparker instance
        room: Webex room name
        prev_state: Previous state from cache
        curr_state: Current state from routers
    """
    for host in prev_state:
        if host not in curr_state:
            logger.info(f"Host {host} aged out of NAT limit table")
            try:
                spark.post_to_spark(
                    C.WEBEX_TEAM,
                    room,
                    f"Host **{host}** has aged out of the NAT limit exceeded table",
                    MessageType.GOOD,
                )
            except Exception as e:
                logger.error(f"Failed to send Webex notification for {host}: {e}")


def main() -> int:
    """Main entry point for NAT limit monitor.

    Returns:
        Exit code (0 for success)
    """
    config = NATMonitorConfig(
        cache_file=CACHE_FILE,
        spark_room=SPARK_ROOM,
    )

    # Load previous state
    prev_state = load_cache(config.cache_file)

    # Initialize Sparker
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    # Collect current state from all routers
    curr_state: dict[str, int] = {}

    for router, device_type in config.routers.items():
        logger.info(f"Checking NAT limits on {router} (type: {device_type})")

        connection = RouterConnection(
            hostname=router,
            username=CLEUCreds.NET_USER,
            password=CLEUCreds.NET_PASS,
            device_type=device_type,
        )

        violations = get_nat_limits(connection)
        curr_state.update(violations)

        logger.info(f"Found {len(violations)} violations on {router}")

    # Send notifications for new violations
    notify_new_violations(spark, config.spark_room, prev_state, curr_state)

    # Send notifications for aged out hosts
    notify_aged_out(spark, config.spark_room, prev_state, curr_state)

    # Save current state
    save_cache_atomic(config.cache_file, curr_state)

    logger.info("NAT limit monitoring completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
