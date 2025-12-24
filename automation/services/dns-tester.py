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

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import CLEUCreds  # type: ignore
import dns.rcode
import dns.resolver
from cleu.config import Config as C  # type: ignore
from sparker import MessageType, Sparker  # type: ignore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Constants
SPARK_ROOM = "DNS Alarms"
CACHE_FILE = Path.home() / "dns_cache.dat"
DNS_TIMEOUT = 2
DNS_LIFETIME = 2


@dataclass
class DNSTestConfig:
    """Configuration for DNS testing."""

    servers: list[str]
    targets: list[str]
    query_types: tuple[str, ...] = ("A", "AAAA")


@dataclass
class DNSState:
    """DNS test state tracking."""

    results: dict[str, dict[str, dict[str, bool]]] = field(default_factory=dict)

    def get_status(self, server: str, target: str, query_type: str) -> bool | None:
        """Get the status for a specific DNS query."""
        return self.results.get(server, {}).get(target, {}).get(query_type)

    def set_status(self, server: str, target: str, query_type: str, status: bool) -> None:
        """Set the status for a specific DNS query."""
        if server not in self.results:
            self.results[server] = {}
        if target not in self.results[server]:
            self.results[server][target] = {}
        self.results[server][target][query_type] = status


def report_error(server: str, addr: str, query_type: str, error_obj: Any) -> None:
    """Report DNS resolution error to Webex."""
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    msg = f"DNS failure to {server} for {query_type} query for {addr}\n\n```\n{error_obj}\n```"

    if not spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, msg, MessageType.BAD):
        logger.error("Failed to post error message to Webex")


def report_good(msg: str) -> None:
    """Report DNS resolution success to Webex."""
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    if not spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, msg, MessageType.GOOD):
        logger.error("Failed to post success message to Webex")


def load_previous_state() -> DNSState:
    """Load previous DNS test state from cache file."""
    if not CACHE_FILE.exists():
        return DNSState()

    try:
        with CACHE_FILE.open("r") as fd:
            data = json.load(fd)
            return DNSState(results=data)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load previous state from {CACHE_FILE}: {e}")
        return DNSState()


def save_current_state(state: DNSState) -> None:
    """
    Save current DNS test state to cache file atomically.

    Uses atomic write (write to temp file, then rename) to prevent
    truncation or corruption if interrupted during write.
    """
    temp_file = CACHE_FILE.with_suffix(".tmp")
    try:
        # Write to temporary file first
        with temp_file.open("w") as fd:
            json.dump(state.results, fd, indent=2)
            fd.flush()  # Ensure data is written to disk

        # Atomically replace the old file with the new one
        temp_file.replace(CACHE_FILE)
    except OSError as e:
        logger.error(f"Failed to save state to {CACHE_FILE}: {e}")
        # Clean up temp file if it exists
        if temp_file.exists():
            try:
                temp_file.unlink()
            except OSError:
                pass


def create_resolver(nameserver: str) -> dns.resolver.Resolver:
    """Create a DNS resolver with specified configuration."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    resolver.nameservers = [nameserver]
    return resolver


def test_dns_query(
    resolver: dns.resolver.Resolver,
    server: str,
    target: str,
    query_type: str,
    prev_state: DNSState,
    curr_state: DNSState,
) -> None:
    """
    Test a single DNS query and update state.

    Args:
        resolver: DNS resolver to use
        server: DNS server being tested
        target: Target hostname to resolve
        query_type: DNS query type (A, AAAA, etc.)
        prev_state: Previous test state
        curr_state: Current test state to update
    """
    try:
        ans = resolver.resolve(target, query_type)
        success = ans.response.rcode() == dns.rcode.NOERROR
        curr_state.set_status(server, target, query_type, success)

        prev_status = prev_state.get_status(server, target, query_type)

        if not success and prev_status:
            # Failure after previous success
            report_error(server, target, query_type, ans.response)
        elif success and prev_status is False:
            # Success after previous failure
            report_good(f"{server} is now resolving a {query_type} record for {target} correctly")

    except Exception as e:
        curr_state.set_status(server, target, query_type, False)
        prev_status = prev_state.get_status(server, target, query_type)

        if prev_status:
            # Failure after previous success
            report_error(server, target, query_type, e)


def test_dns_servers(config: DNSTestConfig, prev_state: DNSState) -> DNSState:
    """
    Test DNS resolution for all configured servers and targets.

    Args:
        config: DNS test configuration
        prev_state: Previous test state for comparison

    Returns:
        Current test state
    """
    curr_state = DNSState()

    for server in config.servers:
        resolver = create_resolver(server)

        for target in config.targets:
            for query_type in config.query_types:
                test_dns_query(resolver, server, target, query_type, prev_state, curr_state)

    return curr_state


def main() -> None:
    """Main execution function."""
    # DNS server configurations
    dns_servers = [
        "10.100.253.6",
        "10.100.254.6",
        "2a11:d940:2:64fd::6",
        "2a11:d940:2:64fe::6",
    ]

    dns64_servers = [
        "10.100.253.64",
        "10.100.254.64",
        "2a11:d940:2:64fd::100",
        "2a11:d940:2:64fe::100",
    ]

    # Target configurations
    regular_targets = [f"cl-freebsd.{C.DNS_DOMAIN}", "google.com"]
    dns64_targets = ["github.com", "slack.com"]

    # Load previous state
    prev_state = load_previous_state()

    # Test regular DNS servers (A and AAAA records)
    regular_config = DNSTestConfig(
        servers=dns_servers,
        targets=regular_targets,
        query_types=("A", "AAAA"),
    )
    curr_state = test_dns_servers(regular_config, prev_state)

    # Test DNS64 servers (AAAA records only)
    dns64_config = DNSTestConfig(
        servers=dns64_servers,
        targets=dns64_targets,
        query_types=("AAAA",),
    )

    # Test DNS64 servers and merge results
    dns64_state = test_dns_servers(dns64_config, prev_state)
    curr_state.results.update(dns64_state.results)

    # Save current state
    save_current_state(curr_state)


if __name__ == "__main__":
    main()
