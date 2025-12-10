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

"""Edge Router Route Table Monitor.

This script monitors routing table changes on edge routers, tracks differences,
optionally commits changes to git, and sends Webex notifications for changes.
"""

import argparse
import json
import logging
import random
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import DEVNULL, run

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

CACHE_DIR = Path("/home/jclarke/routing-tables")
ROUTER_FILE = Path("/home/jclarke/routers.json")
WEBEX_ROOM = "Edge Routing Diffs"

# Regex patterns for output cleanup
PATTERN_CARRIAGE_RETURN = re.compile(r"\r")
PATTERN_ROUTE_SPLIT = re.compile(r"([\d\.]+) (\[[^\n]+)")
PATTERN_VIA_CLEANUP = re.compile(r"(via [\d\.]+), [^,\n]+([,\n])")


@dataclass
class RouteCommand:
    """Configuration for a routing table command."""

    name: str
    command: str


@dataclass
class MonitorConfig:
    """Configuration for route table monitoring."""

    cache_dir: Path
    router_file: Path
    webex_room: str
    git_repo: Path | None = None
    git_branch: str | None = None
    notify_routers: list[str] = field(default_factory=list)

    commands: list[RouteCommand] = field(
        default_factory=lambda: [
            RouteCommand("ip_route", "show ip route"),
            RouteCommand("ipv6_route", "show ipv6 route"),
        ]
    )


@dataclass
class RouterConnection:
    """Router connection parameters."""

    hostname: str
    ip: str
    username: str
    password: str
    device_type: str = "cisco_ios"
    timeout: int = 60


def load_routers(router_file: Path) -> dict[str, str]:
    """Load router inventory from JSON file.

    Args:
        router_file: Path to JSON file with router inventory

    Returns:
        Dictionary mapping router hostnames to IP addresses
    """
    try:
        with router_file.open("r") as fd:
            routers = json.load(fd)
            logger.info(f"Loaded {len(routers)} routers from {router_file}")
            return routers
    except Exception as e:
        logger.error(f"Failed to load routers file {router_file}: {e}")
        raise


def clean_route_output(output: str) -> str:
    """Clean and normalize routing table output.

    Args:
        output: Raw command output from router

    Returns:
        Cleaned output with normalized formatting
    """
    # Remove carriage returns
    output = PATTERN_CARRIAGE_RETURN.sub("", output)
    # Split routes onto separate lines for better diffs
    output = PATTERN_ROUTE_SPLIT.sub(r"\1\n          \2", output)
    # Remove timestamps from 'via' lines
    output = PATTERN_VIA_CLEANUP.sub(r"\1\2", output)
    return output


def get_routing_table(
    connection: RouterConnection,
    command: RouteCommand,
) -> str | None:
    """Retrieve routing table from router using netmiko.

    Args:
        connection: Router connection parameters
        command: Routing command to execute

    Returns:
        Cleaned routing table output, or None if failed
    """
    device_params = {
        "device_type": connection.device_type,
        "host": connection.ip,
        "username": connection.username,
        "password": connection.password,
        "timeout": connection.timeout,
        "session_log": None,
    }

    try:
        with ConnectHandler(**device_params) as ssh:
            logger.debug(f"Connected to {connection.hostname} ({connection.ip})")
            output = ssh.send_command(command.command, read_timeout=90)

            if len(output) < 600:
                logger.warning(f"Truncated output from {connection.hostname} for {command.name} " f"({len(output)} bytes)")
                return None

            return clean_route_output(output)

    except NetmikoTimeoutException:
        logger.error(f"Connection timeout to {connection.hostname} ({connection.ip})")
        return None
    except NetmikoAuthenticationException:
        logger.error(f"Authentication failed for {connection.hostname} ({connection.ip})")
        return None
    except Exception as e:
        logger.error(f"Failed to get {command.name} from {connection.hostname}: {e}")
        return None


def compare_and_save(
    router: str,
    command_name: str,
    output: str,
    cache_dir: Path,
) -> tuple[bool, str]:
    """Compare new routing table with previous and save.

    Args:
        router: Router hostname
        command_name: Command name (used in filename)
        output: Cleaned routing table output
        cache_dir: Directory for cache files

    Returns:
        Tuple of (changed, diff_output)
    """
    cache_dir.mkdir(parents=True, exist_ok=True)

    file_base = cache_dir / f"{command_name}-{router}"
    curr_path = file_base.with_suffix(".curr")
    prev_path = file_base.with_suffix(".prev")

    # Write current output
    with curr_path.open("w") as fd:
        fd.write(output)

    changed = False
    diff_output = ""

    # Compare with previous if it exists
    if prev_path.exists():
        result = run(
            ["diff", "-b", "-B", "-w", "-u", str(prev_path), str(curr_path)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            changed = True
            # Remove cache_dir prefix from diff output for cleaner display
            diff_output = result.stdout.replace(f"{cache_dir}/", "")

    # Move current to previous for next run
    curr_path.replace(prev_path)

    return changed, diff_output


def commit_to_git(
    file_path: Path,
    git_repo: Path,
    message: str = "Routing table update",
) -> bool:
    """Commit routing table file to git repository.

    Args:
        file_path: Path to file to commit
        git_repo: Path to git repository
        message: Commit message

    Returns:
        True if commit successful
    """
    if not git_repo.is_dir():
        logger.error(f"Git repo {git_repo} is not a directory")
        return False

    try:
        # Copy file to git repo
        git_file = git_repo / file_path.with_suffix(".txt").name
        shutil.copyfile(file_path, git_file)

        # Git add and commit
        run(
            ["git", "add", git_file.name],
            cwd=git_repo,
            check=True,
            stdout=DEVNULL,
            stderr=DEVNULL,
        )
        run(
            ["git", "commit", "-m", message, git_file.name],
            cwd=git_repo,
            check=True,
            stdout=DEVNULL,
            stderr=DEVNULL,
        )

        return True

    except Exception as e:
        logger.error(f"Failed to commit to git repo {git_repo}: {e}")
        return False


def push_to_git(git_repo: Path, branch: str) -> bool:
    """Push git commits to remote repository.

    Args:
        git_repo: Path to git repository
        branch: Branch name to push

    Returns:
        True if push successful
    """
    try:
        # Pull first to avoid conflicts
        run(
            ["git", "pull", "origin", branch],
            cwd=git_repo,
            check=True,
            stdout=DEVNULL,
            stderr=DEVNULL,
        )

        # Push changes
        result = run(
            ["git", "push", "origin", branch],
            cwd=git_repo,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.error(f"Failed to push to git: {result.stderr}")
            return False

        logger.info(f"Successfully pushed to git branch {branch}")
        return True

    except Exception as e:
        logger.error(f"Failed to push to git: {e}")
        return False


def should_notify(router: str, notify_list: list[str]) -> bool:
    """Determine if notifications should be sent for this router.

    Args:
        router: Router hostname
        notify_list: List of routers to notify on (empty = notify all)

    Returns:
        True if should send notification
    """
    return not notify_list or router in notify_list


def process_router(
    router: str,
    ip: str,
    config: MonitorConfig,
    spark: Sparker,
) -> bool:
    """Process routing tables for a single router.

    Args:
        router: Router hostname
        ip: Router IP address
        config: Monitor configuration
        spark: Sparker instance for notifications

    Returns:
        True if any changes committed to git
    """
    connection = RouterConnection(
        hostname=router,
        ip=ip,
        username=CLEUCreds.NET_USER,
        password=CLEUCreds.NET_PASS,
    )

    git_commits = False

    for command in config.commands:
        logger.info(f"Checking {command.name} on {router}")

        output = get_routing_table(connection, command)
        if not output:
            continue

        changed, diff_output = compare_and_save(
            router,
            command.name,
            output,
            config.cache_dir,
        )

        if changed:
            logger.info(f"Detected changes in {command.name} on {router}")

            # Send Webex notification
            if should_notify(router, config.notify_routers):
                try:
                    spark.post_to_spark(
                        C.WEBEX_TEAM,
                        config.webex_room,
                        f"Routing table diff ({command.command}) on **{router}**:\n```\n{diff_output}\n```",
                        MessageType.BAD,
                    )
                    time.sleep(1)  # Rate limiting
                except Exception as e:
                    logger.error(f"Failed to send Webex notification: {e}")

            # Commit to git if configured
            if config.git_repo:
                prev_path = config.cache_dir / f"{command.name}-{router}.prev"
                if commit_to_git(prev_path, config.git_repo):
                    git_commits = True

    return git_commits


def main() -> int:
    """Main entry point for routing table monitor.

    Returns:
        Exit code (0 for success)
    """
    parser = argparse.ArgumentParser(description="Monitor routing table changes on edge routers")
    parser.add_argument(
        "--router-file",
        type=Path,
        default=Path(__file__).parent / "routers.json",
        help="JSON file with router inventory (default: routers.json)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("/var/tmp/route-table-cache"),
        help="Directory for cache files (default: /var/tmp/route-table-cache)",
    )
    parser.add_argument(
        "--git-repo",
        type=Path,
        help="Git repository path for commits (optional)",
    )
    parser.add_argument(
        "--git-branch",
        default="master",
        help="Git branch name (default: master)",
    )
    parser.add_argument(
        "--webex-room",
        default="Core Alarms",
        help="Webex room name for notifications (default: Core Alarms)",
    )
    parser.add_argument(
        "--notify-routers",
        nargs="*",
        default=[],
        help="Only notify for these routers (default: all routers)",
    )
    parser.add_argument(
        "--jitter",
        type=int,
        default=150,
        help="Maximum random startup delay in seconds (default: 150)",
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

    # Random startup jitter to avoid thundering herd
    if args.jitter > 0:
        delay = random.randrange(args.jitter)
        logger.info(f"Sleeping for {delay} seconds (startup jitter)")
        time.sleep(delay)

    # Load router inventory
    try:
        routers = load_routers(args.router_file)
    except Exception:
        return 1

    # Configure monitoring
    config = MonitorConfig(
        cache_dir=args.cache_dir,
        router_file=args.router_file,
        git_repo=args.git_repo,
        git_branch=args.git_branch,
        webex_room=args.webex_room,
        notify_routers=args.notify_routers,
        commands=[
            RouteCommand(name="ip-route", command="show ip route"),
            RouteCommand(name="ipv6-route", command="show ipv6 route"),
        ],
    )

    # Initialize Sparker for Webex notifications
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    # Track if we need to push to git
    git_commits = False

    # Process each router
    for router, ip in routers.items():
        try:
            if process_router(router, ip, config, spark):
                git_commits = True
        except Exception as e:
            logger.error(f"Failed to process router {router}: {e}")
            continue

    # Push git commits if any were made
    if git_commits and config.git_repo:
        push_to_git(config.git_repo, config.git_branch)

    logger.info("Routing table monitoring completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
