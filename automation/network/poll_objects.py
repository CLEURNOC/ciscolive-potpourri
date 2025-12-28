#!/usr/bin/env python3
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

import json
import logging
import random
import re
import tempfile
import time
from multiprocessing import Pool as _Pool
from multiprocessing.pool import Pool
from pathlib import Path

import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from sparker import MessageType, Sparker  # type: ignore

IDF_FILE = "/home/jclarke/idf-devices.json"
ROOM_NAME = "Core Alarms"
CACHE_FILE = "/home/jclarke/object_counts.json"

logger = logging.getLogger(__name__)


def get_results(dev: str, command: str, cache: dict) -> tuple[dict, list[str]]:
    """Get command results from device using netmiko.

    Returns:
        Tuple of (device metrics dict, list of alert messages)
    """
    device_params = {
        "device_type": "cisco_ios",
        "host": dev,
        "username": CLEUCreds.NET_USER,
        "password": CLEUCreds.NET_PASS,
        "timeout": 10,
        "conn_timeout": 5,
    }

    output = ""

    try:
        with ConnectHandler(**device_params) as ssh_client:
            try:
                output = ssh_client.send_command(command, read_timeout=30)
            except Exception as iie:
                logger.error(f"Failed to get result for {command} from {dev}: {iie}", exc_info=True)
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        logger.error(f"Failed to connect to {dev}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error connecting to {dev}: {e}", exc_info=True)

    dev_obj = {dev: {}}
    alerts = []

    for line in output.split("\n"):
        if m := re.search(r"^(([^:]+):\s+)?([^\s]+):\s(\d+)(,([^:]+):\s(\d+))?", line):
            metric_header = ""
            values = []
            metrics = []
            if m.group(2):
                metric_header = m.group(2).replace("-", "_").replace(" ", "_").lower() + "_"
            metrics.append(metric_header + m.group(3).replace("-", "_").lower())
            values.append(int(m.group(4)))
            if m.group(6):
                metrics.append(metric_header + m.group(6).replace("-", "_").lower())
                values.append(int(m.group(7)))
            for i, metric in enumerate(metrics):
                if metric and metric != "total_objects":
                    value = values[i]
                    if dev in cache and metric in cache[dev] and cache[dev][metric] < value and value > 0:
                        msg = f"Metric **{metric}** has changed from {cache[dev][metric]} to {value} on **{dev}**"
                        alerts.append(msg)

                    dev_obj[dev][metric] = value

    return dev_obj, alerts


def atomic_write_json(filepath: str | Path, data: dict) -> None:
    """Atomically write JSON data to a file to avoid truncation."""
    filepath = Path(filepath)
    # Write to temporary file in same directory to ensure same filesystem
    with tempfile.NamedTemporaryFile(mode="w", dir=filepath.parent, prefix=f".{filepath.name}.", suffix=".tmp", delete=False) as tmp_file:
        json.dump(data, tmp_file, indent=2)
        tmp_path = Path(tmp_file.name)

    # Atomic rename
    tmp_path.replace(filepath)


def get_metrics(pool: Pool) -> tuple[dict, list[str]]:
    """Collect metrics from all devices.

    Returns:
        Tuple of (device metrics dict, list of alert messages)
    """
    response = {}
    all_alerts = []

    cache_path = Path(CACHE_FILE)
    try:
        if cache_path.exists():
            cache = json.loads(cache_path.read_text())
            logger.info(f"Loaded cache with {len(cache)} devices")
        else:
            logger.info("No existing cache found, starting fresh")
            cache = {}
    except Exception as e:
        logger.warning(f"Failed to load cache: {e}")
        cache = {}

    try:
        idfs = json.loads(Path(IDF_FILE).read_text())
        logger.info(f"Polling {len(idfs)} IDF devices")
    except Exception as e:
        logger.error(f"Failed to load IDF file {IDF_FILE}: {e}")
        idfs = []

    results = [pool.apply_async(get_results, [d, "show platform software object-manager switch active f0 statistics", cache]) for d in idfs]
    for res in results:
        dev_obj, alerts = res.get()
        if dev_obj:
            response = response | dev_obj
        all_alerts.extend(alerts)

    logger.info(f"Collected metrics from {len(response)} IDF devices")

    cores = [
        "core1-core",
        "core2-core",
        "core1-wa",
        "core2-wa",
        "core1-edge",
        "core2-edge",
        "core1-nat64",
        "core2-nat64",
        "mer1-dist-a",
        "mer1-dist-b",
        "mer2-dist-a",
        "mer2-dist-b",
        "mer4-dist-a",
        "mer4-dist-b",
    ]

    results = [pool.apply_async(get_results, [d, "show platform software object-manager f0 statistics", cache]) for d in cores]
    collected_cores = 0
    for res in results:
        dev_obj, alerts = res.get()
        if dev_obj:
            response = response | dev_obj
            collected_cores += 1
        all_alerts.extend(alerts)

    logger.info(f"Collected metrics from {collected_cores}/{len(cores)} core devices")

    return response, all_alerts


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    logger.info("Starting object polling")
    time.sleep(random.randrange(90))

    with _Pool(20) as pool:
        response, alerts = get_metrics(pool)

    atomic_write_json(CACHE_FILE, response)
    logger.info(f"Completed polling, wrote {len(response)} device results to {CACHE_FILE}")

    # Send alerts after all data is collected
    if alerts:
        spark = Sparker(token=CLEUCreds.SPARK_TOKEN)
        for msg in alerts:
            spark.post_to_spark(C.WEBEX_TEAM, ROOM_NAME, msg, MessageType.BAD)
        logger.info(f"Sent {len(alerts)} alerts to Webex")
