#!/usr/bin/env python
#
# Copyright (c) 2026  Joe Clarke <jclarke@cisco.com>
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
import sys
from pathlib import Path
from typing import Any

import CLEUCreds  # type: ignore
import requests
import xmltodict
from cleu.config import Config as C  # type: ignore
from sparker import MessageType, Sparker  # type: ignore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

PDU_URL = "http://10.13.2.32/api/data.xml"
REQUEST_TIMEOUT = 30
SPARK_ROOM = "Core Alarms"
CACHE_FILE = Path.home() / "server_room_pdu_state.json"


def normalize_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def get_text_value(value: Any) -> str | None:
    if isinstance(value, dict):
        if "#text" in value:
            return str(value["#text"])
        return None
    if isinstance(value, list):
        return get_text_value(value[0]) if value else None
    return str(value) if value is not None else None


def post_alert(spark: Sparker, message: str, severity: MessageType) -> None:
    try:
        spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, message, severity)
    except Exception:
        logger.exception("Failed to send Webex alert")


def load_state() -> dict[str, str]:
    if not CACHE_FILE.exists():
        return {}
    try:
        with CACHE_FILE.open("r") as fd:
            data = json.load(fd)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load state file %s: %s", CACHE_FILE, exc)
    return {}


def save_state(state: dict[str, str]) -> None:
    temp_file = CACHE_FILE.with_suffix(".tmp")
    try:
        with temp_file.open("w") as fd:
            json.dump(state, fd, indent=2)
        temp_file.replace(CACHE_FILE)
    except OSError as exc:
        logger.warning("Failed to save state file %s: %s", CACHE_FILE, exc)
        if temp_file.exists():
            temp_file.unlink()


def check_pdu_health(spark: Sparker, previous_status: str | None) -> tuple[int, str]:
    try:
        response = requests.get(PDU_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
        post_alert(
            spark,
            "CRITICAL: **Timeout** fetching Server Room power source status!  Check to see if the server room still has power!",
            MessageType.BAD,
        )
        logger.error("Timeout or connection error fetching PDU status from %s: %s", PDU_URL, exc)
        return 1, "bad"
    except requests.exceptions.RequestException as exc:
        post_alert(
            spark,
            "WARNING: Failed to fetch Server Room power source status",
            MessageType.WARNING,
        )
        logger.warning("Error fetching PDU status from %s: %s", PDU_URL, exc)
        return 1, "warn"

    try:
        payload = xmltodict.parse(response.text)
    except Exception as exc:
        post_alert(
            spark,
            "WARNING: Failed to parse Server Room power source XML",
            MessageType.WARNING,
        )
        logger.warning("Failed to parse Server Room power source XML from %s: %s", PDU_URL, exc)
        return 1, "warn"

    smart_pdu = payload.get("SmartPDU") if isinstance(payload, dict) else None
    power_sources = []
    for pdu in normalize_list(smart_pdu):
        if not isinstance(pdu, dict):
            continue
        power_sources.extend(normalize_list(pdu.get("PowerSource")))

    if not power_sources:
        post_alert(
            spark,
            "WARNING: Server Room power source status missing from XML payload",
            MessageType.WARNING,
        )
        return 1, "warn"

    missing_health = False
    bad_sources: list[str] = []
    for idx, source in enumerate(power_sources, start=1):
        if not isinstance(source, dict):
            missing_health = True
            continue
        health = get_text_value(source.get("Health"))
        if health is None:
            missing_health = True
            continue
        if health != "Good":
            bad_sources.append(f"PowerSource {idx}: {health}")

    if bad_sources:
        post_alert(
            spark,
            "CRITICAL: Server Room power source health issues: **" + ", ".join(bad_sources) + "**",
            MessageType.BAD,
        )
        return 1, "bad"

    if missing_health:
        post_alert(
            spark,
            "WARNING: Server Room power source health status missing in XML payload",
            MessageType.WARNING,
        )
        return 1, "warn"

    logger.info("Server Room power source health is Good")
    if previous_status and previous_status != "good":
        post_alert(
            spark,
            "Server Room power source health is back to Good",
            MessageType.GOOD,
        )
    return 0, "good"


def main() -> int:
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)
    prev_state = load_state()
    previous_status = prev_state.get("status")
    result, current_status = check_pdu_health(spark, previous_status)
    prev_state["status"] = current_status
    save_state(prev_state)
    return result


if __name__ == "__main__":
    sys.exit(main())
