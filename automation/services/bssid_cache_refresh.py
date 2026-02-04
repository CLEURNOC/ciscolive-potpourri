#!/usr/bin/env python
#
# Copyright (c) 2025-2026  Joe Clarke <jclarke@cisco.com>
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

"""
Script to refresh the BSSID cache from wireless LAN controllers via NETCONF.

This script queries one or more wireless LAN controllers via NETCONF to retrieve
BSSID to AP name mappings and stores them in a cache file for lookup by other services.

Environment Variables:
    WLCS: Comma-separated list of wireless LAN controller hostnames or IPs
    NETCONF_USERNAME: Username for NETCONF authentication
    NETCONF_PASSWORD: Password for NETCONF authentication
    BSSID_CACHE_FILE: Path to the cache file (default: bssid_cache.json)
"""

import json
import logging
import os
import sys
from pathlib import Path
from cleu.config import Config as C  # type: ignore
import CLEUCreds  # type: ignore

import xmltodict
from ncclient import manager


# Set up logging
logger = logging.getLogger("bssid-cache-refresh")
loglevel = logging.DEBUG if os.getenv("DEBUG", "false").lower() == "true" else logging.INFO
logger.setLevel(loglevel)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False


def _get_bssids_from_netconf(controller: str, bssids: dict[str, str]) -> None:
    """Get the per-WLAN BSSIDs from NETCONF"""

    # NETCONF filter for the radio operational data
    filter_xml = """
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <access-point-oper-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-wireless-access-point-oper">
        <radio-oper-data/>
        <ap-name-mac-map/>
      </access-point-oper-data>
    </filter>
    """

    try:
        with manager.connect(
            host=controller,
            port=830,
            username=CLEUCreds.NET_USER,
            password=CLEUCreds.NET_PASS,
            hostkey_verify=False,
            device_params={"name": "iosxe"},
            timeout=30,
        ) as m:
            # Get the operational data using NETCONF
            netconf_reply = m.get(filter=filter_xml)

            # Convert XML to dict using xmltodict
            data_dict = xmltodict.parse(netconf_reply.xml)
            if not data_dict:
                logger.warning(f"Empty NETCONF response from controller {controller}")
                return

            # Get the AP name to MAC mapping
            ap_name_mac_map = data_dict.get("rpc-reply", {}).get("data", {}).get("access-point-oper-data", {}).get("ap-name-mac-map", {})

            # Ensure it's a list (xmltodict returns single items as dict, not list)
            if isinstance(ap_name_mac_map, dict):
                ap_name_mac_map = [ap_name_mac_map]
            elif not ap_name_mac_map:
                ap_name_mac_map = []

            mac_aps = {}
            for ap in ap_name_mac_map:
                if (ap_name := ap.get("wtp-name")) and (ap_mac := ap.get("wtp-mac")):
                    mac_aps[ap_mac] = ap_name

            # Navigate to the radio-oper-data in the response
            radio_oper_data = data_dict.get("rpc-reply", {}).get("data", {}).get("access-point-oper-data", {}).get("radio-oper-data", [])

            # Ensure it's a list (xmltodict returns single items as dict, not list)
            if isinstance(radio_oper_data, dict):
                radio_oper_data = [radio_oper_data]
            elif not radio_oper_data:
                radio_oper_data = []

            for ap in radio_oper_data:
                if (wtp_mac := ap.get("wtp-mac")) and (vap_config := ap.get("vap-oper-config")):
                    # vap-oper-config won't be present for monitor mode
                    # Ensure vap_config is a list
                    ap_name = mac_aps.get(wtp_mac, "unknown-ap")
                    if isinstance(vap_config, dict):
                        vap_config = [vap_config]
                    bssids.update({mac["bssid-mac"].lower(): ap_name for mac in vap_config})

    except Exception as e:
        logger.warning(f"NETCONF request failed to {controller}: {e}", exc_info=True)
        return


def _load_bssid_cache(cache_file: Path) -> dict[str, str]:
    """Load cached BSSIDs from file.

    Args:
        cache_file: Path to cache file

    Returns:
        Dictionary mapping BSSIDs to AP names
    """
    if not cache_file.exists():
        logger.info(f"Cache file {cache_file} does not exist, starting fresh")
        return {}

    try:
        with cache_file.open("r") as fd:
            bssids = json.load(fd)
            logger.info(f"Loaded cache with {len(bssids)} devices")
            return bssids
    except Exception as e:
        logger.error(f"Failed to load cache file {cache_file}: {e}", exc_info=True)
        return {}


def _save_bssid_cache_atomic(cache_file: Path, bssids: dict) -> None:
    """Save interface state to cache file atomically.

    Args:
        cache_file: Path to cache file
        bssids: BSSID to AP name mapping to save
    """
    temp_file = cache_file.with_suffix(".tmp")

    try:
        # Write to temporary file
        with temp_file.open("w") as fd:
            json.dump(bssids, fd, indent=4)

        # Atomic replace
        temp_file.replace(cache_file)
        logger.info(f"Saved cache with {len(bssids)} devices to {cache_file}")
    except Exception as e:
        logger.error(f"Failed to save cache file {cache_file}: {e}", exc_info=True)
        if temp_file.exists():
            temp_file.unlink()


def refresh_bssid_cache() -> int:
    """Refresh the BSSID cache from the controllers via NETCONF.

    Returns:
        Exit code (0 for success, 1 for error)
    """

    cache_file = Path(C.BSSID_CACHE_FILE)
    bssids = _load_bssid_cache(cache_file)

    for controller in C.WLCS:
        controller = controller.strip()
        if controller:
            logger.info(f"Refreshing BSSID cache from controller: {controller}")
            _get_bssids_from_netconf(controller, bssids)

    _save_bssid_cache_atomic(cache_file, bssids)
    logger.info(f"Successfully refreshed BSSID cache with {len(bssids)} total entries")
    return 0


if __name__ == "__main__":
    sys.exit(refresh_bssid_cache())
