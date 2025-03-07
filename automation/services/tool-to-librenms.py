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

from __future__ import print_function
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import json
import sys
import time
import re
import traceback
import argparse
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

CACHE_FILE = "/home/jclarke/monitored_devs.json"

LIBRE_HEADERS = {"X-Auth-Token": CLEUCreds.LIBRENMS_TOKEN}


def get_devs():
    url = "http://{}/get/switches/json".format(C.TOOL)

    devs = []
    response = requests.get(url)
    code = 200
    code = response.status_code
    if code == 200:
        j = response.json()

        for dev in j:
            if dev["IPAddress"] == "0.0.0.0" or not dev["Reachable"]:
                continue

            if not re.search(r"^[0-9A-Za-z]{3}-", dev["Hostname"]):
                continue

            if (
                re.search(r".*CORE.*", dev["Hostname"], flags=re.I)
                or re.search(r"^WLC", dev["Hostname"], flags=re.I)
                or re.search(r".*MER[124]-dist.*", dev["Hostname"], flags=re.I)
                or re.search(r".*EDGE.*", dev["Hostname"], flags=re.I)
            ):
                continue

            devs.append(dev)

    return devs


def delete_device(dev):
    global LIBRE_HEADERS

    url = f"https://librenms.{C.DNS_DOMAIN}/api/v0/devices/{dev}"
    resp = requests.delete(url, headers=LIBRE_HEADERS)

    return resp


if __name__ == "__main__":
    devs = {}
    force = False
    changed_devs = False
    do_log = False

    parser = argparse.ArgumentParser(sys.argv[0], "Add devices from the Tool to LibreNMS")
    parser.add_argument("--force", "-f", default=False, help="Force adding devices", action="store_true")
    parser.add_argument("--log", "-l", default=False, help="Log progress (default: False)", action="store_true")

    args = parser.parse_args()
    force = args.force
    do_log = args.log

    try:
        with open(CACHE_FILE, "r") as fd:
            devs = json.load(fd)
    except Exception as e:
        print(f"Failed to open {CACHE_FILE}: {e}")

    tdevs = get_devs()

    i = 0
    for tdev in tdevs:
        i += 1
        if tdev["AssetTag"] in list(devs.keys()) and devs[tdev["AssetTag"]] != tdev["Hostname"]:
            if do_log:
                print("=== Deleting device {} from LibreNMS ({} / {}) ===".format(tdev["Hostname"], i, len(tdevs)))
            res = delete_device(devs[tdev["AssetTag"]])
            if res.status_code > 299:
                print("\n\n***WARNING: Failed to remove LibreNMS device {}: response='{}'".format(devs[tdev["AssetTag"]], res.text))

            if do_log:
                print("=== DONE. ===")
            changed_devs = True
            del devs[tdev["AssetTag"]]
            time.sleep(3)

        if tdev["AssetTag"] not in list(devs.keys()) or force:
            if force:
                if do_log:
                    print("=== Deleting device {} from LibreNMS ({} / {}) ===".format(tdev["Hostname"], i, len(tdevs)))
                res = delete_device(tdev["Hostname"])
                if res.status_code > 299:
                    print("\n\n***WARNING: Failed to remove LibreNMS device {}: response='{}'".format(tdev["Hostname"], res.text))

                if do_log:
                    print("=== DONE. ===")
                time.sleep(3)

            url = f"https://librenms.{C.DNS_DOMAIN}/api/v0/inventory/{tdev['Hostname']}"
            try:
                response = requests.get(url, headers=LIBRE_HEADERS)
                response.raise_for_status()
                devs[tdev["AssetTag"]] = tdev["Hostname"]
                changed_devs = True
                continue
            except requests.exceptions.HTTPError as he:
                if he.response.status_code != 400:
                    print(f"Error retrieving device status for {tdev['Hostname']} from LibreNMS: '{he.response.text}'")
                else:
                    delete_device(tdev["Hostname"])
            except Exception:
                print(f"Error retrieving device status for {tdev['Hostname']} from LibreNMS")
                traceback.print_exc()

            if do_log:
                print("=== Adding device {} to LibreNMS ({} / {}) ===".format(tdev["Hostname"], i, len(tdevs)))
            url = f"https://librenms.{C.DNS_DOMAIN}/api/v0/devices"
            payload = {
                "hostname": tdev["Hostname"],
                "version": "v3",
                "authlevel": "authPriv",
                "authname": "CLEUR",
                "authpass": CLEUCreds.SNMP_AUTH_PASS,
                "authalgo": "sha",
                "cryptopass": CLEUCreds.SNMP_PRIV_PASS,
                "cryptoalgo": "aes",
            }
            res = requests.post(url, headers=LIBRE_HEADERS, json=payload)
            if res.status_code > 299:
                print("\n\n***ERROR: Failed to add {} to LibreNMS: response='{}'".format(tdev["Hostname"], res.text))
                continue

            if do_log:
                print("=== DONE. ===")

            changed_devs = True
            devs[tdev["AssetTag"]] = tdev["Hostname"]

    if changed_devs:
        with open(CACHE_FILE, "w") as fd:
            json.dump(devs, fd)
