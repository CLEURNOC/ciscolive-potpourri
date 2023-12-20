#!/usr/bin/env python
#
# Copyright (c) 2017-2024  Joe Clarke <jclarke@cisco.com>
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
import netsnmp  # type: ignore
import os
import json
import argparse
import sys
from sparker import Sparker, MessageType  # type: ignore
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

CACHE_FILE = "/home/jclarke/errors_cache"
THRESHOLD = 1
WINDOW = 12
REARM = 6

IF_UP = 1

prev_state = {}
curr_state = {}


def main():
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Poll errors from network devices")
    parser.add_argument(
        "--name",
        "-n",
        metavar="<NAME>",
        help="Name of the poller",
        required=True,
    )
    parser.add_argument(
        "--device-file",
        "-f",
        metavar="<DEVICE_FILE>",
        help="Path to the JSON file containing the devices to poll",
        required=True,
    )
    parser.add_argument("--webex-room", "-r", metavar="<ROOM_NAME>", help="Name of Webex room to send alerts to", required=True)
    parser.add_argument(
        "--ignore-interfaces-file", "-i", metavar="<IGNORE_FILE>", help="Path to JSON file that maps devices and interfaces to ignore"
    )
    parser.add_argument("--no-discards", help="Poll ifIn/OutDiscards (default: discards are polled)", action="store_true")
    args = parser.parse_args()

    devices = None
    try:
        with open(args.device_file) as fd:
            devices = json.load(fd)
    except Exception as e:
        print("ERROR: Failed to load device file {}: {}".format(args.device_file, getattr(e, "message", repr(e))))
        sys.exit(1)

    ignore_interfaces = {}

    if args.ignore_interfaces_file:
        try:
            with open(args.ignore_interfaces_file) as fd:
                ignore_interfaces = json.load(fd)
        except Exception as e:
            print(
                "ERROR: Failed to load the ignore interfaces file {}: {}".format(
                    args.ignore_interfaces_file, getattr(e, "message", repr(e))
                )
            )
            sys.exit(1)

    cache_file = CACHE_FILE + "_" + args.name + ".dat"

    if os.path.exists(cache_file):
        with open(cache_file, "r") as fd:
            prev_state = json.load(fd)

    for device in devices:
        swent = {}

        if not args.no_discards:
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
            if var.iid not in swent:
                swent[var.iid] = {}
                swent[var.iid]["count"] = 0
                swent[var.iid]["suppressed"] = False

            swent[var.iid][var.tag] = var.val

        curr_state[device] = swent
        if device not in prev_state:
            continue

        for ins, vard in list(curr_state[device].items()):
            if ins not in prev_state[device]:
                continue
            if "ifDescr" not in vard:
                continue
            if "ifOperStatus" not in vard or int(vard["ifOperStatus"]) != IF_UP:
                continue
            if "ifAlias" not in vard:
                vard["ifAlias"] = ""
            if "count" in prev_state[device][ins]:
                curr_state[device][ins]["count"] = prev_state[device][ins]["count"]

            if "suppressed" in prev_state[device][ins]:
                curr_state[device][ins]["suppressed"] = prev_state[device][ins]["suppressed"]
            if_descr = vard["ifDescr"]
            if_alias = vard["ifAlias"]
            if device in ignore_interfaces and if_descr in ignore_interfaces[device]:
                continue
            found_error = False
            for k, v in list(vard.items()):
                if k == "ifDescr" or k == "ifAlias" or k == "count" or k == "suppressed":
                    continue
                if k in prev_state[device][ins]:
                    diff = int(v) - int(prev_state[device][ins][k])
                    if diff >= THRESHOLD:
                        found_error = True
                        if curr_state[device][ins]["count"] < WINDOW and not curr_state[device][ins]["suppressed"]:
                            spark.post_to_spark(
                                C.WEBEX_TEAM,
                                args.webex_room,
                                "Interface **{}** ({}) on device _{}_ has seen an increase of **{}** {} since the last poll (previous: {}, current: {}).".format(
                                    if_descr, if_alias, device, diff, k, prev_state[device][ins][k], v
                                ),
                                MessageType.WARNING,
                            )
                        elif not curr_state[device][ins]["suppressed"]:
                            curr_state[device][ins]["suppressed"] = True
                            spark.post_to_spark(
                                C.WEBEX_TEAM,
                                args.webex_room,
                                "Suppressing alarms for interface **{}** ({}) on device _{}_".format(if_descr, if_alias, device),
                            )
            if not found_error:
                if curr_state[device][ins]["count"] > 0:
                    curr_state[device][ins]["count"] -= 1
                    if curr_state[device][ins]["count"] < REARM and curr_state[device][ins]["suppressed"]:
                        spark.post_to_spark(
                            C.WEBEX_TEAM,
                            args.webex_room,
                            "Interface **{}** ({}) on device _{}_ is no longer seeing an increase of errors".format(
                                if_descr, if_alias, device
                            ),
                            MessageType.GOOD,
                        )
                        curr_state[device][ins]["suppressed"] = False
            else:
                curr_state[device][ins]["count"] += 1

    with open(cache_file, "w") as fd:
        json.dump(curr_state, fd, indent=4)


if __name__ == "__main__":
    main()
