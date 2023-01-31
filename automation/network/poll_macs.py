#!/usr/bin/env python
#
# Copyright (c) 2017-2023  Joe Clarke <jclarke@cisco.com>
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

from builtins import str
from builtins import range
import os
import re
import sys
import time
import json
import paramiko
from multiprocessing import Pool
import traceback
import CLEUCreds  # type: ignore


CACHE_FILE = "/home/jclarke/mac_counts.dat"
CACHE_FILE_TMP = CACHE_FILE + ".tmp"
IDF_FILE = "/home/jclarke/idf-devices.json"

commands = {
    "macCore": {
        "command": "show mac address-table count | inc Dynamic Address Count",
        "pattern": r"Dynamic Address Count:\s+(\d+)",
        "metric": "totalMacs",
    },
    "macIdf": {
        "command": "show mac address-table dynamic | inc Total",
        "pattern": r"Total.*: (\d+)",
        "metric": "totalMacs",
    },
    "arpEntries": {
        "command": "show ip arp summary | inc IP ARP",
        "pattern": r"(\d+) IP ARP entries",
        "metric": "arpEntries",
    },
    "ndEntries": {
        "command": "show ipv6 neighbors statistics | inc Entries",
        "pattern": r"Entries (\d+),",
        "metric": "ndEntries",
    },
    "natTrans": {
        "command": "show ip nat translations total",
        "pattern": r"Total number of translations: (\d+)",
        "metric": "natTranslations",
    },
    "umbrella1Trans": {
        "command": "show platform hardware qfp active feature nat datapath limit",
        "pattern": r"limit_type 5 limit_id 0xa64fd06.*curr_count (\d+)",
        "metric": "umbrella1NatTrans",
    },
    "umbrella2Trans": {
        "command": "show platform hardware qfp active feature nat datapath limit",
        "pattern": r"limit_type 5 limit_id 0xa64fe06.*curr_count (\d+)",
        "metric": "umbrella2NatTrans",
    },
    "natPoolDefault1": {
        "command": "show ip nat statistics | begin NAT-POOL-DEFAULT-1",
        "pattern": r"total addresses (\d+), allocated (\d+)[^,]+, misses (\d+)",
        "metrics": ["natPoolDefault1Addresses", "natPoolDefault1Allocated", "natPoolDefault1Misses"],
    },
    "natPoolDefault2": {
        "command": "show ip nat statistics | begin NAT-POOL-DEFAULT-2",
        "pattern": r"total addresses (\d+), allocated (\d+)[^,]+, misses (\d+)",
        "metrics": ["natPoolDefault2Addresses", "natPoolDefault2Allocated", "natPoolDefault2Misses"],
    },
    "natPoolDns": {
        "command": "show ip nat statistics | begin NAT-POOL-DNS",
        "pattern": r"total addresses (\d+), allocated (\d+)[^,]+, misses (\d+)",
        "metrics": ["natPoolDnsAddresses", "natPoolDnsAllocated", "natPoolDnsMisses"],
    },
    "natPoolLabs": {
        "command": "show ip nat statistics | begin NAT-POOL-LABS",
        "pattern": r"total addresses (\d+), allocated (\d+)[^,]+, misses (\d+)",
        "metrics": ["natPoolLabsAddresses", "natPoolLabsAllocated", "natPoolLabsMisses"],
    },
    "natPoolWLC": {
        "command": "show ip nat statistics | begin NAT-ACL-WLC",
        "pattern": r"total addresses (\d+), allocated (\d+)[^,]+, misses (\d+)",
        "metrics": ["natPoolWLCAddresses", "natPoolWLCAllocated", "natPoolWLCMisses"],
    },
    "natGatewayStatsIn": {
        "command": "show platform hardware qfp active feature nat datapath gatein activity",
        "pattern": r"Hits ([^,]+), Miss ([^,]+), Aged ([^ ]+) Added ([^ ]+) Active ([0-9]+)",
        "metrics": ["natGateInHits", "natGateInMisses", "natGateInAged", "natGateInAdded", "natGateInActive"],
    },
    "natGatewayStatsOut": {
        "command": "show platform hardware qfp active feature nat datapath gateout activity",
        "pattern": r"Hits ([^,]+), Miss ([^,]+), Aged ([^ ]+) Added ([^ ]+) Active ([0-9]+)",
        "metrics": ["natGateOutHits", "natGateOutMisses", "natGateOutAged", "natGateOutAdded", "natGateOutActive"],
    },
    "natHealthStats": {
        "command": "show ip nat statistics | begin In-to-out",
        "pattern": r"In-to-out-drops: (\d+)\s+Out-to-in-drops: (\d+).*Pool stats drop: (\d+)\s+Mapping stats drop: (\d+).*Port block alloc fail: (\d+).*IP alias add fail: (\d+).*Limit entry add fail: (\d+)",
        "metrics": [
            "natHealthInOutDrops",
            "natHealthOutInDrops",
            "natHealthStatsDrops",
            "natHealthPortBlockAllocFail",
            "natHealthAliasAddFail",
            "natHealthEntryAddFail",
        ],
    },
    "qfpUtil": {
        "command": "show platform hardware qfp active datapath utilization summary",
        "pattern": r"Processing: Load \(pct\)\s+(\d+)",
        "metric": "qfpUtil",
    },
}

devices = [
    {
        "pattern": "CORE{}-CORE",
        "range": {"min": 1, "max": 2},
        "commands": ["arpEntries", "ndEntries"],
    },
    {
        "file": IDF_FILE,
        "commands": ["macIdf", "arpEntries", "ndEntries"],
    },
    {
        "pattern": "CORE{}-WA",
        "range": {"min": 1, "max": 2},
        "commands": ["macIdf", "arpEntries", "ndEntries"],
    },
    {
        "pattern": "CORE{}-EDGE",
        "range": {"min": 1, "max": 2},
        "commands": [
            "natTrans",
            "qfpUtil",
            "umbrella1Trans",
            "umbrella2Trans",
            "natPoolDefault1",
            "natPoolDefault2",
            "natPoolDns",
            "natPoolLabs",
            "natPoolWLC",
            "natHealthStats",
            "natGatewayStatsIn",
            "natGatewayStatsOut",
        ],
    },
]


def send_command(chan, command):
    chan.sendall(command + "\n")
    time.sleep(0.5)
    output = ""
    i = 0
    while i < 60:
        r = chan.recv(65535)
        if len(r) == 0:
            raise EOFError("Remote host has closed the connection")
        r = r.decode("utf-8", "ignore")
        output += r
        if re.search(r"[#>]$", r.strip()):
            break
        time.sleep(1)

    return output


def get_results(dev):
    global commands

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    response = []
    try:
        ssh_client.connect(
            dev["device"],
            username=CLEUCreds.NET_USER,
            password=CLEUCreds.NET_PASS,
            timeout=5,
            allow_agent=False,
            look_for_keys=False,
        )
        chan = ssh_client.invoke_shell()
        try:
            send_command(chan, "term width 0")
            send_command(chan, "term length 0")
            for command in dev["commands"]:
                cmd = commands[command]["command"]
                pattern = commands[command]["pattern"]
                metric = None
                if "metric" in commands[command]:
                    metric = commands[command]["metric"]
                output = ""

                try:
                    output = send_command(chan, cmd)
                except Exception as iie:
                    response.append("")
                    sys.stderr.write("Failed to get result for {} from {}: {}\n".format(cmd, dev["device"], iie))
                    traceback.print_exc()

                m = re.search(pattern, output)
                if m:
                    if metric:
                        response.append('{}{{idf="{}"}} {}'.format(metric, dev["device"], m.group(1)))
                    else:
                        metrics = commands[command]["metrics"]
                        i = 1
                        for metric in metrics:
                            response.append('{}{{idf="{}"}} {}'.format(metric, dev["device"], m.group(i)))
                            i += 1
                else:
                    # sys.stderr.write(
                    #     'Failed to find pattern "{}" in "{}"\n'.format(pattern, output)
                    # )
                    if metric:
                        response.append('{}{{idf="{}"}} {}'.format(metric, dev["device"], 0))
                    else:
                        metrics = commands[command]["metrics"]
                        for metric in metrics:
                            response.append('{}{{idf="{}"}} {}'.format(metric, dev["device"], 0))
        except Exception as ie:
            for command in dev["commands"]:
                response.append("")
            sys.stderr.write("Failed to setup SSH on {}: {}\n".format(dev["device"], ie))
            traceback.print_exc()
    except Exception as e:
        for command in dev["commands"]:
            response.append("")
        sys.stderr.write("Failed to connect to {}: {}\n".format(dev["device"], e))

    ssh_client.close()

    return response


def get_metrics(pool):

    response = []
    targets = []

    for device in devices:
        if "list" in device:
            for dev in device["list"]:
                targets.append({"device": dev, "commands": device["commands"]})
        elif "range" in device or "subs" in device:
            if "range" in device:
                for i in range(device["range"]["min"], device["range"]["max"] + 1):
                    targets.append(
                        {
                            "device": device["pattern"].format(str(i)),
                            "commands": device["commands"],
                        }
                    )
            else:
                for sub in device["subs"]:
                    targets.append(
                        {
                            "device": device["pattern"].format(sub),
                            "commands": device["commands"],
                        }
                    )
        else:
            with open(device["file"]) as fd:
                for dev in json.load(fd):
                    targets.append({"device": dev, "commands": device["commands"]})

    results = [pool.apply_async(get_results, [d]) for d in targets]
    for res in results:
        retval = res.get()
        if retval is not None:
            response += retval

    return response


if __name__ == "__main__":
    pool = Pool(20)
    response = get_metrics(pool)

    with open(CACHE_FILE_TMP, "w") as fd:
        json.dump(response, fd, indent=4)

    os.rename(CACHE_FILE_TMP, CACHE_FILE)
