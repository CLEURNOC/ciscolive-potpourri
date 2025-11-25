#!/usr/bin/env python
#
# Copyright (c) 2025  Joe Clarke <jclarke@cisco.com>
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

import pyshark
from subprocess import Popen, PIPE, DEVNULL
from shlex import split
from influxdb import InfluxDBClient
import datetime
import traceback
from cleu.config import Config as C  # type: ignore
import CLEUCreds  # type: ignore


def print_client_mac(pkt):
    try:
        print(f"Got packet from {pkt.dhcp.hw.mac_addr}")
    except Exception:
        traceback.print_exec()
        return

    is_v6mostly = False

    if "55" in pkt.dhcp.option.type:
        param_list = pkt.dhcp.option.type_tree[pkt.dhcp.option.type.index("55")]
        print(f"Param list is {param_list.request_list_item}")
        if "108" in param_list.request_list_item:
            is_v6mostly = True

    json_body = [
        {
            "measurement": "dhcp_client",
            "time": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tags": {"relay_ip": pkt.dhcp.ip.relay},
            "fields": {"supports_v6mostly": is_v6mostly, "client_mac": pkt.dhcp.hw.mac_addr},
        }
    ]
    client.write_points(json_body)


def main():
    p = Popen(split(f"ssh root@{C.DHCP_SERVER} 'tcpdump -U -i ens160 -w - udp port 67'"), stdout=PIPE, stderr=DEVNULL)

    capture = pyshark.PipeCapture(p.stdout, display_filter="dhcp.option.type==53||dhcp.option.type==1", use_json=True)
    capture.apply_on_packets(print_client_mac)

    p.wait()


if __name__ == "__main__":
    client = InfluxDBClient(C.MONITORING, 8086, CLEUCreds.INFLUX_USER, CLEUCreds.INFLUX_PASS, "v6mostly")
    main()
