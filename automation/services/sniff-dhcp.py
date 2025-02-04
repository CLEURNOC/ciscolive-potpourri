#!/usr/bin/env python

import pyshark
from subprocess import Popen, PIPE, DEVNULL
from shlex import split
from influxdb import InfluxDBClient
import datetime
from cleu.config import Config as C  # type: ignore
import CLEUCreds  # type: ignore


def print_client_mac(pkt):
    global client

    print(f"Got packet from {pkt.dhcp.hw.mac_addr}")

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
