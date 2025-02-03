#!/usr/bin/env python

import pyshark
from subprocess import Popen, PIPE
from shlex import split


def print_client_mac(pkt):
    print(pkt.dhcp.hw_mac_addr)


def main():
    p = Popen(split("ssh root@dc1-dhcp.ciscolive.network 'tcpdump -U -i ens160 -w - udp port 67'"), stdout=PIPE)

    capture = pyshark.PipeCapture(p.stdout, display_filter="dhcp.option.request_list_item==108 && dhcp.option.dhcp==1")
    capture.apply_on_packets(print_client_mac, timeout=1000)

    p.wait()


if __name__ == "__main__":
    main()
