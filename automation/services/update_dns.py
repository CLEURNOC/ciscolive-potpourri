#!/usr/bin/env python3

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys
import re
from argparse import ArgumentParser
import CLEUCreds
from cleu.config import Config as C

HEADERS = {"authorization": CLEUCreds.JCLARKE_BASIC, "accept": "application/json", "content-type": "application/json"}

if __name__ == "__main__":

    parser = ArgumentParser(description="Usage:")

    # script arguments
    parser.add_argument("-i", "--input", type=str, help="Path to input CSV file")
    parser.add_argument("--host", type=str, help="Hostname for a single add")
    parser.add_argument("--ip", type=str, help="IP address for a single add")
    args = parser.parse_args()

    hosts = []

    if not args.input:
        if not args.ip or not args.host:
            print("Single addition requires both a hostname and an IP address.")
            sys.exit(1)
        hosts.append((args.host, args.ip))
    else:

        contents = None
        try:
            fd = open(args.input, "r")
            contents = fd.read()
            fd.close()
        except Exception as e:
            print("Failed to open {} for reading: {}".format(args.input, e))
            sys.exit(1)

        for row in contents.split("\n"):
            row = row.strip()
            if re.search(r"^#", row):
                continue
            if row == "":
                continue

            [hostname, ip] = row.split(",")
            hostname = hostname.strip().upper()
            ip = ip.strip()

            hosts.append((hostname, ip))

    for h in hosts:
        hostname = h[0]
        ip = h[1]

        url = C.DNS_BASE + "CCMHost" + "/{}".format(hostname)

        response = requests.request("GET", url, params={"zoneOrigin": C.DNS_DOMAIN}, headers=HEADERS, verify=False)
        if response.status_code != 404:
            host_obj = response.json()
            a = host_obj["addrs"]["stringItem"][0]

            if a != ip:
                try:
                    response = requests.request("DELETE", url, params={"zoneOrigin": C.DNS_DOMAIN}, headers=HEADERS, verify=False)
                    response.raise_for_status()
                except Exception as e:
                    sys.stderr.write("Failed to remove host {}: {}".format(hostname, e))
                    continue

                try:
                    host_obj["addrs"]["stringItem"][0] = ip
                    response = requests.request("PUT", url, json=host_obj, headers=HEADERS, verify=False)
                    response.raise_for_status()
                except Exception as e:
                    sys.stderr.write("Error adding entry for {}: {}".format(hostname, e))
        else:
            try:
                host_obj = {"addrs": {"stringItem": [ip]}, "name": hostname, "zoneOrigin": C.DNS_DOMAIN}
                response = requests.request("PUT", url, headers=HEADERS, json=host_obj, verify=False)
                response.raise_for_status()
            except Exception as e:
                sys.stderr.write("Error adding entry for {}: {}\n".format(hostname, e))
