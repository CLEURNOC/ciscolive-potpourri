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


from __future__ import print_function
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore
import json
import sys
import re
import os
import argparse
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

CACHE_FILE = "dns_records.dat"
SKU_MAP = {
    "WS-C3560CX-12PD-S": None,
    "C9300-48U": "C9300-48P",
    "C9300-48P": None,
    "C9300-24U": "C9300-24P",
    "C9300-24P": None,
}


def get_devs():
    url = f"http://{C.TOOL}/get/switches/json"

    devices = []
    response = requests.request("GET", url)
    code = response.status_code
    if code == 200:
        j = response.json()

        for dev in j:
            dev_dic = {}
            if dev["IPAddress"] == "0.0.0.0":
                continue

            # Do not add MDF switches (or APs)
            if not re.search(r"^[0-9A-Za-z]{3}-", dev["Hostname"]):
                continue

            dev_dic["name"] = dev["Hostname"]
            dev_dic["aliases"] = [f"{dev['Name']}.{C.DNS_DOMAIN}.", f"{dev['AssetTag']}.{C.DNS_DOMAIN}."]

            dev_dic["ip"] = dev["IPAddress"]

            devices.append(dev_dic)

    return devices


def purge_rr(name, url, zone):
    params = {"zoneOrigin": zone}

    try:
        response = requests.request("DELETE", url, headers=CNR_HEADERS, params=params, verify=False)
        response.raise_for_status()
        print(f"INFO: Purged entry for {name}")
    except Exception as e:
        sys.stderr.write(f"INFO: Failed to purge entry for {name}: {e}\n")


def purge_rrs(hname, dev):
    aname = hname
    cnames = []
    for alias in dev["aliases"]:
        cnames.append(alias.split(".")[0])
    pname = ".".join(dev["ip"].split(".")[::-1][0:3])

    ubase = C.DNS_BASE + "CCMRRSet" + "/{}"

    url = ubase.format(aname)

    purge_rr(aname, url, C.DNS_DOMAIN)

    for cname in cnames:
        url = ubase.format(cname)

        purge_rr(cname, url, C.DNS_DOMAIN)

    url = ubase.format(pname)

    purge_rr(pname, url, "10.in-addr.arpa")


def add_entry(url, hname, dev):
    global CNR_HEADERS, CNR_AUTH

    try:
        rrset = [
            f"IN 0 A {dev['ip']}",
        ]

        rrset_obj = {"name": hname, "rrs": {"stringItem": rrset}, "zoneOrigin": C.DNS_DOMAIN}

        response = requests.request("PUT", url, auth=CNR_AUTH, headers=CNR_HEADERS, json=rrset_obj, verify=False)
        response.raise_for_status()
        print(f"INFO: Added entry for {hname} ==> {dev['ip']}")
    except Exception as e:
        sys.stderr.write(f"ERROR: Failed to add entry for {hname}: {e}\n")
        return

    for alias in dev["aliases"]:
        aname = alias.split(".")[0]
        alias_rrset_obj = {
            "name": aname,
            "rrs": {"stringItem": [f"IN 0 CNAME {hname}.{C.DNS_DOMAIN}."]},
            "zoneOrigin": C.DNS_DOMAIN,
        }
        url = C.DNS_BASE + "CCMRRSet" + f"/{hname}"

        try:
            response = requests.request("PUT", url, auth=CNR_AUTH, headers=CNR_HEADERS, json=alias_rrset_obj, verify=False)
            response.raise_for_status()
            print(f"Added CNAME entry {alias} ==> {hname}")
        except Exception as e:
            sys.stderr.write(f"ERROR: Failed to add CNAME {alias} for {hname}: {e}\n")

    try:
        ptr_rrset = [f"IN 0 PTR {hname}.{C.DNS_DOMAIN}."]
        rip = ".".join(dev["ip"].split(".")[::-1][0:3])
        ptr_rrset_obj = {"name": rip, "rrs": {"stringItem": ptr_rrset}, "zoneOrigin": "10.in-addr.arpa."}
        url = C.DNS_BASE + "CCMRRSet" + "/{}".format(rip)
        response = requests.request("PUT", url, auth=CNR_AUTH, headers=CNR_HEADERS, json=ptr_rrset_obj, verify=False)
        response.raise_for_status()
        print(f"INFO: Added PTR entry {rip} ==> {hname}")
    except Exception as e:
        sys.stderr.write(f"ERROR: Failed to add PTR entry for {rip}: {e}\n")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Usage:")

    # script arguments
    parser.add_argument("--purge", help="Purge previous records", action="store_true")
    args = parser.parse_args()

    prev_records = []

    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as fd:
            prev_records = json.load(fd)

    devs = get_devs()
    for record in prev_records:
        found_record = False
        for dev in devs:
            hname = dev["name"].replace(f".{C.DNS_DOMAIN}", "")
            if record == hname:
                found_record = True
                break
        if found_record:
            continue

        url = C.DNS_BASE + "CCMHost" + f"/{record}"
        try:
            response = requests.request(
                "DELETE", url, auth=CNR_AUTH, headers=CNR_HEADERS, params={"zoneOrigin": C.DNS_DOMAIN}, verify=False
            )
            response.raise_for_status()
        except Exception as e:
            sys.stderr.write(f"WARNING: Failed to delete entry for {record}\n")

    records = []
    for dev in devs:
        hname = dev["name"].replace(f".{C.DNS_DOMAIN}", "")

        records.append(hname)
        if args.purge:
            purge_rrs(hname, dev)
        url = C.DNS_BASE + "CCMHost" + f"/{hname}"
        response = requests.request("GET", url, auth=CNR_AUTH, headers=CNR_HEADERS, params={"zoneOrigin": C.DNS_DOMAIN}, verify=False)
        url = C.DNS_BASE + "CCMRRSet" + f"/{hname}"
        if response.status_code == 404:
            iurl = C.DNS_BASE + "CCMHost"
            response = requests.request(
                "GET", iurl, params={"zoneOrigin": C.DNS_DOMAIN, "addrs": dev["ip"] + "$"}, auth=CNR_AUTH, headers=CNR_HEADERS, verify=False
            )
            cur_entry = []
            if response.status_code != 404:
                cur_entry = response.json()

            if len(cur_entry) > 0:
                print("Found entry for {}: {}".format(dev["ip"], response.status_code))
                cur_entry = response.json()
                if len(cur_entry) > 1:
                    print(f"ERROR: Found multiple entries for IP {dev['ip']}")
                    continue

                print(f"INFO: Found old entry for IP {dev['ip']} => {cur_entry[0]['name']}")

                durl = C.DNS_BASE + "CCMHost" + f"/{cur_entry[0]['name']}"
                try:
                    response = requests.request(
                        "DELETE", durl, params={"zoneOrigin": C.DNS_DOMAIN}, auth=CNR_AUTH, headers=CNR_HEADERS, verify=False
                    )
                    response.raise_for_status()
                except Exception as e:
                    sys.stderr.write(f"ERROR: Failed to delete stale entry for {cur_entry[0]['hname']} ({dev['ip']})\n")
                    continue

            add_entry(url, hname, dev)
        else:
            cur_entry = response.json()
            create_new = True
            for addr in cur_entry["addrs"]["stringItem"]:
                if addr == dev["ip"]:
                    if "aliases" in dev and "aliases" in cur_entry:
                        if (len(dev["aliases"]) > 0 and "stringItem" not in cur_entry["aliases"]) or (
                            len(dev["aliases"]) != len(cur_entry["aliases"]["stringItem"])
                        ):
                            break
                        common = set(dev["aliases"]) & set(cur_entry["aliases"]["stringItem"])
                        if len(common) != len(dev["aliases"]):
                            break
                        create_new = False
                        break
                    elif ("aliases" in dev and "aliases" not in cur_entry) or ("aliases" in cur_entry and "aliases" not in dev):
                        break
                    else:
                        create_new = False
                        break

            if create_new:
                print(f"INFO: Deleting entry for {hname}")
                purge_rrs(hname, dev)

                add_entry(url, hname, dev)
            else:
                # print("Not creating a new entry for {} as it already exists".format(dev["name"]))
                pass

    fd = open(CACHE_FILE, "w")
    with open(CACHE_FILE, "w") as fd:
        json.dump(records, fd, indent=4)
