#!/usr/bin/env python
#
# Copyright (c) 2017-2022  Joe Clarke <jclarke@cisco.com>
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
import json
from elemental_utils import ElementalNetbox
import ipaddress
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys
import re
import os
import CLEUCreds
from cleu.config import Config as C

IDF_CNT = 99
ADDITIONAL_IDFS = (252, 253, 254)
FIRST_IP = 31
LAST_IP = 253

NB_TENANT = "Attendees"

IDF_OVERRIDES = {
    252: {"first_ip": 160, "last_ip": "250"},
    253: {"first_ip": 160, "last_ip": "250"},
    254: {"first_ip": 160, "last_ip": "250"},
}

SCOPE_BASE = C.DHCP_BASE + "Scope"

DHCP_TEMPLATE = {"optionList": {"OptionItem": []}}

HEADERS = {"accept": "application/json", "content-type": "application/json"}


if __name__ == "__main__":
    os.environ["NETBOX_ADDRESS"] = C.NETBOX_SERVER
    os.environ["NETBOX_API_TOKEN"] = CLEUCreds.NETBOX_API_TOKEN

    enb = ElementalNetbox()

    tenant = list(enb.tenancy.tenants.filter(tenant_name=NB_TENANT))[0]
    prefixes = list(enb.ipam.prefixes.filter(tenant_id=tenant.id))

    for prefix in prefixes:
        prefix_obj = ipaddress.ip_network(prefix.prefix)

        start = 1
        cnt = IDF_CNT

        idf_set = ()

        if str(prefix_obj.netmask) == "255.255.0.0":
            start = 0
            cnt = 0

        for i in range(start, cnt + 1):
            idf_set += (i,)

        if str(prefix_obj.netmask) != "255.255.0.0":
            idf_set += ADDITIONAL_IDFS

        for i in idf_set:
            scope_prefix = f"IDF-{str(i).zfill(3)}"
            if i == 0:
                scope_prefix = "CORE"

            scope = (f"{scope_prefix}-{prefix.vlan.name}").upper()
            ip = f"10.{prefix.vlan.id}.{i}.0"
            octets = ["10", str(prefix.vlan.id), str(i), "0"]
            roctets = list(octets)
            roctets[3] = "254"

            url = "{}/{}".format(SCOPE_BASE, scope)

            response = requests.request("GET", url, auth=(CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD), headers=HEADERS, verify=False)
            if response.status_code != 404:
                sys.stderr.write(f"Scope {scope} already exists: {response.status_code}\n")
                continue

            template = {"optionList": {"OptionItem": []}}
            if str(prefix_obj.netmask) == "255.255.0.0":
                roctets[2] = "255"
            template["optionList"]["OptionItem"].append({"number": "3", "value": ".".join(roctets)})
            first_ip = FIRST_IP
            last_ip = LAST_IP
            if i in IDF_OVERRIDES:
                first_ip = IDF_OVERRIDES[i]["first_ip"]
                last_ip = IDF_OVERRIDES[i]["last_ip"]

            sipa = list(octets)
            sipa[3] = str(first_ip)
            eipa = list(octets)
            eipa[3] = str(last_ip)
            if str(prefix_obj.netmask) == "255.255.0.0":
                eipa[2] = "255"

            sip = ".".join(sipa)
            eip = ".".join(eipa)

            rlist = {"RangeItem": [{"end": eip, "start": sip}]}
            cidr = prefix_obj.prefixlen

            payload = {
                "embeddedPolicy": template,
                "name": scope,
                "policy": prefix.role.name,
                "rangeList": rlist,
                "subnet": f"{ip}/{cidr}",
                "tenantId": "0",
                "vpnId": "0",
            }

            response = requests.request(
                "PUT", url, json=payload, auth=(CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD), headers=HEADERS, verify=False
            )
            try:
                response.raise_for_status()
            except Exception as e:
                sys.stderr.write(f"Error adding scope {scope} ({ip}/{cidr}) with range sip:{sip} eip:{eip}: {response.text} ({e})\n")
                sys.stderr.write(f"Request: {json.dumps(payload, indent=4)}\n")
                continue
