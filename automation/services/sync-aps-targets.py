#!/usr/bin/env python
#
# Copyright (c) 2017-2026  Joe Clarke <jclarke@cisco.com>
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

from __future__ import annotations

import re
import sys
from pathlib import Path

import CLEUCreds  # type: ignore
import urllib3
import yaml
from cleu.config import Config as C  # type: ignore
from pysnmp.hlapi import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    nextCmd,
    usmAesCfb256Protocol,
    usmHMAC192SHA256AuthProtocol,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


CISCO_CONTROLLER_ADDRS = C.WLCS


def hex_str_to_mac(hex_str: str) -> str:
    """Convert hex string to MAC address format."""
    hex_str = hex_str.lower().replace("0x", "")
    return ":".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))


def main(output_file: str) -> None:
    """Main function to collect AP data from controllers and write to output file."""
    # These vars are:
    #  .1.3.6.1.4.1.14179.2.2.1.1.4 ==> AP location
    #  .1.3.6.1.4.1.14179.2.2.1.1.3 ==> AP name
    #  .1.3.6.1.4.1.14179.2.2.1.1.19 ==> AP IPv4 address
    #  .1.3.6.1.4.1.9.9.513.1.10.2.1.2 ==> WLAN BSSIDs
    snmp_vars = (
        ObjectType(ObjectIdentity("1.3.6.1.4.1.14179.2.2.1.1.4")),
        ObjectType(ObjectIdentity("1.3.6.1.4.1.14179.2.2.1.1.3")),
        ObjectType(ObjectIdentity("1.3.6.1.4.1.14179.2.2.1.1.19")),
    )

    bssids_vars = (ObjectType(ObjectIdentity("1.3.6.1.4.1.9.9.513.1.10.2.1.2")),)

    aps = {}

    snmp_auth = UsmUserData(
        userName="CLEUR",
        authKey=CLEUCreds.SNMP_AUTH_PASS,
        privKey=CLEUCreds.SNMP_PRIV_PASS,
        authProtocol=usmHMAC192SHA256AuthProtocol,
        privProtocol=usmAesCfb256Protocol,
    )

    for controller in CISCO_CONTROLLER_ADDRS:
        print(f"Polling {controller}")
        snmp_iter = nextCmd(
            SnmpEngine(),
            snmp_auth,
            UdpTransportTarget((controller, 161)),
            ContextData(),
            *snmp_vars,
            lexicographicMode=False,
            lookupMib=False,
        )

        bssid_iter = nextCmd(
            SnmpEngine(),
            snmp_auth,
            UdpTransportTarget((controller, 161)),
            ContextData(),
            *bssids_vars,
            lexicographicMode=False,
            lookupMib=False,
        )

        for errorIndication, errorStatus, errorIndex, varBinds in snmp_iter:
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                error_var = varBinds[int(errorIndex) - 1][0] if errorIndex else "?"
                print(f"{errorStatus.prettyPrint()} at {error_var}")
                break
            else:
                ap = {}
                mac = None
                for varBind in varBinds:
                    oid = str(varBind[0].prettyPrint())
                    value = str(varBind[1].prettyPrint())

                    m = re.search(r"(([0-9]+\.){5}[0-9]+)$", oid)
                    if m:
                        octets = m.group(1).split(".")
                        mac = ":".join(f"{int(o):02x}" for o in octets)

                    if oid.startswith("1.3.6.1.4.1.14179.2.2.1.1.4"):
                        ap["location"] = value
                    elif oid.startswith("1.3.6.1.4.1.14179.2.2.1.1.3"):
                        ap["name"] = value
                    elif oid.startswith("1.3.6.1.4.1.14179.2.2.1.1.19"):
                        ap["ipv4"] = value

                if mac and "ipv4" in ap and ap["ipv4"] != "0.0.0.0":
                    aps[mac] = ap

        for errorIndication, errorStatus, errorIndex, varBinds in bssid_iter:
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                error_var = varBinds[int(errorIndex) - 1][0] if errorIndex else "?"
                print(f"{errorStatus.prettyPrint()} at {error_var}")
                break
            else:
                mac = None
                for varBind in varBinds:
                    oid = varBind[0].prettyPrint()
                    value = varBind[1].prettyPrint()

                    m = re.search(r"1\.3\.6\.1\.4\.1\.9\.9\.513\.1\.10\.2\.1\.2\.(([0-9]+\.){6})[\d\.]+$", oid)
                    if m:
                        octets = m.group(1).strip(".").split(".")
                        mac = ":".join(f"{int(o):02x}" for o in octets)

                    if mac and mac in aps:
                        aps[mac].setdefault("bssids", []).append(hex_str_to_mac(value))

    targets = {"targets": {"wireless": list(aps.values())}}
    targets["targets"]["wireless"] = sorted(targets["targets"]["wireless"], key=lambda d: d["name"])

    output_path = Path(output_file)
    output_path.write_text(yaml.safe_dump(targets), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} OUTPUT_FILE", file=sys.stderr)
        sys.exit(1)

    main(sys.argv[1])
