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

# import asyncio
import logging
import os
import re
from enum import StrEnum
from typing import Annotated, Literal

# import httpx
import pynetbox
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
# from mcp.shared.exceptions import McpError
# from mcp.types import METHOD_NOT_FOUND
from pydantic import BaseModel, Field

# Set up logging
loglevel = logging.DEBUG if os.getenv("DEBUG", "false").lower() == "true" else logging.INFO
logging.basicConfig(level=loglevel, format="%(asctime)s %(levelname)s %(threadName)s %(name)s: %(message)s")
logger = logging.getLogger("noc-mcp")


server_mcp = FastMCP(
    "Cisco Live Europe NOC",
    dependencies=["httpx", "fastmcp", "pynetbox"],
    log_level=logging.getLevelName(loglevel),
    debug=loglevel == logging.DEBUG,
)

pnb = pynetbox.api(os.getenv("NETBOX_SERVER"), os.getenv("NETBOX_API_TOKEN"))
tls_verify = os.getenv("DHCP_BOT_TLS_VERIFY", "True").lower() == "true"
pnb.http_session.verify = tls_verify

AT_MACADDR = 9

CNR_HEADERS = {"Accept": "application/json"}
BASIC_AUTH = (os.getenv("CPNR_USERNAME"), os.getenv("CPNR_PASSWORD"))
REST_TIMEOUT = int(os.getenv("DHCP_BOT_REST_TIMEOUT", "10"))

DEFAULT_INT_TYPE = "Ethernet"

ALLOWED_TO_DELETE = ("jclarke@cisco.com", "josterfe@cisco.com", "anjesani@cisco.com")

# TYPES

LINT_REG = r"[\da-z-]{1,15}"
IPV4_REG = r"(\d{1,3}.){3}\d{1,3}"
IPV6_REG = r"[\da-fA-F:]{3,39}" + f"(%{LINT_REG})?"
IP_REG = rf"^({IPV4_REG}|{IPV6_REG})(?![\n\r])$"
HOSTNAME_REG = r"[a-zA-Z\d.-]{1,64}"
HOST_REG = rf"^{HOSTNAME_REG}(?![\n\r])$"
DOMAIN_REG = rf"{IPV4_REG}|\[{IPV6_REG}\]|{HOSTNAME_REG}"


class InputTypeEnum(StrEnum):
    ip_address = "ip"
    hostname = "hostname"
    username = "username"
    mac_address = "mac"


class NetBoxTypeEnum(StrEnum):
    device = "device"
    vm = "VM"


MACAddress = Annotated[
    str | None,
    Field(
        pattern=re.compile(r"^[a-fA-F\d]{2}(:[a-fA-F\d]{2}){5}(?![\n\r])$"),
        description="MAC address in Linux format.",
        examples=["00:11:22:33:44:55"],
    ),
]

Hostname = Annotated[
    str,
    Field(
        pattern=re.compile(HOST_REG),
        description="A Linux hostname (not FQDN).",
    ),
]

IPAddress = Annotated[
    str,
    Field(
        pattern=re.compile(IP_REG),
        description="An IPv4 or IPv6 host address.",
    ),
]


class IPAddressClass(BaseModel, extra="forbid"):
    type: Literal[InputTypeEnum.ip_address]
    ip: IPAddress


class HostnameClass(BaseModel, extra="forbid"):
    type: Literal[InputTypeEnum.hostname]
    hostname: Hostname


NetBoxInput = Annotated[
    IPAddressClass | HostnameClass,
    Field(
        description="The input arguments to fetching data from Netbox.",
        discriminator="type",
    ),
]


class NetBoxResponse(BaseModel, extra="forbid"):
    name: str = Field(..., description="The name of the object in NetBox.")
    type: NetBoxTypeEnum = Field(..., description="The type of the NetBox object.")
    ip: IPAddress | None = Field(None, description="The primary IP address of the object, if available.")
    responsible_people: list[str] | None = Field(None, description="List of people responsible for the object.")
    usage_notes: str | None = Field(None, description="Any usage notes associated with the object.")


# UTILITIES


def is_ascii(s: str) -> bool:
    """
    Check if a string contains all ASCII characters.

    Args:
        s (str): String to check

    Returns:
        bool: True if all characters in the string are ASCII; False otherwise
    """
    return all(ord(c) < 128 for c in s)


def normalize_mac(mac: str) -> MACAddress:
    """
    Normalize all MAC addresses to colon-delimited and lower case.

    Args:
        mac (str): MAC address to normalize

    Returns:
        MACAddress: The normalized MAC address
    """
    mac_addr = "".join(l + ":" * (n % 2 == 1) for n, l in enumerate(list(re.sub(r"[:.-]", "", mac)))).strip(":")

    return MACAddress(mac_addr.lower())


def parse_relay_info(outd: dict[str, str]) -> dict[str, str]:
    """
    Parse DHCP relay information and produce a string for the connected switch and port.

    Args:
        outd (dict[str, str]): Dict of the encoded relayAgentCircuitId and relayAgentRemoteId keys

    Returns:
        dict[str, str]: Dict with the port, vlan, and switch values decoded as ASCII strings (if possible)
    """
    # Initialize result with default values
    res = {"vlan": "N/A", "port": "N/A", "switch": "N/A"}

    # Parse relayAgentCircuitId if present
    circuit_id = outd.get("relayAgentCircuitId")
    if circuit_id:
        octets = circuit_id.split(":")
        # Expect at least 6 octets for valid parsing
        if len(octets) > 5:
            # VLAN is encoded in octets 2 and 3 (hex)
            try:
                res["vlan"] = str(int("".join(octets[2:4]), 16))
            except ValueError:
                res["vlan"] = "N/A"
            # Port info is in octets 4 and 5
            try:
                first_part = int(octets[4], 16)
                port_num = int(octets[5], 16)
                # If first_part > 1, it's a Port-channel
                if first_part > 1:
                    res["port"] = f"Port-channel{port_num}"
                else:
                    # Otherwise, it's a standard interface
                    port = f"{first_part}/0" if first_part != 0 else str(first_part)
                    res["port"] = f"{DEFAULT_INT_TYPE}{port}/{port_num}"
            except ValueError:
                res["port"] = "N/A"

    # Parse relayAgentRemoteId if present
    remote_id = outd.get("relayAgentRemoteId")
    if remote_id:
        octets = remote_id.split(":")
        # Convert hex string (from octet 2 onward) to ASCII switch name
        try:
            switch_name = bytes.fromhex("".join(octets[2:])).decode("utf-8", "ignore")
            # Validate ASCII and non-empty
            res["switch"] = switch_name if is_ascii(switch_name) and switch_name else "N/A"
        except (ValueError, IndexError):
            res["switch"] = "N/A"

    return res


# TOOLS


@server_mcp.tool(
    annotations={
        "title": "Get Objects from NetBox",
        "readOnlyHint": True,
    }
)
async def get_object_info_from_netbox(inp: NetBoxInput | dict) -> list[NetBoxResponse]:
    """
    Get a list of objects from the NetBox network source of truth given an IP address or a name.
    """
    ip = None
    name = None
    try:
        # XXX The dict usage is a workaround for some LLMs that pass a JSON string
        # representation of the argument object.
        if isinstance(inp, dict):
            if inp["type"] == "ip":
                inp = IPAddressClass(**inp)
            elif inp["type"] == "hostname":
                inp = HostnameClass(**inp)
            else:
                raise ValueError(f"Invalid annotation type: {inp['type']}. Must be one of 'ip' or 'hostname'.")

        if isinstance(inp, IPAddressClass):
            ip = inp
        elif isinstance(inp, HostnameClass):
            name = inp
        else:
            raise ValueError("Invalid input type. Must be IPAddressClass or HostnameClass.")

        if name:
            res = []
            devs = list(pnb.dcim.devices.filter(name__ic=str(name.hostname)))
            if len(devs) > 0:
                for dev in devs:
                    res.append({"name": dev.name, "type": "device", "ip": dev.primary_ip4})
            else:
                vms = list(pnb.virtualization.virtual_machines.filter(name__ic=str(name.hostname)))
                if len(vms) > 0:
                    for vm in vms:
                        ret = {"name": vm.name, "type": "VM", "ip": vm.primary_ip4}
                        if "Contact" in vm.custom_fields and vm.custom_fields["Contact"]:
                            ret["responsible_people"] = vm.custom_fields["Contact"].split(",")
                        if "Notes" in vm.custom_fields and vm.custom_fields["Notes"]:
                            ret["usage_notes"] = vm.custom_fields["Notes"]

                        res.append(ret)

            if len(res) > 0:
                return res

            raise ValueError(f"No objects found in NetBox matching hostname {name.hostname}")

        ipa = None
        for prefix in ("24", "31", "32", "16", "64", "128"):
            ipa = pnb.ipam.ip_addresses.get(address=f"{str(ip.ip)}/{prefix}")
            if ipa:
                break

        if ipa:
            ipa.full_details()
            if ipa.assigned_object_type == "virtualization.vminterface":
                ret = {"type": "VM", "name": str(ipa.assigned_object.virtual_machine), "ip": str(ipa)}
                vm_obj = ipa.assigned_object.virtual_machine
                if "Contact" in vm_obj.custom_fields and vm_obj.custom_fields["Contact"]:
                    ret["responsible_people"] = vm_obj.custom_fields["Contact"].split(",")
                if "Notes" in vm_obj.custom_fields and vm_obj.custom_fields["Notes"]:
                    ret["usage_notes"] = vm_obj.custom_fields["Notes"]

                return [ret]
            elif ipa.assigned_object_type == "dcim.interface":
                return [{"type": "device", "name": str(ipa.assigned_object.device), "ip": str(ipa)}]

        raise ValueError(f"No objects found in NetBox matching IP address {ip.ip}")
    except Exception as e:
        logger.error(f"Error getting object info from NetBox: {e}", exc_info=True)
        raise ToolError(e)


if __name__ == "__main__":
    server_mcp.run()
