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
from typing import Annotated, List, Dict

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


server_mcp = FastMCP("Cisco Live Europe NOC")

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
IP_REG = rf"^({IPV4_REG}|{IPV6_REG})(/\d+)?(?![\n\r])$"
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


class NetBoxInput(BaseModel, extra="forbid"):
    ip: IPAddress | None = Field(None, description="The IP address to look up in NetBox.")
    hostname: Hostname | None = Field(None, description="The hostname to look up in NetBox.")


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


def parse_relay_info(outd: Dict[str, str]) -> Dict[str, str]:
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
async def get_object_info_from_netbox(inp: NetBoxInput | dict) -> List[NetBoxResponse]:
    """
    Get a list of objects from the NetBox network source of truth given an IP address or a name.
    Args:
        inp (NetBoxInput | dict): Input data, either a validated NetBoxInput or a dict (for LLM compatibility).
    """
    try:
        # Handle dict input for LLMs that pass JSON objects
        if isinstance(inp, dict):
            inp = NetBoxInput(**inp)

        # Determine query type
        if inp.ip:
            ip = inp.ip
            name = None
        elif inp.hostname:
            name = inp.hostname
            ip = None
        else:
            raise ValueError("Invalid input.  Either 'ip' or 'hostname' property must be specified.")

        # Query by hostname
        if name:
            responses = []
            # Search devices by hostname (case-insensitive)
            devs = list(pnb.dcim.devices.filter(name__ic=name))
            for dev in devs:
                responses.append(
                    NetBoxResponse(
                        name=dev.name,
                        type=NetBoxTypeEnum.device,
                        ip=str(dev.primary_ip4) if dev.primary_ip4 else None,
                        responsible_people=None,
                        usage_notes=None,
                    )
                )
            # If no devices, search VMs by hostname
            if not responses:
                vms = list(pnb.virtualization.virtual_machines.filter(name__ic=name))
                for vm in vms:
                    responses.append(
                        NetBoxResponse(
                            name=vm.name,
                            type=NetBoxTypeEnum.vm,
                            ip=str(vm.primary_ip4) if vm.primary_ip4 else None,
                            responsible_people=vm.custom_fields.get("Contact", "").split(",") if vm.custom_fields.get("Contact") else None,
                            usage_notes=vm.custom_fields.get("Notes") if vm.custom_fields.get("Notes") else None,
                        )
                    )
            if responses:
                return responses
            raise ValueError(f"No objects found in NetBox matching hostname {name}")

        # Query by IP address
        if ip:
            ipa = None
            # Try common subnet sizes for IP lookup (NetBox requires prefix)
            for prefix in ("32", "31", "24", "128", "64", "16"):
                ipa = pnb.ipam.ip_addresses.get(address=f"{ip}/{prefix}")
                if ipa:
                    break
            if ipa:
                ipa.full_details()  # Ensure all fields are populated
                # VM interface assignment
                if ipa.assigned_object_type == "virtualization.vminterface":
                    vm_obj = ipa.assigned_object.virtual_machine
                    return [
                        NetBoxResponse(
                            name=str(vm_obj),
                            type=NetBoxTypeEnum.vm,
                            ip=str(ipa),
                            responsible_people=(
                                vm_obj.custom_fields.get("Contact", "").split(",") if vm_obj.custom_fields.get("Contact") else None
                            ),
                            usage_notes=vm_obj.custom_fields.get("Notes") if vm_obj.custom_fields.get("Notes") else None,
                        )
                    ]
                # Device interface assignment
                elif ipa.assigned_object_type == "dcim.interface":
                    dev_obj = ipa.assigned_object.device
                    return [
                        NetBoxResponse(
                            name=str(dev_obj), type=NetBoxTypeEnum.device, ip=str(ipa), responsible_people=None, usage_notes=None
                        )
                    ]
            raise ValueError(f"No objects found in NetBox matching IP address {ip}")

    except Exception as e:
        logger.error(f"Error getting object info from NetBox: {e}", exc_info=True)
        raise ToolError(e)


if __name__ == "__main__":
    server_mcp.run()
