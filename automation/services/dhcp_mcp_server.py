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


import asyncio
import logging
import os
import re
from enum import StrEnum
from shlex import split
from subprocess import run
from typing import Annotated, Dict, List, Tuple
from pathlib import Path
import json

import dns.asyncresolver
import dns.reversename
import httpx
import pynetbox
import xmltodict
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from ncclient import manager
from pydantic import BaseModel, Field
from sparker import Sparker  # type: ignore

# Set up logging
logger = logging.getLogger("noc-mcp-server")
loglevel = logging.DEBUG if os.getenv("DEBUG", "false").lower() == "true" else logging.INFO
logger.setLevel(loglevel)
# Configure handler with format for this module only
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False

is_testing = os.getenv("DHCP_BOT_IS_TESTING", "False").lower() == "true"

server_mcp = FastMCP("Cisco Live Europe NOC")

AT_MACADDR = 9

CNR_HEADERS = {"Accept": "application/json"}

DEFAULT_INT_TYPE = "Ethernet"

ALLOWED_TO_DELETE = ("jclarke@cisco.com", "josterfe@cisco.com", "anjesani@cisco.com", "eagcagul@cisco.com", "james@bottswanamedia.info")

# TYPES

LINT_REG = r"[\da-z-]{1,15}"
IPV4_REG = r"(\d{1,3}.){3}\d{1,3}"
IPV6_REG = r"[\da-fA-F:]{3,39}" + f"(%{LINT_REG})?"
IP_REG = rf"^({IPV4_REG}|{IPV6_REG})(/\d+)?$"
HOSTNAME_REG = r"[a-zA-Z\d.-]{1,64}"
HOST_REG = rf"^{HOSTNAME_REG}$"
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
    str,
    Field(
        pattern=re.compile(r"^[a-fA-F\d]{2}(:[a-fA-F\d]{2}){5}$"),
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


class WebexInfoInput(BaseModel, extra="forbid"):
    mac: MACAddress | None = Field(None, description="The MAC address of the Webex device to look up.")
    ip: IPAddress | None = Field(None, description="The IP address of the Webex device to look up.")
    device_name: str | None = Field(None, description="The name of the Webex device to look up.")


class ISEInput(BaseModel, extra="forbid"):
    username: str | None = Field(None, description="The username of the client to look up in ISE.")
    mac: MACAddress | None = Field(None, description="The MAC address of the client to look up in ISE.")
    ip: IPAddress | None = Field(None, description="The IP address of the client to look up in ISE.")


class DNACInput(BaseModel, extra="forbid"):
    username: str | None = Field(None, description="The username of the client to look up in Catalyst Center.")
    mac: MACAddress | None = Field(None, description="The MAC address of the client to look up in Catalyst Center.")
    ip: IPAddress | None = Field(None, description="The IP address of the client to look up in Catalyst Center.")


class CPNRReservationInput(BaseModel, extra="forbid"):
    ip: IPAddress | None = Field(None, description="The IP address of the reservation to look up in CPNR.")
    mac: MACAddress | None = Field(None, description="The MAC address of the reservation to look up in CPNR.")


class CPNRLeaseInput(BaseModel, extra="forbid"):
    ip: IPAddress | None = Field(None, description="The IP address of the lease to look up in CPNR.")
    mac: MACAddress | None = Field(None, description="The MAC address of the lease to look up in CPNR.")


class DNSInput(BaseModel, extra="forbid"):
    ip: IPAddress | None = Field(None, description="The IP address to perform a reverse DNS lookup on.")
    hostname: Hostname | None = Field(None, description="The hostname to perform a forward DNS lookup on.")


class NetBoxResponse(BaseModel, extra="forbid"):
    name: str = Field(..., description="The name of the object in NetBox.")
    type: NetBoxTypeEnum = Field(..., description="The type of the NetBox object.")
    ip: IPAddress | None = Field(None, description="The primary IP address of the object, if available.")
    responsible_people: list[str] | None = Field(None, description="List of people responsible for the object.")
    usage_notes: str | None = Field(None, description="Any usage notes associated with the object.")


class WebexInfoResponse(BaseModel, extra="forbid"):
    name: str = Field(..., description="The name of the Webex device.")
    product: str = Field(..., description="The product type of the Webex device.")
    device_type: str = Field(..., description="The type of the Webex device.")
    mac: MACAddress = Field(..., description="The MAC address of the Webex device.")
    ip: IPAddress = Field(..., description="The IP address of the Webex device.")
    serial_number: str = Field(..., description="The serial number of the Webex device.")
    software: str = Field(..., description="The software version of the Webex device.")
    connection_status: str = Field(..., description="The connection status of the Webex device.")
    connected_interface: str = Field(..., description="The currently active interface of the Webex device.")
    location: str | None = Field(None, description="The location of the Webex device's workspace.")
    room_temperature: str | None = Field(None, description="The temperature of the workspace in degrees C.")
    room_humidity: str | None = Field(None, description="The humidity of the workspace in percentage.")


class ISEResponse(BaseModel, extra="forbid"):
    username: str = Field(..., description="The username of the client.")
    client_mac: MACAddress = Field(..., description="The MAC address of the client.")
    network_access_server: IPAddress | None = Field(None, description="The IP address of the network access server (NAS).")
    client_ipv4: IPAddress | None = Field(None, description="The IPv4 address of the client, if available.")
    client_ipv6: list[IPAddress] | None = Field(None, description="List of IPv6 addresses of the client, if available.")
    authentication_timestamp: str | None = Field(None, description="The timestamp of the client's authentication.")
    associated_access_point: str | None = Field(None, description="The MAC address or name of the associated access point, if available.")
    connected_vlan: str | None = Field(None, description="The VLAN ID the client is connected to, if available.")
    associated_ssid: str | None = Field(None, description="The SSID the client is associated with, if available.")


class DNACResponse(BaseModel, extra="forbid"):
    user: str | None = Field(None, description="The username of the client.")
    mac: MACAddress | None = Field(None, description="The MAC address of the client.")
    type: str | None = Field(None, description="The type of the client device.")
    ostype: str | None = Field(None, description="The operating system type of the client device.")
    health: int | None = Field(None, description="The overall health score of the client device.")
    reason: str | None = Field(None, description="The reason for the health score, if available.")
    onboard: int | None = Field(None, description="The onboarding health score of the client device.")
    connect: int | None = Field(None, description="The connectivity health score of the client device.")
    ssid: str | None = Field(None, description="The SSID the client is connected to, if available.")


class CPNRReservationResponse(BaseModel, extra="forbid"):
    mac: MACAddress = Field(..., description="The MAC address of the reservation.")
    scope: str = Field(..., description="The scope name of the reservation.")


class CPNRLeaseResponse(BaseModel, extra="forbid"):
    ip: IPAddress = Field(..., description="The IP address of the lease.")
    name: str = Field(..., description="The hostname of the client.")
    mac: MACAddress = Field(..., description="The MAC address of the client.")
    scope: str = Field(..., description="The scope name of the lease.")
    state: str = Field(..., description="The state of the lease (e.g., ACTIVE, EXPIRED).")
    relay_info: Dict[str, str] = Field(..., description="DHCP relay information including switch, VLAN, and port.")
    is_reserved: bool = Field(..., description="Indicates if the lease is reserved.")


class DNSResponse(BaseModel, extra="forbid"):
    query: str = Field(..., description="The original query string (IP or hostname).")
    record_type: str = Field(..., description="The type of DNS record (A, AAAA, PTR).")
    results: List[str] = Field(..., description="List of resolved DNS records.")


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
    # Remove all separators and convert to lowercase
    clean_mac = re.sub(r"[:.-]", "", mac).lower()

    # Validate length and allow for some trailing fuzziness.
    if len(clean_mac) < 12:
        raise ValueError(f"Invalid MAC address length: {mac}")

    # Insert colons every 2 characters
    formatted_mac = ":".join(clean_mac[i : i + 2] for i in range(0, 12, 2))
    return MACAddress(formatted_mac)


def parse_relay_info(outd: Dict[str, str]) -> Dict[str, str]:
    """
    Parse DHCP relay information and produce a string for the connected switch and port.

    Args:
        outd (Dict[str, str]): Dict of the encoded relayAgentCircuitId and relayAgentRemoteId keys

    Returns:
        Dict[str, str]: Dict with the port, vlan, and switch values decoded as ASCII strings (if possible)
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


async def get_request_from_cat_center(
    curl: str, cheaders: Dict[str, str], params: Dict[str, str], client: str, dnac: str
) -> Tuple[Dict[str, str] | None]:
    try:
        async with httpx.AsyncClient(verify=tls_verify, timeout=REST_TIMEOUT) as hclient:
            response = await hclient.get(curl, headers=cheaders, params=params)
            response.raise_for_status()
    except Exception as e:
        logger.exception("Failed to find client %s in Catalyst Center %s: %s" % (client, dnac, getattr(e, "message", repr(e))))
        return (None, None)

    return (response.json(), response)


async def get_token_from_cat_center(dnac: str) -> str | None:

    turl = f"https://{dnac}/dna/system/api/v1/auth/token"
    theaders = {"content-type": "application/json"}
    try:
        async with httpx.AsyncClient(verify=tls_verify, timeout=REST_TIMEOUT) as client:
            response = await client.post(turl, headers=theaders, auth=BASIC_AUTH)
            response.raise_for_status()
    except Exception as e:
        logger.exception("Unable to get an auth token from Catalyst Center: %s" % getattr(e, "message", repr(e)))
        return None

    j = response.json()
    if "Token" not in j:
        logger.warning("Failed to get a Token element from Catalyst Center %s: %s" % (dnac, response.text))
        return None

    return j["Token"]


def process_cat_center_user(j: Dict[str, str], response: object, dnac: str) -> Dict[str, str] | None:
    if len(j) == 0 or "userDetails" not in j[0]:
        logger.warning("Got an unknown response from Catalyst Center %s: '%s'" % (dnac, response.text))
        return None

    if len(j[0]["userDetails"].keys()) == 0:
        return None

    return j[0]["userDetails"]


def process_cat_center_mac(j: Dict[str, str], dnac: str) -> Dict[str, str] | None:
    if "detail" not in j:
        logger.warning("Got an unknown response from Catalyst Center %s: '%s'" % (dnac, str(j)))
        return None

    if "errorCode" in j["detail"] or len(j["detail"].keys()) == 0:
        return None

    return j["detail"]


def build_dna_obj(dna_obj: Dict[str, str], detail: Dict[str, str]) -> Dict[str, str]:
    if "hostType" in detail:
        dna_obj["type"] = detail["hostType"]

    if "userId" in detail:
        dna_obj["user"] = detail["userId"]

    if "hostMac" in detail:
        dna_obj["mac"] = detail["hostMac"]

    if "hostOs" in detail and detail["hostOs"]:
        dna_obj["ostype"] = detail["hostOs"]
    elif "subType" in detail:
        dna_obj["ostype"] = detail["subType"]

    if "healthScore" in detail:
        for hscore in detail["healthScore"]:
            if hscore["healthType"] == "OVERALL":
                dna_obj["health"] = hscore["score"]
                if hscore["reason"] != "":
                    dna_obj["reason"] = hscore["reason"]
            elif hscore["healthType"] == "ONBOARDED":
                dna_obj["onboard"] = hscore["score"]
            elif hscore["healthType"] == "CONNECTED":
                dna_obj["connect"] = hscore["score"]

    if "ssid" in detail:
        dna_obj["ssid"] = detail["ssid"]

    if "location" in detail:
        dna_obj["location"] = detail["location"]

    if "clientConnection" in detail:
        dna_obj["ap"] = detail["clientConnection"]

    if "frequency" in detail:
        if detail["frequency"]:
            dna_obj["band"] = detail["frequency"] + " GHz"

    return dna_obj


async def check_for_reservation(input: CPNRReservationInput | dict) -> CPNRReservationResponse | None:
    """
    Check for a DHCP lease by IP or MAC address within CPNR.  Only one of IP address or MAC address is required.

    Args:
      CPNRReservationInput | dict: Input data, either a validated CPNRReservationInput (ip or mac)
            or a dict (for certain LLM compatibility).

    Returns:
      CPNRReservationResponse | None: A dict containing the MAC address and lease scope if a lease is found or None if the lease is not found or an error occurs

    Raises:
      ValueError: If both ip and mac were not specified
    """

    if isinstance(input, dict):
        input = CPNRReservationInput(**input)

    if not input.ip and not input.mac:
        raise ValueError("At least one of ip or mac must be specified")

    url: str
    params: Dict[str, str]
    mac_addr: str | None = None

    if input.ip:
        url = f"{DHCP_BASE}/Reservation/{input.ip}"
        params = {}
    else:
        mac_addr = str(normalize_mac(input.mac))
        url = f"{DHCP_BASE}/Reservation"
        params = {"lookupKey": mac_addr}

    try:
        async with httpx.AsyncClient(verify=False, timeout=REST_TIMEOUT) as client:
            response = await client.get(url, auth=BASIC_AUTH, params=params, headers=CNR_HEADERS)
            response.raise_for_status()
    except httpx.HTTPError as he:
        if he.response.status_code != 404:
            logger.exception(f"Did not get a good response from CPNR for reservation {input.ip or input.mac}: {he}")
        return None
    except Exception as e:
        logger.exception(f"Did not get a good response from CPNR for reservation {input.ip or input.mac}: {e}")
        return None

    rsvp = response.json()
    # Extract MAC address from lookupKey (last 6 octets)
    mac_value = ":".join(rsvp["lookupKey"].split(":")[-6:])
    scope_value = rsvp["scope"]

    return CPNRReservationResponse(mac=mac_value, scope=scope_value)


async def _get_dhcp_lease_info_from_cpnr(input: CPNRLeaseInput | dict) -> CPNRLeaseResponse | None:
    """
    Get a list of DHCP leases with hostname of the client, MAC address of the client, scope for the lease, state of the lease,
    DHCP relay information (switch, VLAN, and port), and whether the lease is reserved for a given MAC address
    or IP address from CPNR.

    Args:
        input (CPNRLeaseInput | dict): Input data, either a validated CPNRLeaseInput (ip or mac)
            or a dict (for certain LLM compatibility).
    """

    if isinstance(input, dict):
        input = CPNRLeaseInput(**input)

    if not input.mac and not input.ip:
        raise ValueError("At least one of mac or ip must be specified")

    url: str
    params: Dict[str, str]
    mac_addr: str | None = None

    if input.mac:
        mac_addr = str(normalize_mac(input.mac))
        url = f"{DHCP_BASE}/Lease"
        params = {"clientMacAddr": mac_addr}
        client_id = mac_addr
    else:
        url = f"{DHCP_BASE}/Lease/{input.ip}"
        params = {}
        client_id = str(input.ip)

    try:
        async with httpx.AsyncClient(verify=False, timeout=REST_TIMEOUT) as client:
            response = await client.get(url, auth=BASIC_AUTH, headers=CNR_HEADERS, params=params)
            response.raise_for_status()
    except httpx.HTTPError as he:
        if he.response.status_code != 404:
            logger.exception(f"Did not get a good response from CPNR for client {client_id}: {he}")
        return None
    except Exception as e:
        logger.exception(f"Did not get a good response from CPNR for client {client_id}: {e}")
        return None

    data = response.json()
    leases_data = data if input.mac else [data]

    leases: List[CPNRLeaseResponse] = []
    for lease in leases_data:
        if "address" not in lease or "clientMacAddr" not in lease:
            continue

        relay_info = parse_relay_info(lease)
        ip_addr = lease["address"]
        name = lease.get("clientHostName") or lease.get("clientDnsName") or "UNKNOWN"
        # Extract MAC address (after last comma)
        mac_field = lease["clientMacAddr"]
        mac_value = mac_field[mac_field.rfind(",") + 1 :]
        scope = lease["scopeName"]
        state = lease["state"]
        is_reserved = False

        rsvp = await check_for_reservation({"ip": ip_addr})
        if rsvp and rsvp.mac == mac_value:
            is_reserved = True

        leases.append(
            CPNRLeaseResponse(
                ip=ip_addr,
                name=name,
                mac=mac_value,
                scope=scope,
                state=state,
                relay_info=relay_info,
                is_reserved=is_reserved,
            )
        )

    return leases if leases else None


def _get_bssids_from_netconf(controller: str, bssids: dict[str, str]) -> None:
    """Get the per-WLAN BSSIDs from NETCONF"""

    # NETCONF filter for the radio operational data
    filter_xml = """
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <access-point-oper-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-wireless-access-point-oper">
        <radio-oper-data/>
        <ap-name-mac-map/>
      </access-point-oper-data>
    </filter>
    """

    try:
        with manager.connect(
            host=controller,
            port=830,
            username=NETCONF_USERNAME,
            password=NETCONF_PASSWORD,
            hostkey_verify=False,
            device_params={"name": "iosxe"},
            timeout=30,
        ) as m:
            # Get the operational data using NETCONF
            netconf_reply = m.get(filter=filter_xml)

            # Convert XML to dict using xmltodict
            data_dict = xmltodict.parse(netconf_reply.xml)

            # Get the AP name to MAC mapping
            ap_name_mac_map = data_dict.get("rpc-reply", {}).get("data", {}).get("access-point-oper-data", {}).get("ap-name-mac-map", {})

            # Ensure it's a list (xmltodict returns single items as dict, not list)
            if isinstance(ap_name_mac_map, dict):
                ap_name_mac_map = [ap_name_mac_map]
            elif not ap_name_mac_map:
                ap_name_mac_map = []

            mac_aps = {}
            for ap in ap_name_mac_map:
                if (ap_name := ap.get("wtp-name")) and (ap_mac := ap.get("wtp-mac")):
                    mac_aps[ap_mac] = ap_name

            # Navigate to the radio-oper-data in the response
            radio_oper_data = data_dict.get("rpc-reply", {}).get("data", {}).get("access-point-oper-data", {}).get("radio-oper-data", [])

            # Ensure it's a list (xmltodict returns single items as dict, not list)
            if isinstance(radio_oper_data, dict):
                radio_oper_data = [radio_oper_data]
            elif not radio_oper_data:
                radio_oper_data = []

            for ap in radio_oper_data:
                if (wtp_mac := ap.get("wtp-mac")) and (vap_config := ap.get("vap-oper-config")):
                    # vap-oper-config won't be present for monitor mode
                    # Ensure vap_config is a list
                    ap_name = mac_aps.get(wtp_mac, "unknown-ap")
                    if isinstance(vap_config, dict):
                        vap_config = [vap_config]
                    bssids.update({mac["bssid-mac"].lower(): ap_name for mac in vap_config})

    except Exception as e:
        logger.warning(f"NETCONF request failed: {e}")
        return


def _load_bssid_cache(cache_file: Path) -> dict[str, str]:
    """Load cached BSSIDs from file.

    Args:
        cache_file: Path to cache file

    Returns:
        Dictionary mapping BSSIDs to AP names
    """
    if not cache_file.exists():
        logger.info(f"Cache file {cache_file} does not exist, starting fresh")
        return {}

    try:
        with cache_file.open("r") as fd:
            bssids = json.load(fd)
            logger.info(f"Loaded cache with {len(bssids)} devices")
            return bssids
    except Exception as e:
        logger.error(f"Failed to load cache file {cache_file}: {e}")
        return {}


def _save_bssid_cache_atomic(cache_file: Path, bssids: dict) -> None:
    """Save interface state to cache file atomically.

    Args:
        cache_file: Path to cache file
        bssids: BSSID to AP name mapping to save
    """
    temp_file = cache_file.with_suffix(".tmp")

    try:
        # Write to temporary file
        with temp_file.open("w") as fd:
            json.dump(bssids, fd, indent=4)

        # Atomic replace
        temp_file.replace(cache_file)
        logger.debug(f"Saved cache with {len(bssids)} devices")
    except Exception as e:
        logger.error(f"Failed to save cache file {cache_file}: {e}")
        if temp_file.exists():
            temp_file.unlink()


def _refresh_bssid_cache(do_refresh: bool = False) -> dict[str, str]:
    """Refresh the BSSID cache from the controller via NETCONF.

    Args:
        controller: Controller hostname or IP
        cache_file: Path to cache file
    """
    bssids = _load_bssid_cache(Path("bssid_cache.json"))
    if not do_refresh:
        return bssids
    for controller in WLCS.split(","):
        controller = controller.strip()
        if controller:
            _get_bssids_from_netconf(controller, bssids)
    _save_bssid_cache_atomic(Path("bssid_cache.json"), bssids)

    return bssids


# TOOLS


@server_mcp.tool(
    annotations={
        "title": "Get Objects from NetBox",
        "readOnlyHint": True,
    }
)
async def get_object_info_from_netbox(inp: NetBoxInput | dict) -> List[NetBoxResponse]:
    """
    Query NetBox IPAM for devices/VMs by IP or hostname. Returns name, type, IP, contacts, and notes.

    Args:
        inp: NetBoxInput with ip OR hostname (mutually exclusive)
    """
    try:
        # Handle dict input for LLMs that pass JSON objects
        if isinstance(inp, dict):
            inp = NetBoxInput(**inp)

        # Determine query type
        # Ensure only one of ip or hostname is specified
        if inp.ip and inp.hostname:
            raise ValueError("Only one of 'ip' or 'hostname' may be specified.")
        if inp.ip:
            ip = str(inp.ip)
            name = None
        elif inp.hostname:
            name = str(inp.hostname)
            ip = None
        else:
            raise ValueError("Invalid input. Either 'ip' or 'hostname' property must be specified.")

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
            if "/" not in ip:
                for prefix in ("32", "31", "24", "128", "64", "16"):
                    ipa = pnb.ipam.ip_addresses.get(address=f"{ip}/{prefix}")
                    if ipa:
                        break
            else:
                ipa = pnb.ipam.ip_addresses.get(address=ip)
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


@server_mcp.tool(
    annotations={
        "title": "Get Webex Device Info",
        "readOnlyHint": True,
    },
    enabled=not is_testing,
)
async def get_webex_device_info(inp: WebexInfoInput | dict) -> WebexInfoResponse:
    """
    Get Webex device details by MAC, IP, or device name. Returns product info, serial, connection status, workspace location, and environmental metrics.

    Args:
      inp: WebexInfoInput with mac, ip, OR device_name (one required)
    """

    if isinstance(inp, dict):
        inp = WebexInfoInput(**inp)

    # Validate and parse input
    provided = [(k, v) for k, v in [("mac", inp.mac), ("ip", inp.ip), ("device_name", inp.device_name)] if v]
    if not provided:
        raise ToolError("At least one of mac, ip, or device_name must be specified")
    if len(provided) > 1:
        raise ToolError("Only one of mac, ip, or device_name may be specified")

    key, val = provided[0]
    if key == "mac":
        key = "mac"
        val = str(normalize_mac(val))
    elif key == "ip":
        key = "ip"
        val = str(val)
    elif key == "device_name":
        if val.lower().startswith("sep"):
            key = "mac"
            val = str(normalize_mac(val.lower().replace("sep", "")))
        else:
            key = "displayName"
            val = val

    async with Sparker(token=COLLAB_WEBEX_TOKEN, logit=True) as dev_spark:
        devices = await dev_spark.get_webex_devices_async()
        if not devices:
            raise ToolError("No devices found")

        for device in devices:
            if device[key].lower() == val.lower():
                workspace = await dev_spark.get_workspace_async(device["workspaceId"])
                location = workspace["displayName"] if workspace else None

                room_temperature = None
                room_humidity = None
                for metric, units in {"temperature": "degrees C", "humidity": "%"}.items():
                    details = await dev_spark.get_workspace_metric_async(device["workspaceId"], metric)
                    if details and len(details) > 0 and "mean" in details[0]:
                        value = f"{int(details[0]['mean'])} {units}"
                        if metric == "temperature":
                            room_temperature = value
                        elif metric == "humidity":
                            room_humidity = value

                return WebexInfoResponse(
                    name=device["displayName"],
                    product=device["product"],
                    device_type=device["type"],
                    mac=device["mac"],
                    ip=device["ip"],
                    serial_number=device["serial"],
                    software=device["software"],
                    connection_status=device["connectionStatus"],
                    connected_interface=device["activeInterface"],
                    location=location,
                    room_temperature=room_temperature,
                    room_humidity=room_humidity,
                )

        raise ToolError(f"No device found matching {key} {val}")


@server_mcp.tool(
    annotations={
        "title": "Get Webex Device Info",
        "readOnlyHint": True,
    },
    enabled=is_testing,
)
async def test_get_webex_device_info(inp: WebexInfoInput | dict) -> WebexInfoResponse:
    """
    Get Webex device details by MAC, IP, or device name. Returns product info, serial, connection status, workspace location, and environmental metrics.

    Args:
      inp: WebexInfoInput with mac, ip, OR device_name (one required)
    """

    if isinstance(inp, dict):
        inp = WebexInfoInput(**inp)

    # Validate input
    if not (inp.mac or inp.ip or inp.device_name):
        raise ToolError("At least one of mac, ip, or device_name must be specified")
    if sum([inp.mac is not None, inp.ip is not None, inp.device_name is not None]) > 1:
        raise ToolError("Only one of mac, ip, or device_name may be specified")

    # Return sample, but valid data for testing purposes
    sample_response = WebexInfoResponse(
        name=inp.device_name or "Test Webex Device",
        product="Webex Room Kit",
        device_type="Room Device",
        mac=inp.mac or "00:11:22:33:44:55",
        ip=inp.ip or "192.0.2.10",
        serial_number="ABC123XYZ",
        software="RoomOS 10.20.1",
        connection_status="Connected",
        connected_interface="Ethernet",
        location="Test Room",
        room_temperature="22 degrees C",
        room_humidity="45 %",
    )
    return sample_response


@server_mcp.tool(
    annotations={
        "title": "Convert Celsius to Fahrenheit",
        "readOnlyHint": True,
        "openWorldHint": False,
    }
)
async def convert_celsius_to_fahrenheit(degrees_celsius: int) -> int:
    """
    Convert Celsius to Fahrenheit (°C × 1.8 + 32).

    Args:
      degrees_celsius: Temperature in °C (≥-273)
    """
    if degrees_celsius < -273:
        raise ToolError("degrees_celsius must be greater than or equal to -273")

    return int((degrees_celsius * 1.8) + 32.0)


@server_mcp.tool(
    annotations={
        "title": "Generate Random Password",
        "readOnlyHint": True,
        "openWorldHint": False,
    }
)
async def generate_password(
    words: Annotated[int, Field(description="Number of words in the password", ge=3, le=6)] = 3, add_symbol: bool = False
) -> Annotated[str, Field(description="The generated password.")]:
    """
    Generate passphrase with word count (3-6) and optional symbol.

    Args:
      words: Word count (3-6, default: 3)
      add_symbol: Include symbol (default: False)
    """
    try:
        num_words = int(words)
    except ValueError:
        raise ToolError("num_words is not an integer")

    cmd = split(f"hankify-pw --num-words {num_words}")
    if add_symbol:
        cmd.append("--add-symbol")

    res = run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        return res.stdout

    raise ToolError(f"Error generating password: {res.stderr}")


@server_mcp.tool(
    annotations={
        "title": "Get AP name from BSSID",
        "readOnlyHint": True,
    },
    enabled=not is_testing,
)
async def get_ap_name_from_bssid(bssid: str) -> str:
    """
    Resolve AP name from BSSID (wireless MAC). Auto-refreshes cache if needed.

    Args:
        bssid: Access point BSSID (MAC address)
    """
    bssids = _refresh_bssid_cache(do_refresh=False)
    bssid_str = str(normalize_mac(bssid)).lower()
    if bssid_str in bssids:
        return bssids[bssid_str]
    else:
        bssids = _refresh_bssid_cache(do_refresh=True)
        if bssid_str in bssids:
            return bssids[bssid_str]
    raise ToolError(f"No AP name found for BSSID {bssid_str}")


@server_mcp.tool(
    annotations={
        "title": "Get Client Details from ISE",
        "readOnlyHint": True,
    },
    enabled=not is_testing,
)
async def get_user_details_from_ise(ise_input: ISEInput | dict) -> ISEResponse:
    """
    Query Cisco ISE for client auth session by username, MAC, or IP. Returns NAS, client IPs, AP, VLAN, SSID, and timestamp.

    Args:
        ise_input: ISEInput with username, mac, OR ip (one required)
    """

    if isinstance(ise_input, dict):
        ise_input = ISEInput(**ise_input)

    username = ise_input.username
    mac = ise_input.mac
    ip = ise_input.ip

    if not username and not mac and not ip:
        raise ToolError("One of username, mac, or ip is required")
    if sum([username is not None, mac is not None, ip is not None]) > 1:
        raise ToolError("Only one of username, mac, or ip may be specified")

    if mac:
        mac_str = str(normalize_mac(mac)).upper()
        url = f"https://{ISE_SERVER}/admin/API/mnt/Session/MACAddress/{mac_str}"
    elif ip:
        url = f"https://{ISE_SERVER}/admin/API/mnt/Session/EndPointIPAddress/{ip}"
    else:
        url = f"https://{ISE_SERVER}/admin/API/mnt/Session/UserName/{username}"

    try:
        async with httpx.AsyncClient(verify=tls_verify, timeout=REST_TIMEOUT) as client:
            response = await client.get(
                url,
                auth=(ISE_API_USER, ISE_API_PASS),
                headers={"Accept": "application/xml"},
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error getting client details from ISE: {e}", exc_info=True)
        raise ToolError(f"HTTP error {e.response.status_code}: {e.response.text}")
    except Exception as e:
        logger.error(f"Unable to get client details from ISE: {e}", exc_info=True)
        raise ToolError(e)

    session_details = xmltodict.parse(response.text)["sessionParameters"]

    # Required fields
    network_access_server = session_details.get("nas_ip_address")
    calling_station_id = session_details.get("calling_station_id")
    if calling_station_id:
        client_mac = str(normalize_mac(calling_station_id))
    else:
        client_mac = ""

    # Optional fields
    client_ipv4 = session_details.get("framed_ip_address")
    auth_username = username if username else session_details.get("user_name", "")

    # IPv6 addresses
    client_ipv6 = None
    framed_ipv6 = session_details.get("framed_ipv6_address")
    if framed_ipv6 and "ipv6_address" in framed_ipv6:
        ipv6_list = framed_ipv6["ipv6_address"]
        if isinstance(ipv6_list, str):
            client_ipv6 = [ipv6_list]
        elif isinstance(ipv6_list, list):
            client_ipv6 = [addr for addr in ipv6_list if addr]
        else:
            client_ipv6 = []
    else:
        client_ipv6 = None

    authentication_timestamp = session_details.get("auth_acs_timestamp")

    # Optional attributes from other_attr_string
    associated_access_point = None
    associated_ssid = None
    connected_vlan = None
    other_attr_string = session_details.get("other_attr_string", "")
    if other_attr_string:
        ap_match = re.search(r"Called-Station-ID=([a-fA-F0-9:-]+)", other_attr_string)
        ssid_match = re.search(r"cisco-wlan-ssid=([^,]+)", other_attr_string)
        vlan_match = re.search(r"vlan-id=([^,]+)", other_attr_string)

        if ap_match:
            associated_access_point = str(normalize_mac(ap_match.group(1)))
        if ssid_match:
            associated_ssid = ssid_match.group(1)
        if vlan_match:
            connected_vlan = vlan_match.group(1)

    return ISEResponse(
        username=auth_username,
        client_mac=client_mac,
        network_access_server=network_access_server,
        client_ipv4=client_ipv4,
        client_ipv6=client_ipv6,
        authentication_timestamp=authentication_timestamp,
        associated_access_point=associated_access_point,
        connected_vlan=connected_vlan,
        associated_ssid=associated_ssid,
    )


@server_mcp.tool(
    annotations={
        "title": "Get Client Details from ISE",
        "readOnlyHint": True,
    },
    enabled=is_testing,
)
async def test_get_user_details_from_ise(ise_input: ISEInput | dict) -> ISEResponse:
    """
    Query Cisco ISE for client auth session by username, MAC, or IP. Returns NAS, client IPs, AP, VLAN, SSID, and timestamp.

    Args:
        ise_input: ISEInput with username, mac, OR ip (one required)
    """

    if isinstance(ise_input, dict):
        ise_input = ISEInput(**ise_input)

    username = ise_input.username
    mac = ise_input.mac
    ip = ise_input.ip

    if not username and not mac and not ip:
        raise ToolError("One of username, mac, or ip is required")
    if sum([username is not None, mac is not None, ip is not None]) > 1:
        raise ToolError("Only one of username, mac, or ip may be specified")

    # Return sample, but valid data for testing purposes
    sample_response = ISEResponse(
        username=username or "testuser",
        client_mac=mac or "00:11:22:33:44:55",
        network_access_server=ip or "192.0.2.1",
        client_ipv4=ip or "192.0.2.10",
        client_ipv6=["2001:db8::1"],
        authentication_timestamp="2025-01-01T12:00:00Z",
        associated_access_point="aa:bb:cc:dd:ee:ff",
        connected_vlan="100",
        associated_ssid="TestSSID",
    )
    return sample_response


@server_mcp.tool(
    annotations={
        "title": "Get Client Details from Catalyst Center",
        "readOnlyHint": True,
    },
    enabled=not is_testing,
)
async def get_client_details_from_cat_center(
    input_data: DNACInput | dict,
) -> DNACResponse:
    """
    Query Cisco Catalyst Center (DNA Center) for client health metrics by username, MAC, or IP. Returns device type, OS, health scores (overall/onboard/connect), AP, and SSID.

    Args:
       input_data: DNACInput with username, mac, OR ip (one required)
    """
    # Validate input
    if isinstance(input_data, dict):
        input_data = DNACInput(**input_data)

    username = input_data.username
    mac = input_data.mac
    ip = input_data.ip

    if not username and not mac and not ip:
        raise ToolError("At least one of username, mac, or ip must be specified")
    if sum([username is not None, mac is not None, ip is not None]) > 1:
        raise ToolError("Only one of username, mac, or ip may be specified")

    dna_obj: Dict[str, str | int | None] = {
        "user": None,
        "mac": None,
        "type": None,
        "ostype": None,
        "health": None,
        "reason": None,
        "onboard": None,
        "connect": None,
        "ssid": None,
    }

    macs: List[str] = []

    # If only IP is provided, try to resolve MAC(s) via DHCP lease info
    if ip and not mac and not username:
        leases = await _get_dhcp_lease_info_from_cpnr({"ip": ip})
        if leases and len(leases) > 0:
            macs = [le["mac"] for le in leases if "mac" in le]
        else:
            raise ToolError("No MAC address found for given IP")
    elif mac:
        macs = [str(normalize_mac(mac))]

    dnacs = [dnac.strip() for dnac in DNACS.split(",") if dnac.strip()]
    if not dnacs:
        raise ToolError("No Catalyst Center servers configured")

    for dnac in dnacs:
        token = await get_token_from_cat_center(dnac)
        if not token:
            continue

        detail: Dict[str, str | int | None] = {}

        if username:
            curl = f"https://{dnac}/dna/intent/api/v1/client-enrichment-details"
            cheaders = {
                "accept": "application/json",
                "x-auth-token": token,
                "entity_type": "network_user_id",
                "entity_value": username,
            }
            params: Dict[str, str] = {}
            client = username

            j, response = await get_request_from_cat_center(curl, cheaders, params, client, dnac)
            if not j:
                continue

            detail = process_cat_center_user(j, response, dnac)
            if not detail:
                continue

        else:
            curl = f"https://{dnac}/dna/intent/api/v1/client-detail"
            cheaders = {"accept": "application/json", "x-auth-token": token}
            jsons: Dict[str, Dict[str, str]] = {}

            for macaddr in macs:
                params = {"macAddress": macaddr}
                client = macaddr
                j, response = await get_request_from_cat_center(curl, cheaders, params, client, dnac)
                if j:
                    jsons[macaddr] = j

            if not jsons:
                continue

            for macaddr, j in jsons.items():
                detail = process_cat_center_mac(j, dnac)
                if detail:
                    dna_obj["mac"] = macaddr
                    break

        if detail:
            dna_obj = build_dna_obj(dna_obj, detail)
            # Map to DNACResponse using proper types
            return DNACResponse(
                user=dna_obj.get("user"),
                mac=dna_obj.get("mac"),
                type=dna_obj.get("type"),
                ostype=dna_obj.get("ostype"),
                health=int(dna_obj["health"]) if dna_obj.get("health") is not None else None,
                reason=dna_obj.get("reason"),
                onboard=int(dna_obj["onboard"]) if dna_obj.get("onboard") is not None else None,
                connect=int(dna_obj["connect"]) if dna_obj.get("connect") is not None else None,
                ssid=dna_obj.get("ssid"),
            )

    raise ToolError("No client details found in Catalyst Center")


@server_mcp.tool(
    annotations={
        "title": "Get Client Details from Catalyst Center",
        "readOnlyHint": True,
    },
    enabled=is_testing,
)
async def test_get_client_details_from_cat_center(
    input_data: DNACInput | dict,
) -> DNACResponse:
    """
    Query Cisco Catalyst Center (DNA Center) for client health metrics by username, MAC, or IP. Returns device type, OS, health scores (overall/onboard/connect), AP, and SSID.

    Args:
       input_data: DNACInput with username, mac, OR ip (one required)
    """
    # Validate input
    if isinstance(input_data, dict):
        input_data = DNACInput(**input_data)

    username = input_data.username
    mac = input_data.mac
    ip = input_data.ip

    if not username and not mac and not ip:
        raise ToolError("At least one of username, mac, or ip must be specified")
    if sum([username is not None, mac is not None, ip is not None]) > 1:
        raise ToolError("Only one of username, mac, or ip may be specified")

    # Return sample, but valid data for testing purposes
    sample_response = DNACResponse(
        user=username or "testuser",
        mac=mac or "00:11:22:33:44:55",
        type="Wireless",
        ostype="Windows",
        health=95,
        reason="Good signal",
        onboard=100,
        connect=90,
        ssid="TestSSID",
    )
    return sample_response


@server_mcp.tool(
    annotations={
        "title": "Get DHCP Lease Info from CPNR",
        "readOnlyHint": True,
    },
    enabled=not is_testing,
)
async def get_dhcp_lease_info_from_cpnr(input: CPNRLeaseInput | dict) -> List[CPNRLeaseResponse]:
    """
    Query Cisco Prime Network Registrar (CPNR) for DHCP lease by IP or MAC. Returns hostname, MAC, scope, state, relay info (switch/VLAN/port), and reservation status.

    Args:
        input: CPNRLeaseInput with ip OR mac (one required)
    """

    leases = await _get_dhcp_lease_info_from_cpnr(input)
    if leases:
        return leases

    raise ToolError("No DHCP lease information found in CPNR")


@server_mcp.tool(
    annotations={
        "title": "Get DHCP Lease Info from CPNR",
        "readOnlyHint": True,
    },
    enabled=is_testing,
)
async def test_get_dhcp_lease_info_from_cpnr(input: CPNRLeaseInput | dict) -> List[CPNRLeaseResponse]:
    """
    Query Cisco Prime Network Registrar (CPNR) for DHCP lease by IP or MAC. Returns hostname, MAC, scope, state, relay info (switch/VLAN/port), and reservation status.

    Args:
        input: CPNRLeaseInput with ip OR mac (one required)
    """

    if isinstance(input, dict):
        input = CPNRLeaseInput(**input)

    if not input.mac and not input.ip:
        raise ToolError("At least one of mac or ip must be specified")
    if input.mac is not None and input.ip is not None:
        raise ToolError("Only one of mac or ip may be specified")

    # Return sample, but valid data for testing purposes
    # Use input data for sample response
    ip = input.ip or "192.0.2.10"
    mac = input.mac or "00:11:22:33:44:55"
    sample_lease = CPNRLeaseResponse(
        ip=ip,
        name="test-host",
        mac=mac,
        scope="TestScope",
        state="LEASED",
        relay_info={"vlan": "100", "port": "Ethernet1/0/1", "switch": "test-switch"},
        is_reserved=False,
    )
    return [sample_lease]


@server_mcp.tool(
    annotations={
        "title": "Delete DHCP Reservation from CPNR",
        "readOnlyHint": False,
        "destructiveHint": True,
    },
    enabled=not is_testing,
    meta={"auth_list": ALLOWED_TO_DELETE},
)
async def delete_dhcp_reservation_from_cpnr(ip: IPAddress) -> bool:
    """
    Remove DHCP reservation from CPNR by IP. Destructive operation.

    Args:
      ip: Reserved IP address to delete
    """

    if not ip:
        raise ToolError("IP address is required")

    url = f"{DHCP_BASE}/Reservation/{ip}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=REST_TIMEOUT) as client:
            response = await client.delete(url, auth=BASIC_AUTH, headers=CNR_HEADERS)
            response.raise_for_status()
    except httpx.HTTPStatusError as he:
        logger.error(f"HTTP error deleting reservation for {ip} from CPNR: {he}", exc_info=True)
        raise ToolError(f"HTTP error {he.response.status_code}: {he.response.text}")
    except Exception as e:
        msg = "Failed to delete reservation for %s: %s" % (ip, str(e))
        logger.exception(msg)
        raise ToolError(msg)

    return True


@server_mcp.tool(
    annotations={
        "title": "Delete DHCP Reservation from CPNR",
        "readOnlyHint": False,
        "destructiveHint": True,
    },
    enabled=is_testing,
    meta={"auth_list": ALLOWED_TO_DELETE},
)
async def test_delete_dhcp_reservation_from_cpnr(ip: IPAddress) -> bool:
    """
    Remove DHCP reservation from CPNR by IP. Destructive operation.

    Args:
      ip: Reserved IP address to delete
    """

    if not ip:
        raise ToolError("IP address is required")

    return True


@server_mcp.tool(
    annotations={
        "title": "Create DHCP Reservation in CPNR",
        "readOnlyHint": False,
    },
    enabled=not is_testing,
)
async def create_dhcp_reservation_in_cpnr(ip: IPAddress) -> bool:
    """
    Reserve leased IP in CPNR for current client MAC. Requires active lease.

    Args:
      ip: IP address currently leased to reserve
    """

    if not ip:
        raise ToolError("IP address is required")

    # Check if reservation already exists
    rsvp = await check_for_reservation({"ip": ip})
    if rsvp:
        raise ToolError(f"IP {ip} is already reserved for {rsvp.mac}")

    # Get DHCP lease info for the IP
    leases = await _get_dhcp_lease_info_from_cpnr({"ip": ip})
    if not leases or len(leases) == 0:
        raise ToolError(f"IP {ip} is not currently leased")

    # Find the lease with state 'LEASED' if multiple, else use the first
    lease: CPNRLeaseResponse
    if len(leases) > 1:
        lease = next((le for le in leases if le.state.lower() == "leased"), leases[0])
    else:
        lease = leases[0]

    mac_addr = str(normalize_mac(lease.mac))

    url = f"{DHCP_BASE}/Reservation"
    payload = {
        "ipaddr": ip,
        "lookupKey": f"01:06:{mac_addr}",
        "lookupKeyType": AT_MACADDR,
    }
    try:
        async with httpx.AsyncClient(verify=False, timeout=REST_TIMEOUT) as client:
            response = await client.post(url, auth=BASIC_AUTH, headers=CNR_HEADERS, json=payload)
            response.raise_for_status()
    except httpx.HTTPStatusError as he:
        logger.error(f"HTTP error creating reservation for {ip} => {mac_addr} in CPNR: {he}", exc_info=True)
        raise ToolError(f"HTTP error {he.response.status_code}: {he.response.text}")
    except Exception as e:
        msg = f"Failed to create DHCP reservation for {ip} => {mac_addr}: {e}"
        logger.exception(msg)
        raise ToolError(msg)

    return True


@server_mcp.tool(
    annotations={
        "title": "Create DHCP Reservation in CPNR",
        "readOnlyHint": False,
    },
    enabled=is_testing,
)
async def test_create_dhcp_reservation_in_cpnr(ip: IPAddress) -> bool:
    """
    Reserve leased IP in CPNR for current client MAC. Requires active lease.

    Args:
      ip: IP address currently leased to reserve
    """

    if not ip:
        raise ToolError("IP address is required")

    return True


@server_mcp.tool(
    annotations={
        "title": "Perform DNS Lookup",
        "readOnlyHint": True,
    }
)
async def perform_dns_lookup(input: DNSInput | dict) -> DNSResponse:
    """
    DNS lookup: forward (A/AAAA/CNAME) or reverse (PTR). Auto-appends domain for short hostnames.

    Args:
        input: DNSInput with ip OR hostname (one required)
    """

    if isinstance(input, dict):
        input = DNSInput(**input)

    ip = input.ip
    hostname = input.hostname
    target = ip or hostname
    if not target:
        raise ToolError("Either ip or hostname must be provided")
    if ip is not None and hostname is not None:
        raise ToolError("Only one of ip or hostname may be specified")

    record_type = ""
    results: List[str] = []

    try:
        if ip:
            # Reverse DNS lookup (PTR record)
            if "/" in ip:
                ip = ip.split("/")[0]
            rev_name = dns.reversename.from_address(ip)
            try:
                answer = await dns.asyncresolver.resolve(rev_name, "PTR", lifetime=DNS_TIMEOUT)
                record_type = "PTR"
                results = [str(r) for r in answer]
            except Exception:
                record_type = "PTR"
                results = []
        else:
            if "." not in hostname:
                hostname = f"{hostname}.{DNS_DOMAIN}"
            # Forward DNS lookup (A, AAAA, and CNAME records)
            record_types = ["A", "AAAA", "CNAME"]
            all_results = []
            for rtype in record_types:
                try:
                    answer = await dns.asyncresolver.resolve(hostname, rtype, lifetime=DNS_TIMEOUT)
                    if rtype == "CNAME":
                        all_results.extend([str(r.target) for r in answer])
                    else:
                        all_results.extend([str(r) for r in answer])
                except Exception:
                    continue
            if all_results:
                record_type = ",".join([rtype for rtype in record_types if any(rtype in str(res) for res in all_results)])
                results = all_results
            else:
                record_type = ",".join(record_types)
                results = [hostname]

    except Exception as e:
        raise ToolError(f"DNS lookup failed: {e}")

    return DNSResponse(
        query=target,
        record_type=record_type,
        results=results,
    )


if __name__ == "__main__":
    DHCP_BASE = os.getenv("DHCP_BASE")
    BASIC_AUTH = (os.getenv("CPNR_USERNAME"), os.getenv("CPNR_PASSWORD"))
    REST_TIMEOUT = int(os.getenv("DHCP_BOT_REST_TIMEOUT", "10"))
    DNS_TIMEOUT = float(os.getenv("DHCP_BOT_DNS_TIMEOUT", "5.0"))
    COLLAB_WEBEX_TOKEN = os.getenv("COLLAB_WEBEX_TOKEN")
    ISE_SERVER = os.getenv("ISE_SERVER")
    ISE_API_USER = os.getenv("ISE_API_USER")
    ISE_API_PASS = os.getenv("ISE_API_PASS")
    DNACS = os.getenv("DNACS", "")
    WLCS = os.getenv("WLCS", "")
    DNS_DOMAIN = os.getenv("DNS_DOMAIN")
    NETCONF_USERNAME = os.getenv("NETCONF_USERNAME")
    NETCONF_PASSWORD = os.getenv("NETCONF_PASSWORD")

    pnb = pynetbox.api(os.getenv("NETBOX_SERVER"), os.getenv("NETBOX_API_TOKEN"))
    tls_verify = os.getenv("DHCP_BOT_TLS_VERIFY", "True").lower() == "true"
    pnb.http_session.verify = tls_verify

    asyncio.run(server_mcp.run_async())
