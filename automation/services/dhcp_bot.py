#!/usr/bin/env python
#
# Copyright (c) 2017-2025  Joe Clarke <jclarke@cisco.com>
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

from flask import Flask, jsonify, request
import json
import os
import logging
from sparker import Sparker, MessageType  # type: ignore
from typing import Dict, List, Union
import re
from hashlib import sha1
import hmac
import requests
from collections import OrderedDict
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import traceback
import pynetbox
import inspect
from ollama import Client, ChatResponse
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

AT_MACADDR = 9

CNR_HEADERS = {"Accept": "application/json"}
BASIC_AUTH = (CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD)
REST_TIMEOUT = 10

DEFAULT_INT_TYPE = "Ethernet"

ALLOWED_TO_DELETE = ["jclarke@cisco.com", "josterfe@cisco.com", "anjesani@cisco.com"]

SPARK_ROOM = "DHCP Queries"
CALLBACK_URL = "https://cleur-dhcp-hook.ciscolive.network/chat"
BOT_NAME = "DHCP Bot"
ME = "livenocbot@sparkbot.io"

MODEL = "llama3.3"

webhook_id = None
app = Flask(BOT_NAME)

# Set our initial logging level.
log_level = os.getenv("LOG_LEVEL")
if not log_level:
    log_level = "INFO"

logging.basicConfig(
    format="[%(asctime)s.%(msecs)03d] [%(levelname)s] [%(filename)s] [%(funcName)s():%(lineno)s] [PID:%(process)d TID:%(thread)d] %(message)s"
)
logging.getLogger().setLevel(log_level)


class DhcpHook(object):

    def __init__(self, pnb: pynetbox.api):
        self.pnb = pnb

    @staticmethod
    def is_ascii(s: str) -> bool:
        """
        Check if a string contains all ASCII characters.

        Args:
        s (str): String to check

        Returns:
        bool: True if all characters in the string are ASCII; False otherwise
        """
        return all(ord(c) < 128 for c in s)

    @staticmethod
    def normalize_mac(mac: str) -> str:
        """
        Normalize all MAC addresses to colon-delimited and lower case.

        Args:
          mac (str): MAC address to normalize

        Returns:
          str: The normalized MAC address
        """
        mac_addr = "".join(l + ":" * (n % 2 == 1) for n, l in enumerate(list(re.sub(r"[:.-]", "", mac)))).strip(":")

        return mac_addr.lower()

    @staticmethod
    def parse_relay_info(outd: Dict[str, str]) -> Dict[str, str]:
        """
        Parse DHCP relay information and produce a string for the connected switch and port.

        Args:
          outd (Dict[str, str]): Dict of the encoded relayAgentCircuitId and relayAgentRemoteId keys

        Returns:
          Dict[str, str]: Dict with the port, vlan, and switch values decoded as ASCII strings (if possible)
        """
        global DEFAULT_INT_TYPE

        res = {"vlan": "N/A", "port": "N/A", "switch": "N/A"}
        if "relayAgentCircuitId" in outd:
            octets = outd["relayAgentCircuitId"].split(":")
            if len(octets) > 4:
                res["vlan"] = int("".join(octets[2:4]), 16)
                first_part = int(octets[4], 16)
                port = str(first_part)
                if first_part != 0:
                    port = str(first_part) + "/0"
                res["port"] = DEFAULT_INT_TYPE + port + "/" + str(int(octets[5], 16))

        if "relayAgentRemoteId" in outd:
            octets = outd["relayAgentRemoteId"].split(":")
            res["switch"] = bytes.fromhex("".join(octets[2:])).decode("utf-8", "ignore")
            if not DhcpHook.is_ascii(res["switch"]) or res["switch"] == "":
                res["switch"] = "N/A"

        return res

    @staticmethod
    def check_for_reservation(ip: Union[str, None] = None, mac: Union[str, None] = None) -> Union[Dict[str, str], None]:
        """
        Check for a DHCP lease by IP or MAC address within CPNR.  Only one of IP address or MAC address is required.

        Args:
          ip (Union[str, None], optional): IP address of the lease to check (at least ip or mac must be specified)
          mac (Union[str, None], optional): MAC address of the lease to check (at least ip or mac must be specified)

        Returns:
          Union[Dict[str, str], None]: A dict containing the MAC address and lease scope if a lease is found or None if the lease is not found or an error occurs

        Raises:
          ValueError: If both ip and mac were not specified
        """
        global CNR_HEADERS, BASIC_AUTH, REST_TIMEOUT

        if not ip and not mac:
            raise ValueError("At least one of ip or mac must be specified")

        res = {}

        if ip:
            url = f"{C.DHCP_BASE}/Reservation/{ip}"
            params = {}
            mac_addr = None
        else:
            mac_addr = DhcpHook.normalize_mac(mac)
            url = f"{C.DHCP_BASE}/Reservation"
            params = {"lookupKey": mac_addr}

        try:
            response = requests.request("GET", url, auth=BASIC_AUTH, params=params, headers=CNR_HEADERS, verify=False, timeout=REST_TIMEOUT)
            response.raise_for_status()
        except requests.HTTPError as he:
            if he.response.status_code != 404:
                logging.exception("Did not get a good response from CPNR for reservation %s: %s" % (ip, he))

            return None
        except Exception as e:
            logging.exception("Did not get a good response from CPNR for reservation %s: %s" % (ip, e))
            return None

        rsvp = response.json()
        res["mac"] = ":".join(rsvp["lookupKey"].split(":")[-6:])
        res["scope"] = rsvp["scope"]

        return res

    def create_dhcp_reservation_in_cpnr(self, ip: str) -> Dict[str, Union[str, bool]]:
        """
        Create a new DHCP reservation in CPNR.

        Args:
          ip (str): IP address that is leased to the client

        Returns:
          Dict[str, Union[str, bool]]: A dict with keys "success" (bool) if the reservation was created successfully and "error" if the success is False
        """
        global CNR_HEADERS, BASIC_AUTH, AT_MACADDR, REST_TIMEOUT

        if not ip:
            return {"success": False, "error": "Both ip and mac must be specified"}

        mac = DhcpHook.check_for_reservation(ip=ip)
        if not mac:
            return {"success": False, "error": "IP %s is not currently leased" % ip}

        mac_addr = DhcpHook.normalize_mac(mac["mac"])

        url = f"{C.DHCP_BASE}/Reservation"
        payload = {"ipaddr": ip, "lookupKey": "01:06:" + mac_addr, "lookupKeyType": AT_MACADDR}
        try:
            response = requests.request("POST", url, auth=BASIC_AUTH, headers=CNR_HEADERS, json=payload, verify=False, timeout=REST_TIMEOUT)
            response.raise_for_status()
        except Exception as e:
            msg = "Failed to create DHCP reservation for %s => %s: %s" % (ip, mac_addr, str(e))
            logging.exception(msg)
            return {"success": False, "error": msg}

        return {"success": True}

    def delete_dhcp_reservation_from_cpnr(self, ip: str) -> Dict[str, Union[str, bool]]:
        """
        Delete a DHCP reservation from CPNR.

        Args:
          ip (str): IP address that is reserved in CPNR

        Returns:
          Dict[str, Union[str, bool]]: A dict with keys "success" (bool) if the reservation was deleted successfully and "error" if the success is False
        """
        global CNR_HEADERS, BASIC_AUTH, REST_TIMEOUT

        if not ip:
            return {"success": False, "error": "ip must be specified"}

        url = f"{C.DHCP_BASE}/Reservation/{ip}"
        try:
            response = requests.request("DELETE", url, auth=BASIC_AUTH, headers=CNR_HEADERS, verify=False, timeout=REST_TIMEOUT)
            response.raise_for_status()
        except Exception as e:
            msg = "Failed to delete reservation for %s: %s" % (ip, str(e))
            logging.exception(msg)
            return {"success": False, "error": msg}

        return {"success": True}

    # Only these users are allowed to delete reservations.
    delete_dhcp_reservation_from_cpnr.auth_list = ALLOWED_TO_DELETE

    # def get_dhcp_lease_info_from_cpnr(self, ip: str) -> Dict[str, str] | None:
    #     """
    #     Get DHCP lease information from CPNR based on the IP address of a client.

    #     Args:
    #       ip (str): IP address of the client

    #     Returns:
    #       Dict[str, str]|None: A dict of DHCP lease details with keys "name" (hostname of the client), "mac" (client MAC address), "scope" (DHCP scope in which the IP is leased),
    #                            "state" (lease state), "relay-info" (DHCP relay details which is a dict with key "switch" (switch client is connected to), "vlan" (VLAN the client is on), and "port"
    #                            (port client is connected to)), and "is-reserved" (True if the lease is reserved) or None if the lease was not found in CPNR

    #     """
    #     global CNR_HEADERS, BASIC_AUTH, REST_TIMEOUT

    #     if not ip:
    #         return None

    #     res = {}
    #     url = f"{C.DHCP_LEASE}/Lease/{ip}"
    #     try:
    #         response = requests.request("GET", url, auth=BASIC_AUTH, headers=CNR_HEADERS, verify=False, timeout=REST_TIMEOUT)
    #         response.raise_for_status()
    #     except Exception as e:
    #         logging.exception("Did not get a good response from CPNR for IP %s: %s" % (ip, e))
    #         return None

    #     lease = response.json()

    #     if "clientMacAddr" not in lease:
    #         return None

    #     relay = DhcpHook.parse_relay_info(lease)
    #     if "clientHostName" in lease:
    #         res["name"] = lease["clientHostName"]
    #     elif "client-dns-name" in lease:
    #         res["name"] = lease["clientDnsName"]
    #     else:
    #         res["name"] = "UNKNOWN"

    #     pos = lease["clientMacAddr"].rfind(",") + 1

    #     res["mac"] = lease["clientMacAddr"][pos:]
    #     res["scope"] = lease["scopeName"]
    #     res["state"] = lease["state"]
    #     res["relay-info"] = relay
    #     rsvp = DhcpHook.check_for_reservation(ip=ip)
    #     if rsvp and rsvp["mac"] == res["mac"]:
    #         res["is-reserved"] = True

    #     return res

    def get_dhcp_lease_info_from_cpnr(self, mac: Union[str, None] = None, ip: Union[str, None] = None) -> Union[List[Dict[str, str]], None]:
        """
        Get a list of DHCP leases with hostname of the client, MAC address of the client, scope for the lease, state of the lease,
        DHCP relay information (switch, VLAN, and port), and whether the lease is reserved for a given MAC address from CPNR.

        Args:
          mac (Union[str, None], optional): MAC address of the client (at least one of mac or ip is required)
          ip (Union[str, None], optional): IP address of the client (at least one of mac or ip is required)

        Returns:
          Union[List[Dict[str,str]], None]: A list of dicts where each dict contains lease details with the keys "name" (hostname of the client), "mac" (client MAC address),
                                    "scope" (DHCP scope in which the IP is leased), "state" (lease state),
                                    "relay-info" (DHCP relay details which is a dict with key "switch" (switch client is connected to), "vlan" (VLAN the client is on), and "port"
                                    (port client is connected to)), and "is-reserved" (True if the lease is reserved) or None if the lease was not found in CPNR
        """
        global CNR_HEADERS, BASIC_AUTH, REST_TIMEOUT

        if not mac and not ip:
            raise ValueError("At least one of mac or ip must be specified")

        if mac:
            url = f"{C.DHCP_BASE}/Lease"
            params = {"clientMacAddr": mac}
            client = mac
        else:
            url = f"{C.DHCP_BASE}/Lease/{ip}"
            params = {}
            client = ip

        try:
            response = requests.request("GET", url, auth=BASIC_AUTH, headers=CNR_HEADERS, verify=False, params=params, timeout=REST_TIMEOUT)
            response.raise_for_status()
        except requests.HTTPError as he:
            if he.response.status_code != 404:
                logging.exception("Did not get a good response from CPNR for client %s: %s" % (client, str(he)))

            return None
        except Exception as e:
            logging.exception("Did not get a good response from CPNR for client %s: %s" % (client, str(e)))
            return None

        j = response.json()
        if mac:
            if len(j) == 0:
                return None

            cpnr_leases = j
        else:
            cpnr_leases = [j]

        leases = []
        for lease in cpnr_leases:
            res = {}
            if "address" not in lease or "clientMacAddr" not in lease:
                continue
            relay = DhcpHook.parse_relay_info(lease)
            res["ip"] = lease["address"]
            if "clientHostName" in lease:
                res["name"] = lease["clientHostName"]
            elif "clientDnsName" in lease:
                res["name"] = lease["clientDnsName"]
            else:
                res["name"] = "UNKNOWN"

            pos = lease["clientMacAddr"].rfind(",") + 1

            res["mac"] = lease["clientMacAddr"][pos:]
            res["scope"] = lease["scopeName"]
            res["state"] = lease["state"]
            res["relay-info"] = relay
            rsvp = DhcpHook.check_for_reservation(ip=res["ip"])
            if rsvp and rsvp["mac"] == res["mac"]:
                res["is-reserved"] = True

            leases.append(res)

        return leases

    def get_object_info_from_netbox(self, ip: str) -> Union[Dict[str, str], None]:
        """
        Obtain type and name of an object from NetBox.

        Args:
          ip (str): IP address of object to lookup in NetBox

        Returns:
          Union[Dict[str, str], None]: A dict with keys for "name" and "type" of the object or None if the object is not found in NetBox
        """
        if not ip:
            return None

        for prefix in ("24", "31", "32", "16", "64", "128"):
            ipa = self.pnb.ipam.ip_addresses.get(address=f"{ip}/{prefix}")
            if ipa:
                break

        if ipa:
            ipa.full_details()
            if ipa.assigned_object_type == "virtualization.vminterface":
                return {"type": "VM", "name": str(ipa.assigned_object.virtual_machine)}
            elif ipa.assigned_object_type == "dcim.interface":
                return {"type": "device", "name": str(ipa.assigned_object.device)}

        return None

    def get_client_details_from_cat_center(
        self, user: Union[str, None] = None, mac: Union[str, None] = None
    ) -> Union[Dict[str, str], None]:
        """
        Obtain client connect and onboard health, location, OS type, associated AP and SSID, and type from Catalyst Center based on the client's username or MAC address.
        At least one of the client's username or MAC address is required.

        Args:
            user (Union[str, None]): Username of the client (at least user or mac is required)
            mac (Union[str, None]): MAC address of the client (at least user or mac is required)

        Returns:
            Union[Dict[str,str], None]: A dict with client "ostype" (OS type), "type", "location", "ap" (associated AP), "ssid" (associated SSID), "health" (health score), "onboard" (onboarding score),
                                "connect" (connection score), "reason" (error reason if an error occurred), "band" (WiFi band) as keys or None if client was not found in Catalyst Center
        """
        global BASIC_AUTH, REST_TIMEOUT

        if not user and not mac:
            raise ValueError("At least one of user or mac must be specified")

        dna_obj = {
            "ostype": None,
            "type": None,
            "location": None,
            "ap": None,
            "ssid": None,
            "health": None,
            "onboard": None,
            "connect": None,
            "reason": None,
            "band": None,
            "mac": None,
        }

        for dnac in C.DNACS:
            turl = f"https://{dnac}/dna/system/api/v1/auth/token"
            theaders = {"content-type": "application/json"}
            try:
                response = requests.request("POST", turl, headers=theaders, auth=BASIC_AUTH, verify=False, timeout=REST_TIMEOUT)
                response.raise_for_status()
            except Exception as e:
                logging.exception("Unable to get an auth token from Catalyst Center: %s" % getattr(e, "message", repr(e)))
                continue

            j = response.json()
            if "Token" not in j:
                logging.warning("Failed to get a Token element from Catalyst Center %s: %s" % (dnac, response.text))
                continue

            if user:
                curl = f"https://{dnac}/dna/intent/api/v1/client-enrichment-details"

                cheaders = {
                    "accept": "application/json",
                    "x-auth-token": j["Token"],
                    "entity_type": "network_user_id",
                    "entity_value": user,
                }
                params = {}
                client = user
            else:
                curl = f"https://{dnac}/dna/intent/api/v1/client-detail"

                cheaders = {"accept": "application/json", "x-auth-token": j["Token"]}
                # params = {"macAddress": kwargs["mac"], "timestamp": epoch}
                params = {"macAddress": mac}
                client = mac
                dna_obj["mac"] = mac

            try:
                response = requests.request("GET", curl, headers=cheaders, params=params, verify=False, timeout=REST_TIMEOUT)
                response.raise_for_status()
            except Exception as e:
                logging.exception("Failed to find client %s in Catalyst Center %s: %s" % (client, dnac, getattr(e, "message", repr(e))))
                continue

            j = response.json()

            if user:
                if len(j) == 0 or "userDetails" not in j[0]:
                    logging.warning("Got an unknown response from Catalyst Center %s: '%s'" % (dnac, response.text))
                    continue

                if len(j[0]["userDetails"].keys()) == 0:
                    continue

                detail = j[0]["userDetails"]

                # if "hostType" in detail:
                #     dna_obj["type"] = detail["hostType"]

                # if "userId" in detail:
                #     dna_obj["user"] = detail["userId"]

                # if "hostMac" in detail:
                #     dna_obj["mac"] = detail["hostMac"]

                # if "hostOs" in detail and detail["hostOs"]:
                #     dna_obj["ostype"] = detail["hostOs"]
                # elif "subType" in detail:
                #     dna_obj["ostype"] = detail["subType"]

                # if "healthScore" in detail:
                #     for hscore in detail["healthScore"]:
                #         if hscore["healthType"] == "OVERALL":
                #             dna_obj["health"] = hscore["score"]
                #             if hscore["reason"] != "":
                #                 dna_obj["reason"] = hscore["reason"]
                #         elif hscore["healthType"] == "ONBOARDED":
                #             dna_obj["onboard"] = hscore["score"]
                #         elif hscore["healthType"] == "CONNECTED":
                #             dna_obj["connect"] = hscore["score"]

                # if "ssid" in detail:
                #     dna_obj["ssid"] = detail["ssid"]

                # if "location" in detail:
                #     dna_obj["location"] = detail["location"]

                # if "clientConnection" in detail:
                #     dna_obj["ap"] = detail["clientConnection"]

                # if "frequency" in detail:
                #     dna_obj["band"] = detail["frequency"]

                # return dna_obj
            else:
                if "detail" not in j:
                    logging.warning("Got an unknown response from Catalyst Center %s: '%s'" % (dnac, response.text))
                    continue

                if "errorCode" in j["detail"] or len(j["detail"].keys()) == 0:
                    continue

                detail = j["detail"]

                # if "hostType" in detail:
                #     dna_obj["type"] = detail["hostType"]

                # if "userId" in detail:
                #     dna_obj["user"] = detail["userId"]

                # if "hostOs" in detail and detail["hostOs"]:
                #     dna_obj["ostype"] = detail["hostOs"]
                # elif "subType" in detail:
                #     dna_obj["ostype"] = detail["subType"]

                # if "healthScore" in detail:
                #     for hscore in detail["healthScore"]:
                #         if hscore["healthType"] == "OVERALL":
                #             dna_obj["health"] = hscore["score"]
                #             if hscore["reason"] != "":
                #                 dna_obj["reason"] = hscore["reason"]
                #         elif hscore["healthType"] == "ONBOARDED":
                #             dna_obj["onboard"] = hscore["score"]
                #         elif hscore["healthType"] == "CONNECTED":
                #             dna_obj["connect"] = hscore["score"]

                # if "ssid" in detail:
                #     dna_obj["ssid"] = detail["ssid"]

                # if "location" in detail:
                #     dna_obj["location"] = detail["location"]

                # if "clientConnection" in detail:
                #     dna_obj["ap"] = detail["clientConnection"]

                # if "connectionInfo" in j and j["connectionInfo"] and "band" in j["connectionInfo"]:
                #     dna_obj["band"] = j["connectionInfo"]["band"]

                # return dna_obj

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
                dna_obj["band"] = detail["frequency"]

            return dna_obj

        return None


def register_webhook(spark: Sparker) -> str:
    """Register a callback URL for our bot."""
    global CALLBACK_URL, BOT_NAME
    webhook = spark.get_webhook_for_url(CALLBACK_URL)
    if webhook:
        spark.unregister_webhook(webhook["id"])

    webhook = spark.register_webhook(
        name=f"{BOT_NAME} Webhook", callback_url=CALLBACK_URL, resource="messages", event="created", secret=CLEUCreds.CALLBACK_TOKEN
    )
    if not webhook:
        raise Exception("Failed to register the webhook callback.")

    return webhook["id"]


def handle_message(msg: str, person: Dict[str, str]) -> None:
    """Handle the Webex message using GenAI."""
    global spark, SPARK_ROOM, available_functions, dhcp_hook, ollama_client, MODEL

    final_response = None

    messages = [
        {
            "role": "system",
            "content": "You are a helpful network automation assistant with tool calling capabilities. Analyze the given user prompt and decide whether or not it can be answered by any of the available tools that you have access to."
            "When you receive a tool call response, attempt to determine the data source's name,"
            "use the output to format an answer to the original user question using markdown to highlight key elements, and return a response using the person's name and indicating which data source"
            "each output comes from.  If a data source returns nothing, skip it in the output.  Include emojis where and when appropriate."
            "If you choose to call a function ONLY respond in the JSON format:"
            '{"name": function name, "parameters": dictionary of argument names and their values}. Do not use variables.  If looking for real time'
            "information use relevant functions before falling back to brave_search.  Function calls MUST follow the specified format.  Required parameters MUST always be specified in the response."
            "Put the entire function call reply on one line.",
        },
        {"role": "user", "content": f"Hi! My name is {person['nickName']}"},
        {"role": "user", "content": msg},
    ]

    response: ChatResponse = ollama_client.chat(MODEL, messages=messages, tools=available_functions)
    output = OrderedDict()

    if response.message.tool_calls:
        for tool in response.message.tool_calls:
            if hasattr(dhcp_hook, tool.function.name):
                func = getattr(dhcp_hook, tool.function.name)
                if hasattr(func, "auth_list") and person["from_email"] not in func.auth_list:
                    spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, f"I'm sorry, {person['nickName']}.  I can't do that for you.")
                    return

                logging.debug("Calling function %s with arguments %s" % (tool.function.name, str(tool.function.arguments)))
                try:
                    output[tool.function.name] = func(**tool.function.arguments)
                except Exception as e:
                    output[tool.function.name] = str(e)
            else:
                logging.error("Failed to find a function named %s" % tool.function.name)
                output[tool.function.name] = "You're asking me to do a naughty thing."

        messages.append(response.message)
        for fn, tool_output in output.items():
            messages.append({"role": "tool", "content": str(tool_output), "name": fn})

        final_response = ollama_client.chat(MODEL, messages=messages)

    fresponse = []
    if final_response.message.content:
        for line in final_response.message.content.split("\n"):
            try:
                # The LLM may still choose to try and call an unavailable tool.
                json.loads(line)
            except Exception:
                fresponse.append(line)

    if len(fresponse) > 0:
        spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "\n".join(fresponse))
    else:
        spark.post_to_spark(
            C.WEBEX_TEAM, SPARK_ROOM, "Sorry, %s.  I couldn't find anything regarding your question 🥺" % person["nickName"]
        )


@app.route("/chat", methods=["POST"])
def receive_callback():
    global rid, spark, SPARK_ROOM, ME
    """Receive a callback from the Webex service."""
    """
    Payload will look like:

    ```json
    {
        "id": "Y2lzY29zcGFyazovL3VzL1dFQkhPT0svOTZhYmMyYWEtM2RjYy0xMWU1LWExNTItZmUzNDgxOWNkYzlh",
        "name": "My Attachment Action Webhook",
        "resource": "attachmentActions",
        "event": "created",
        "orgId": "OTZhYmMyYWEtM2RjYy0xMWU1LWExNTItZmUzNDgxOWNkYzlh",
        "appId": "Y2lzY29zcGFyazovL3VzL0FQUExJQ0FUSU9OL0MyNzljYjMwYzAyOTE4MGJiNGJkYWViYjA2MWI3OTY1Y2RhMzliNjAyOTdjODUwM2YyNjZhYmY2NmM5OTllYzFm",
        "ownedBy": "creator",
        "status": "active",
        "actorId": "Y2lzY29zcGFyazovL3VzL1BFT1BMRS83MTZlOWQxYy1jYTQ0LTRmZ",
        "data": {
            "id": "Y2lzY29zcGFyazovL3VzL09SR0FOSVpBVElPTi85NmFiYzJhYS0zZGNjLTE",
            "type": "submit",
            "messageId": "GFyazovL3VzL1BFT1BMRS80MDNlZmUwNy02Yzc3LTQyY2UtOWI4NC",
            "personId": "Y2lzY29zcGFyazovL3VzL1BFT1BMRS83MTZlOWQxYy1jYTQ0LTRmZ",
            "roomId": "L3VzL1BFT1BMRS80MDNlZmUwNy02Yzc3LTQyY2UtOWI",
            "created": "2016-05-10T19:41:00.100Z"
        }
    }
    ```
    """
    sig_header = request.headers.get("x-spark-signature")
    if not sig_header:
        # We didn't get a Webex header at all.  Someone is testing our
        # service.
        logging.info("Received POST without a Webex signature header.")
        return jsonify({"error": "Invalid message"}), 401

    payload = request.data
    logging.debug("Received payload: %s" % payload)

    sig_header = sig_header.strip().lower()
    hashed_payload = hmac.new(CLEUCreds.CALLBACK_TOKEN.encode("UTF-8"), payload, sha1)
    signature = hashed_payload.hexdigest().strip().lower()
    if signature != sig_header:
        logging.error("Received invalid signature from callback; expected %s, received %s" % (signature, sig_header))
        return jsonify({"error": "Message is not authentic"}), 403

    # Perform additional data validation on the payload.
    try:
        record = json.loads(payload)
    except Exception as e:
        logging.exception("Failed to parse JSON callback payload: %s" % str(e))
        return jsonify({"error": "Invalid JSON"}), 422

    if "data" not in record or "personEmail" not in record["data"] or "personId" not in record["data"] or "id" not in record["data"]:
        logging.error("Unexpected payload from Webex callback; did the API change? Payload: %s" % payload)
        return jsonify({"error": "Unexpected callback payload"}), 422

    sender = record["data"]["personEmail"]

    if sender == ME:
        logging.debug("Person email is our bot")
        return jsonify(""), 204

    if rid != record["data"]["roomId"]:
        logging.error("Webex Room ID is not the same as in the message (%s vs. %s)" % (rid, record["data"]["roomId"]))
        return jsonify({"error": "Room ID is not what we expect"}), 422

    mid = record["data"]["id"]

    msg = spark.get_message(mid)
    if not msg:
        logging.error("Did not get a message")
        return jsonify({"error": "Did not get a message"}), 422

    person = spark.get_person(record["data"]["personId"])
    if not person:
        person = {"from_email": sender, "nickName": "mate"}
    else:
        person["from_email"] = sender

    spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, f"Hey, {person['nickName']}!  Let **ChatNOC** work on that for you...")

    txt = msg["text"]

    try:
        handle_message(txt, person)
    except Exception as e:
        logging.exception("Failed to handle message from %s: %s" % (person["nickName"], str(e)))
        spark.post_to_spark(
            C.WEBEX_TEAM, SPARK_ROOM, "Whoops, I encountered an error:<br>\n```\n%s\n```" % traceback.format_exc(), MessageType.BAD
        )
        return jsonify({"error": "Failed to handle message"}), 500

    return jsonify(""), 204


def cleanup() -> None:
    """Cleanup on exit."""
    global webhook_id, spark

    if webhook_id:
        spark.unregister_webhook(webhook_id)


spark = Sparker(token=CLEUCreds.SPARK_TOKEN, logit=True)
pnb = pynetbox.api(C.NETBOX_SERVER, CLEUCreds.NETBOX_API_TOKEN)
dhcp_hook = DhcpHook(pnb)

ollama_client = Client(host=C.LLAMA_URL, auth=(CLEUCreds.LLAMA_USER, CLEUCreds.LLAMA_PASSWORD))

available_functions = [f[1] for f in inspect.getmembers(dhcp_hook, predicate=inspect.ismethod) if not f[0].startswith("_")]

tid = spark.get_team_id(C.WEBEX_TEAM)
if not tid:
    logging.error("Failed to get Spark Team ID")
    exit(1)

rid = spark.get_room_id(tid, SPARK_ROOM)
if not rid:
    logging.error("Failed to get Spark Room ID")
    exit(1)

try:
    webhook_id = register_webhook(spark)
except Exception as e:
    logging.exception("Failed to register Webex webhook callback: %s" % str(e))
    exit(1)
