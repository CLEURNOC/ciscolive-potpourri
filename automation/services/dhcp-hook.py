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
from builtins import str
import sys
import json
from sparker import Sparker, MessageType  # type: ignore
import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import time
import traceback
import socket
import logging
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

AT_MACADDR = 9

CNR_HEADERS = {"Accept": "application/json"}
BASIC_AUTH = (CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD)
REST_TIMEOUT = 10

DEFAULT_INT_TYPE = "GigabitEthernet"

ALLOWED_TO_DELETE = ["jclarke@cisco.com", "josterfe@cisco.com", "anjesani@cisco.com"]


def is_ascii(s):
    return all(ord(c) < 128 for c in s)


def normalize_mac(mac):
    # Normalize all MAC addresses to colon-delimited format.
    mac_addr = "".join(l + ":" * (n % 2 == 1) for n, l in enumerate(list(re.sub(r"[:.-]", "", mac)))).strip(":")

    return mac_addr.lower()


# TODO: We don't use CMX anymore.  This needs to work with DNS Spaces?
def get_from_cmx(**kwargs):
    # marker = "green"
    # if "user" in kwargs and kwargs["user"] == "gru":
    #     marker = "gru"

    # if "ip" in kwargs:
    #     url = "{}?ip={}&marker={}&size=1440".format(C.CMX_GW, kwargs["ip"], marker)
    # elif "mac" in kwargs:
    #     url = "{}?mac={}&marker={}&size=1440".format(C.CMX_GW, kwargs["mac"], marker)
    # else:
    #     return None

    # headers = {"Accept": "image/jpeg, application/json"}

    # try:
    #     response = requests.request("GET", url, headers=headers, stream=True)
    #     response.raise_for_status()
    # except Exception:
    #     logging.error("Encountered error getting data from cmx: {}".format(traceback.format_exc()))
    #     return None

    # if response.headers.get("content-type") == "application/json":
    #     return None

    # return response.raw.data
    return None


def get_from_dnac(**kwargs):
    for dnac in C.DNACS:
        curl = "https://{}/dna/intent/api/v1/client-detail".format(dnac)

        # Get timestamp with milliseconds
        epoch = int(time.time() * 1000)

        turl = "https://{}/dna/system/api/v1/auth/token".format(dnac)
        theaders = {"content-type": "application/json"}
        try:
            response = requests.request("POST", turl, headers=theaders, auth=BASIC_AUTH, verify=False, timeout=REST_TIMEOUT)
            response.raise_for_status()
        except Exception as e:
            logging.warning("Unable to get an auth token from DNAC: {}".format(getattr(e, "message", repr(e))))
            continue

        j = response.json()
        if "Token" not in j:
            logging.warning(f"Failed to get a Token element from DNAC {dnac}: {response.text}")
            continue

        cheaders = {"accept": "application/json", "x-auth-token": j["Token"]}
        params = {"macAddress": kwargs["mac"], "timestamp": epoch}
        try:
            response = requests.request("GET", curl, params=params, headers=cheaders, verify=False)
            response.raise_for_status()
        except Exception as e:
            logging.warning("Failed to find MAC address {} in DNAC: {}".format(kwargs["mac"], getattr(e, "message", repr(e))))
            continue

        j = response.json()
        if "detail" not in j:
            logging.warning("Got an unknown response from DNAC: '{}'".format(response.text))
            continue

        if "errorCode" in j["detail"]:
            continue

        return j["detail"]

    return None


# TODO: We don't use PI anymore.  Remove this in favor of DNAC.
def get_from_pi(**kwargs):

    # what = None

    # if "user" in kwargs:
    #     url = 'https://{}/webacs/api/v2/data/ClientDetails.json?.full=true&userName="{}"&status=ASSOCIATED'.format(C.PI, kwargs["user"])
    #     what = "user"
    # elif "mac" in kwargs:
    #     mac_addr = normalize_mac(kwargs["mac"])
    #     url = 'https://{}/webacs/api/v2/data/ClientDetails.json?.full=true&macAddress="{}"&status=ASSOCIATED'.format(C.PI, mac_addr)
    #     what = "mac"
    # elif "ip" in kwargs:
    #     url = 'https://{}/webacs/api/v2/data/ClientDetails.json?.full=true&ipAddress="{}"&status=ASSOCIATED'.format(C.PI, kwargs["ip"])
    #     what = "ip"
    # else:
    #     return None

    # headers = {"Connection": "close"}

    # done = False
    # first = 0
    # code = 401
    # i = 0
    # while code != 200 and i < 10:
    #     response = None
    #     try:
    #         response = requests.request("GET", url, auth=(CLEUCreds.PI_USER, CLEUCreds.PI_PASS), headers=headers, verify=False)
    #     except Exception as e:
    #         logging.error("Failed to get a response from PI for {}: {}".format(kwargs[what], e))
    #         return None
    #     code = response.status_code
    #     if code != 200:
    #         i += 1
    #         time.sleep(3)
    # if code == 200:
    #     j = json.loads(response.text)
    #     if j["queryResponse"]["@count"] == 0:
    #         return None
    #     return j["queryResponse"]["entity"]
    # else:
    #     logging.error("Failed to get a response from PI for {}: {}".format(kwargs[what], response.text))

    return None


def parse_relay_info(outd):
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
        if not is_ascii(res["switch"]) or res["switch"] == "":
            res["switch"] = "N/A"

    return res


def check_for_reservation(ip):
    global CNR_HEADERS, BASIC_AUTH

    res = {}

    url = "{}/Reservation/{}".format(C.DHCP_BASE, ip)
    try:
        response = requests.request("GET", url, auth=BASIC_AUTH, headers=CNR_HEADERS, verify=False, timeout=REST_TIMEOUT)
        response.raise_for_status()
    except Exception as e:
        logging.warning("Did not get a good response from CNR for reservation {}: {}".format(ip, e))
        return None
    rsvp = response.json()
    res["mac"] = ":".join(rsvp["lookupKey"].split(":")[-6:])
    res["scope"] = rsvp["scope"]

    return res


def check_for_reservation_by_mac(mac):
    global CNR_HEADERS, BASIC_AUTH

    res = {}

    mac_addr = normalize_mac(mac)

    url = "{}/Reservation".format(C.DHCP_BASE)
    try:
        response = requests.request(
            "GET", url, auth=BASIC_AUTH, headers=CNR_HEADERS, params={"lookupKey": mac_addr}, verify=False, timeout=REST_TIMEOUT
        )
        response.raise_for_status()
    except Exception as e:
        logging.warning("Did not get a good response from CNR for reservation {}: {}".format(ip, e))
        return None
    j = response.json()
    if len(j) == 0:
        return None
    rsvp = j[0]
    res["mac"] = ":".join(rsvp["lookupKey"].split(":")[-6:])
    res["scope"] = rsvp["scope"]

    return res


def create_reservation(ip, mac):
    global CNR_HEADERS, BASIC_AUTH, AT_MACADDR

    mac_addr = normalize_mac(mac)

    url = "{}/Reservation".format(C.DHCP_BASE)
    payload = {"ipaddr": ip, "lookupKey": "01:06:" + mac_addr, "lookupKeyType": AT_MACADDR}
    response = requests.request("POST", url, auth=BASIC_AUTH, headers=CNR_HEADERS, json=payload, verify=False, timeout=REST_TIMEOUT)
    response.raise_for_status()


def delete_reservation(ip):
    global CNR_HEADERS, BASIC_AUTH

    url = "{}/Reservation/{}".format(C.DHCP_BASE, ip)
    response = requests.request("DELETE", url, auth=BASIC_AUTH, headers=CNR_HEADERS, verify=False, timeout=REST_TIMEOUT)
    response.raise_for_status()


def check_for_lease(ip):
    global CNR_HEADERS, BASIC_AUTH

    res = {}
    url = "{}/Lease/{}".format(C.DHCP_BASE, ip)
    try:
        response = requests.request("GET", url, auth=BASIC_AUTH, headers=CNR_HEADERS, verify=False, timeout=REST_TIMEOUT)
        response.raise_for_status()
    except Exception as e:
        logging.warning("Did not get a good response from CNR for IP {}: {}".format(ip, e))
        return None

    lease = response.json()

    if not "clientMacAddr" in lease:
        return None
    relay = parse_relay_info(lease)
    if "clientHostName" in lease:
        res["name"] = lease["clientHostName"]
    elif "client-dns-name" in lease:
        res["name"] = lease["clientDnsName"]
    else:
        res["name"] = "UNKNOWN"

    res["mac"] = lease["clientMacAddr"][lease["clientMacAddr"].rfind(",") + 1 :]
    res["scope"] = lease["scopeName"]
    res["state"] = lease["state"]
    res["relay-info"] = relay
    rsvp = check_for_reservation(ip)
    if rsvp and rsvp["mac"] == res["mac"]:
        res["is-reserved"] = True

    return res


def check_for_mac(mac):
    global CNR_HEADERS, BASIC_AUTH

    url = "{}/Lease".format(C.DHCP_BASE)

    try:
        response = requests.request(
            "GET", url, auth=BASIC_AUTH, headers=CNR_HEADERS, verify=False, params={"clientMacAddr": mac}, timeout=REST_TIMEOUT
        )
        response.raise_for_status()
    except Exception as e:
        logging.warning("Did not get a good response from CPNR for MAC {}: {}".format(mac, e))
        return None

    j = response.json()
    if len(j) == 0:
        return None
    leases = []
    for lease in j:
        res = {}
        if "address" not in lease:
            continue
        relay = parse_relay_info(lease)
        res["ip"] = lease["address"]
        if "clientHostName" in lease:
            res["name"] = lease["clientHostName"]
        elif "clientDnsName" in lease:
            res["name"] = lease["clientDnsName"]
        else:
            res["name"] = "UNKNOWN"
        res["scope"] = lease["scopeName"]
        res["state"] = lease["state"]
        res["relay-info"] = relay
        rsvp = check_for_reservation(res["ip"])
        if rsvp and rsvp["mac"] == mac:
            res["is-reserved"] = True

        leases.append(res)

    return leases


def print_dnac(spark, what, details, msg):
    ohealth = None
    healths = {}
    host_info = ""
    ssid = ""
    loc = ""
    hinfo = ""
    sdetails = ""
    if "healthScore" in details:
        for score in details["healthScore"]:
            if "healthType" in score:
                if score["healthType"] == "OVERALL":
                    ohealth = {}
                    ohealth["score"] = score["score"]
                    ohealth["reason"] = score["reason"]
                else:
                    healths[score["healthType"]] = {"score": score["score"], "reason": score["reason"]}

    if "hostOs" in details and details["hostOs"]:
        host_info = "running **{}**".format(details["hostOs"])
    if "ssid" in details and details["ssid"]:
        ssid = "associated to SSID **{}**".format(details["ssid"])
    if "location" in details and details["location"]:
        loc = "located in **{}**".format(details["location"])
    if "port" in details and details["port"] and "clientConnection" in details and details["clientConnection"]:
        sdetails = "connected to device **{}** on port **{}**".format(details["clientConnection"], details["port"])

    if ohealth is not None:
        hinfo = "with health score **{}/10**".format(ohealth["score"])
        if ohealth["reason"]:
            hinfo += " (reason: _{}_)".format(ohealth["reason"])
        if len(healths) > 0:
            hinfo += " ["
            for h, hobj in list(healths.items()):
                hinfo += "{} health: {} ".format(h, hobj["score"])
                if hobj["reason"] != "":
                    hinfo += "(reason: {}) ".format(hobj["reason"])
            hinfo += "]"

    htype = ""
    if "hostType" in details:
        htype = details["hostType"]

    spark.post_to_spark(
        C.WEBEX_TEAM,
        SPARK_ROOM,
        "{} {} is a {} client {} {} {} {} {}".format(msg, what, htype, sdetails, ssid, loc, host_info, hinfo),
    )


def print_pi(spark, what, ents, msg):
    for ent in ents:
        res = ent["clientDetailsDTO"]
        apdet = ""
        condet = ""
        vendet = ""
        if "apName" in res:
            apdet = "**{}** via ".format(res["apName"])
        if "connectionType" in res:
            condet = "is a **{}** client".format(res["connectionType"])
        if "vendor" in res:
            vendet = "of vendor type **{}**".format(res["vendor"])
        spark.post_to_spark(
            C.WEBEX_TEAM,
            SPARK_ROOM,
            "{} {} {} {}, connected to {}**{}** on interface **{}** with MAC address **{}** and IP address **{}** in **VLAN {}** located in **{}**.".format(
                msg,
                what,
                condet,
                vendet,
                apdet,
                res["deviceName"],
                res["clientInterface"],
                res["macAddress"],
                res["ipAddress"]["address"],
                res["vlan"],
                res["location"],
            ),
        )


spark = Sparker(token=CLEUCreds.SPARK_TOKEN, logit=True)

SPARK_ROOM = "DHCP Queries"

if __name__ == "__main__":
    print("Content-type: application/json\r\n\r\n")

    output = sys.stdin.read()

    j = json.loads(output)

    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s : %(message)s", filename="/var/log/dhcp-hook.log", level=logging.DEBUG
    )
    logging.debug(json.dumps(j, indent=4))

    message_from = j["data"]["personEmail"]

    if message_from == "livenocbot@sparkbot.io":
        logging.debug("Person email is our bot")
        print('{"result":"success"}')
        sys.exit(0)

    tid = spark.get_team_id(C.WEBEX_TEAM)
    if tid is None:
        logging.error("Failed to get Spark Team ID")
        print('{"result":"fail"}')
        sys.exit(0)

    rid = spark.get_room_id(tid, SPARK_ROOM)
    if rid is None:
        logging.error("Failed to get Spark Room ID")
        print('{"result":"fail"}')
        sys.exit(0)

    if rid != j["data"]["roomId"]:
        logging.error("Spark Room ID is not the same as in the message ({} vs. {})".format(rid, j["data"]["roomId"]))
        print('{"result":"fail"}')
        sys.exit(0)

    mid = j["data"]["id"]

    msg = spark.get_message(mid)
    if msg is None:
        logging.error("Did not get a message")
        print('{"result":"error"}')
        sys.exit(0)

    person = spark.get_person(j["data"]["personId"])
    if person is not None:
        spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "Hey, {}.  Working on that for you...".format(person["nickName"]))
    else:
        spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "Working on that for you...")

    txt = msg["text"]
    found_hit = False

    if re.search(r"\bhelp\b", txt, re.I):
        spark.post_to_spark(
            C.WEBEX_TEAM,
            SPARK_ROOM,
            'To lookup a reservation, type `@Live NOC Bot reservation IP`.  To lookup a lease by MAC, ask about the MAC.  To lookup a lease by IP ask about the IP.  To look up a user, ask about "user USERNAME".<br>Some question might be, `@Live NOC Bot who has lease 1.2.3.4` or `@Live NOC Bot what lease does 00:11:22:33:44:55 have` or `@Live NOC Bot tell me about user jsmith`.',
        )
        found_hit = True

    try:
        m = re.search(r"user(name)?\s+\b(?P<uname>[A-Za-z][\w\-\.\d]+)([\s\?\.]|$)", txt, re.I)
        if not found_hit and not m:
            m = re.search(r"(who|where)\s+is\s+\b(?P<uname>[A-Za-z][\w\-\.\d]+)([\s\?\.]|$)", txt, re.I)

        if not found_hit and m:
            found_hit = True
            uname = m.group("uname")
            usecret = ""
            if re.search(r"gru", m.group("uname"), re.I):
                uname = "rkamerma"
                usecret = "gru"
            res = get_from_pi(user=uname)
            if res is None:
                res = get_from_pi(user=uname + "@{}".format(C.AD_DOMAIN))

            if res is not None:
                print_pi(spark, m.group("uname"), res, "")
                for ent in res:
                    dnacres = get_from_dnac(mac=ent["clientDetailsDTO"]["macAddress"].lower())
                    if dnacres is not None:
                        print_dnac(spark, m.group("uname"), dnacres, "")
                    cmxres = get_from_cmx(mac=ent["clientDetailsDTO"]["macAddress"].lower(), user=usecret)
                    if cmxres is not None:
                        spark.post_to_spark_with_attach(
                            C.WEBEX_TEAM,
                            SPARK_ROOM,
                            "{}'s location from CMX".format(m.group("uname")),
                            cmxres,
                            "{}_location.jpg".format(m.group("uname")),
                            "image/jpeg",
                        )
            else:
                spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "Sorry, I can't find {}.".format(m.group("uname")))

        m = re.search(r"(remove|delete)\s+(the\s+)?reservation.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", txt, re.I)
        if not m:
            m = re.search(r"(unreserve)(.*?)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", txt, re.I)

        if not found_hit and m:
            found_hit = True
            if message_from not in ALLOWED_TO_DELETE:
                spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "I'm sorry, {}.  I can't do that for you.".format(message_from))
            else:
                res = check_for_reservation(m.group(3))
                if res is None:
                    spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "I didn't find a reservation for {}.".format(m.group(3)))
                else:
                    try:
                        delete_reservation(m.group(3))
                        spark.post_to_spark(
                            C.WEBEX_TEAM, SPARK_ROOM, "Reservation for {} deleted successfully.".format(m.group(3)), MessageType.GOOD
                        )
                    except Exception as e:
                        spark.post_to_spark(
                            C.WEBEX_TEAM, SPARK_ROOM, "Failed to delete reservation for {}: {}".format(m.group(3)), MessageType.BAD
                        )

        m = re.search(r"(make|create|add)\s+(a\s+)?reservation.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", txt, re.I)
        if not found_hit and m:
            found_hit = True
            res = check_for_reservation(m.group(3))
            if res is not None:
                spark.post_to_spark(
                    C.WEBEX_TEAM, SPARK_ROOM, "_{}_ is already reserved by a client with MAC **{}**".format(m.group(3), res["mac"])
                )
            else:
                lres = check_for_lease(m.group(3))
                if lres is None:
                    spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "Did not find an existing lease for {}".format(m.group(3)))
                else:
                    try:
                        rres = check_for_reservation_by_mac(lres["mac"])
                        if rres is not None:
                            spark.post_to_spark(
                                C.WEBEX_TEAM,
                                SPARK_ROOM,
                                "_{}_ already has a reservation for {} in scope {}.".format(lres["mac"], rres["ip"], lres["scope"]),
                            )
                        else:
                            create_reservation(m.group(3), lres["mac"])
                            spark.post_to_spark(
                                C.WEBEX_TEAM, SPARK_ROOM, "Successfully added reservation for {}.".format(m.group(3)), MessageType.GOOD
                            )
                    except Exception as e:
                        spark.post_to_spark(
                            C.WEBEX_TEAM, SPARK_ROOM, "Failed to add reservation for {}: {}".format(m.group(3), e), MessageType.BAD
                        )

        m = re.search(r"reservation.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", txt, re.I)
        if not found_hit and m:
            found_hit = True
            res = check_for_reservation(m.group(1))
            if res is not None:
                spark.post_to_spark(
                    C.WEBEX_TEAM,
                    SPARK_ROOM,
                    "_{}_ is reserved by a client with MAC **{}** in scope **{}**.".format(m.group(1), res["mac"], res["scope"]),
                )
            else:
                spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "I did not find a reservation for {}.".format(m.group(1)))

        m = re.findall(r"\b([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", txt)
        if not found_hit and len(m) > 0:
            found_hit = True
            for hit in m:
                res = check_for_lease(hit)
                pires = get_from_pi(ip=hit)
                cmxres = None
                dnacres = None
                if res is not None:
                    cmxres = get_from_cmx(mac=re.sub(r"(\d+,)+", "", res["mac"]))
                    dnacres = get_from_dnac(mac=re.sub(r"(\d+,)+", "", res["mac"]))
                elif pires is not None:
                    cmxres = get_from_cmx(mac=pires[0]["clientDetailsDTO"]["macAddress"])
                    dnacres = get_from_dnac(mac=pires[0]["clientDetailsDTO"]["macAddress"])
                if res is not None:
                    reserved = ""
                    if "is-reserved" in res and res["is-reserved"]:
                        reserved = " (Client has reserved this IP)"
                    if re.search(r"available", res["state"]):
                        port_info = res["relay-info"]["port"]
                        if port_info != "N/A":
                            port_info = '<a href="{}switchname={}&portname={}">**{}**</a>'.format(
                                C.TOOL_BASE,
                                "-".join(res["relay-info"]["switch"].split("-")[:-1]),
                                res["relay-info"]["port"],
                                res["relay-info"]["port"],
                            )

                        spark.post_to_spark(
                            C.WEBEX_TEAM,
                            SPARK_ROOM,
                            "_{}_ is no longer leased, but _WAS_ leased by a client with name **{}** and MAC **{}** in scope **{}** (state: **{}**) and was connected to switch **{}** on port {} in VLAN **{}**{}.".format(
                                hit,
                                res["name"],
                                res["mac"],
                                res["scope"],
                                res["state"],
                                res["relay-info"]["switch"],
                                port_info,
                                res["relay-info"]["vlan"],
                                reserved,
                            ),
                        )
                    else:
                        port_info = res["relay-info"]["port"]
                        if port_info != "N/A":
                            port_info = '<a href="{}switchname={}&portname={}">**{}**</a>'.format(
                                C.TOOL_BASE,
                                "-".join(res["relay-info"]["switch"].split("-")[:-1]),
                                res["relay-info"]["port"],
                                res["relay-info"]["port"],
                            )

                        spark.post_to_spark(
                            C.WEBEX_TEAM,
                            SPARK_ROOM,
                            "_{}_ is leased by a client with name **{}** and MAC **{}** in scope **{}** (state: **{}**) and is connected to switch **{}** on port {} in VLAN **{}**{}.".format(
                                hit,
                                res["name"],
                                res["mac"],
                                res["scope"],
                                res["state"],
                                res["relay-info"]["switch"],
                                port_info,
                                res["relay-info"]["vlan"],
                                reserved,
                            ),
                        )
                    if pires is not None:
                        print_pi(spark, hit, pires, "I also found this from Prime Infra:")
                    if dnacres is not None:
                        print_dnac(spark, hit, dnacres, "I also found this from Cisco DNA Center:")
                    if cmxres is not None:
                        spark.post_to_spark_with_attach(
                            C.WEBEX_TEAM, SPARK_ROOM, "Location from CMX", cmxres, "{}_location.jpg".format(hit), "image/jpeg"
                        )
                else:
                    spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "I did not find a lease for {}.".format(hit))
                    if pires is not None:
                        print_pi(spark, hit, pires, "But I did get this from Prime Infra:")
                    if dnacres is not None:
                        print_dnac(spark, hit, dnacres, "But I did get this from Cisco DNA Center:")
                    if cmxres is not None:
                        spark.post_to_spark_with_attach(
                            C.WEBEX_TEAM, SPARK_ROOM, "Location from CMX", cmxres, "{}_location.jpg".format(hit), "image/jpeg"
                        )

        m = re.findall(
            "\\b(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)\\b",
            txt,
        )
        if not found_hit and len(m) > 0:
            found_hit = True
            for hit in m:
                pires = get_from_pi(ip=hit)
                if pires is not None:
                    print_pi(spark, hit, pires, "")
                    dnacres = get_from_dnac(mac=pires[0]["clientDetailsDTO"]["macAddress"])
                    cmxres = get_from_cmx(mac=pires[0]["clientDetailsDTO"]["macAddress"])
                    if dnacres is not None:
                        print_dnac(spark, hit, dnacres, "")
                    if cmxres is not None:
                        spark.post_to_spark_with_attach(
                            C.WEBEX_TEAM, SPARK_ROOM, "Location from CMX", cmxres, "{}_location.jpg".format(hit), "image/jpeg"
                        )

                else:
                    spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "I did not find anything about {} in Prime Infra.".format(hit))

        m = re.findall(
            r"\b(([a-fA-F0-9]{1,2}:[a-fA-F0-9]{1,2}:[a-fA-F0-9]{1,2}:[a-fA-F0-9]{1,2}:[a-fA-F0-9]{1,2}:[a-fA-F0-9]{1,2})|([a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4})|([a-fA-F0-9]{1,2}-[a-fA-F0-9]{1,2}-[a-fA-F0-9]{1,2}-[a-fA-F0-9]{1,2}-[a-fA-F0-9]{1,2}-[a-fA-F0-9]{1,2}))\b",
            txt,
        )
        if not found_hit and len(m) > 0:
            found_hit = True
            for hit in m:
                hmac = normalize_mac(hit[0])
                leases = check_for_mac(hmac)
                pires = get_from_pi(mac=hmac)
                cmxres = get_from_cmx(mac=re.sub(r"(\d+,)+", "", hmac))
                dnacres = get_from_dnac(mac=re.sub(r"(\d+,)+", "", hmac))
                if leases is not None:
                    seen_ip = {}
                    for res in leases:
                        if res["ip"] in seen_ip:
                            continue

                        reserved = ""
                        if "is-reserved" in res and res["is-reserved"]:
                            reserved = " (Client has reserved this IP)"

                        seen_ip[res["ip"]] = True
                        if re.search(r"available", res["state"]):
                            spark.post_to_spark(
                                C.WEBEX_TEAM,
                                SPARK_ROOM,
                                "Client with MAC _{}_ no longer has a lease, but _USED TO HAVE_ lease **{}** (hostname: **{}**) in scope **{}** (state: **{}**) and was connected to switch **{}** on port **{}** in VLAN **{}**{}.".format(
                                    hit[0],
                                    res["ip"],
                                    res["name"],
                                    res["scope"],
                                    res["state"],
                                    res["relay-info"]["switch"],
                                    res["relay-info"]["port"],
                                    res["relay-info"]["vlan"],
                                    reserved,
                                ),
                            )
                        else:
                            spark.post_to_spark(
                                C.WEBEX_TEAM,
                                SPARK_ROOM,
                                "Client with MAC _{}_ has lease **{}** (hostname: **{}**) in scope **{}** (state: **{}**) and is connected to switch **{}** on port **{}** in VLAN **{}**{}.".format(
                                    hit[0],
                                    res["ip"],
                                    res["name"],
                                    res["scope"],
                                    res["state"],
                                    res["relay-info"]["switch"],
                                    res["relay-info"]["port"],
                                    res["relay-info"]["vlan"],
                                    reserved,
                                ),
                            )
                            if pires is not None:
                                # spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, '```\n{}\n```'.format(json.dumps(pires, indent=4)))
                                print_pi(spark, hit[0], pires, "I also found this from Prime Infra:")
                            if dnacres is not None:
                                print_dnac(spark, hit[0], dnacres, "I also found this fron Cisco DNA Center:")
                            if cmxres is not None:
                                spark.post_to_spark_with_attach(
                                    C.WEBEX_TEAM, SPARK_ROOM, "Location from CMX", cmxres, "{}_location.jpg".format(hit[0]), "image/jpeg"
                                )
                else:
                    spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "I did not find a lease for {}.".format(hit[0]))
                    if pires is not None:
                        print_pi(spark, hit[0], pires, "But I did get this from Prime Infra:")
                    if dnacres is not None:
                        print_dnac(spark, hit[0], dnacres, "But I did get this from Cisco DNA Center:")
                    if cmxres is not None:
                        spark.post_to_spark_with_attach(
                            C.WEBEX_TEAM, SPARK_ROOM, "Location from CMX", cmxres, "{}_location.jpg".format(hit[0]), "image/jpeg"
                        )

        m = re.search(r"answer", txt, re.I)
        if not found_hit and m:
            found_hit = True
            spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "The answer is 42.")

        m = re.findall(r"([\w\d\-\.]+)", txt)
        if not found_hit and len(m) > 0:
            found_hit = False
            for hit in m:
                ip = None
                try:
                    ip = socket.gethostbyname(hit)
                except:
                    pass
                if ip:
                    res = check_for_lease(ip)
                    pires = get_from_pi(ip=ip)
                    if res is not None:
                        reserved = ""
                        if "is-reserved" in res and res["is-reserved"]:
                            reserved = " (Client has reserved this IP)"
                        if re.search(r"available", res["state"]):
                            found_hit = True
                            spark.post_to_spark(
                                C.WEBEX_TEAM,
                                SPARK_ROOM,
                                "Client with hostname _{}_ no longer has a lease, but _USED TO HAVE_ lease **{}** (hostname: **{}**) in scope **{}** (state: **{}**) and was connected to switch **{}** on port **{}** in VLAN **{}**{}.".format(
                                    hit,
                                    ip,
                                    res["name"],
                                    res["scope"],
                                    res["state"],
                                    res["relay-info"]["switch"],
                                    res["relay-info"]["port"],
                                    res["relay-info"]["vlan"],
                                    reserved,
                                ),
                            )
                        else:
                            found_hit = True
                            spark.post_to_spark(
                                C.WEBEX_TEAM,
                                SPARK_ROOM,
                                "Client with hostname _{}_ has lease **{}** (hostname: **{}**) in scope **{}** (state: **{}**) and is connected to switch **{}** on port **{}** in VLAN **{}**.".format(
                                    hit,
                                    ip,
                                    res["name"],
                                    res["scope"],
                                    res["state"],
                                    res["relay-info"]["switch"],
                                    res["relay-info"]["port"],
                                    res["relay-info"]["vlan"],
                                ),
                            )
                        if pires is not None:
                            found_hit = True
                            # spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, '```\n{}\n```'.format(json.dumps(pires, indent=4)))
                            print_pi(spark, hit, pires, "I also found this from Prime Infra:")
                            dnacres = get_from_dnac(mac=pires[0]["clientDetailsDTO"]["macAddress"])
                            cmxres = get_from_cmx(mac=pires[0]["clientDetailsDTO"]["macAddress"])
                            if dnacres is not None:
                                print_dnac(spark, hit, dnacres, "I also found this from Cisco DNA Center:")
                            if cmxres is not None:
                                spark.post_to_spark_with_attach(
                                    C.WEBEX_TEAM, SPARK_ROOM, "Location from CMX", cmxres, "{}_location.jpg".format(hit), "image/jpeg"
                                )
                    else:
                        found_hit = True
                        spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "I did not find a lease for {}.".format(hit))
                        if pires is not None:
                            print_pi(spark, hit, pires, "But I did get this from Prime Infra:")
                            dnacres = get_from_dnac(mac=pires[0]["clientDetailsDTO"]["macAddress"])
                            cmxres = get_from_cmx(mac=pires[0]["clientDetailsDTO"]["macAddress"])
                            if dnacres is not None:
                                print_dnac(spark, hit, dnacres, "But I did get this from Cisco DNA Center:")
                            if cmxres is not None:
                                spark.post_to_spark_with_attach(
                                    C.WEBEX_TEAM, SPARK_ROOM, "Location from CMX", cmxres, "{}_location.jpg".format(hit), "image/jpeg"
                                )

        if not found_hit:
            spark.post_to_spark(
                C.WEBEX_TEAM,
                SPARK_ROOM,
                'Sorry, I didn\'t get that.  Please give me a MAC or IP (or "reservation IP" or "user USER") or just ask for "help".',
            )
    except Exception as e:
        logging.error("Error in obtaining data: {}".format(traceback.format_exc()))
        spark.post_to_spark(
            C.WEBEX_TEAM, SPARK_ROOM, "Whoops, I encountered an error:<br>\n```\n{}\n```".format(traceback.format_exc()), MessageType.BAD
        )

    print('{"result":"success"}')
