#!/usr/bin/env python3
#
# Copyright (c) 2017-2020  Joe Clarke <jclarke@cisco.com>
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

from builtins import range
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import json
import sys
import time
import os
from subprocess import call
from sparker import Sparker
import pprint
import re
from multiprocessing import Pool
import socket
import CLEUCreds
from cleu.config import Config as C

CACHE_FILE = "/home/jclarke/cached_devs.dat"
PING_DEVS_FILE = "/home/jclarke/ping-devs.json"

MESSAGES = {
    "BAD": {"msg": "Pinger detected that device %s (IP: %s)%s is no longer reachable", "type": MessageType.BAD},
    "GOOD": {"msg": "Pinger has detected that device %s (IP: %s)%s is now reachable again", "type": MessageType.GOOD},
}

ROOM_NAME = "Device Alarms"

excluded_devices = [r"^VHS-"]

additional_devices = []


def check_prev(dev_dic, prev_devs, pstate="REACHABLE"):
    send_msg = False
    for pd in prev_devs:
        if pd["name"] == dev_dic["name"]:
            if pd["reachability"] != pstate:
                send_msg = True
            break
    return send_msg


def know_device(dev_dic, prev_devs):
    for pd in prev_devs:
        if pd["name"] == dev_dic["name"]:
            return True

    return False


def ping_device(dev):
    global ROOM_NAME, MESSAGES, prev_devs, spark, excluded_devices

    dev_dic = {}

    if not re.search(r"^0", dev["Hostname"]):
        return None

    dev_dic["name"] = dev["Hostname"]
    dev_dic["ip"] = dev["IPAddress"]
    if dev_dic["ip"] == "0.0.0.0":
        return None
    for exc in excluded_devices:
        if re.search(exc, dev_dic["name"]) or re.search(exc, dev_dic["ip"]):
            return None
    # print('Pinging {}'.format(dev_dic['name']))
    msg_tag = "BAD"
    send_msg = True
    if not dev["Reachable"]:
        send_msg = know_device(dev_dic, prev_devs)
    for i in range(2):
        res = call(["/usr/local/sbin/fping", "-q", "-r0", dev_dic["ip"]])
        time.sleep(0.5)
    if res != 0:
        dev_dic["reachability"] = "UNREACHABLE"
        send_msg = check_prev(dev_dic, prev_devs, "UNREACHABLE")
    else:
        dev_dic["reachability"] = "REACHABLE"
        msg_tag = "GOOD"
        send_msg = check_prev(dev_dic, prev_devs)

    if send_msg:
        loc = ""
        if "LocationDetail" in dev:
            loc = " (Location: {})".format(dev["LocationDetail"])
        message = MESSAGES[msg_tag]["msg"] % (dev_dic["name"], dev_dic["ip"], loc)
        spark.post_to_spark(C.WEBEX_TEAM, ROOM_NAME, message, MESSAGES[msg_tag]["type"])

    return dev_dic


def get_devs(p):
    global additional_devices

    url = "http://{}/get/switches/json".format(C.TOOL)

    devices = []
    #    response = requests.request('GET', url)
    code = 200
    #   code = response.status_code
    if code == 200:
        # j = json.loads(response.text)
        j = []

        for dev in additional_devices:
            ip = dev
            try:
                ip = socket.gethostbyname(dev)
            except:
                pass
            j.append({"Hostname": dev, "IPAddress": ip, "Reachable": True})

        results = [pool.apply_async(ping_device, [d]) for d in j]
        for res in results:
            retval = res.get()
            if retval is not None:
                devices.append(retval)

    return devices


if __name__ == "__main__":
    prev_devs = []
    if os.path.exists(CACHE_FILE):
        fd = open(CACHE_FILE, "r")
        prev_devs = json.load(fd)
        fd.close()

    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

    try:
        fd = open(PING_DEVS_FILE, "r")
        additional_devices = json.load(fd)
        fd.close()
    except:
        pass

    pool = Pool(20)
    devs = get_devs(pool)
    fd = open(CACHE_FILE, "w")
    json.dump(devs, fd, ensure_ascii=False, indent=4)
    fd.close()
