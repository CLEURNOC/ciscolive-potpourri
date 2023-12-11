#!/usr/bin/env python3
#
# Copyright (c) 2017-2024  Joe Clarke <jclarke@cisco.com>
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

from flask import Flask  # type: ignore
from flask import jsonify  # type: ignore
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import CLEUCreds
import re
from gevent.pywsgi import WSGIServer  # type: ignore
from webargs.flaskparser import use_kwargs  # type: ignore
from webargs import fields  # type: ignore
from cleu.config import Config as C


PORT = 8084
PAGE_LIMIT = 13

app = Flask("DHCP Abstraction API")

CNR_HEADERS = {"Accept": "application/json", "Content-Type": "application/json", "Authorization": CLEUCreds.JCLARKE_BASIC}


def get_items_pages(*args, **kwargs):
    global PAGE_LIMIT

    more_pages = True
    result = []
    response = None

    cnt = 0
    while more_pages and cnt < PAGE_LIMIT:
        try:
            response = requests.request(*args, **kwargs)
            response.raise_for_status()
            result += response.json()
            if "Link" in response.headers:
                links = requests.utils.parse_header_links(response.headers["Link"])
                found_next = False
                for link in links:
                    if link["rel"] == "next":
                        args = (args[0], link["url"])
                        kwargs.pop("params", None)
                        found_next = True
                        break

                if found_next:
                    cnt += 1
                    continue

                more_pages = False
            else:
                more_pages = False
        except Exception:
            return (result, response)

    return (result, response)


@app.route("/api/v1/subnetLookup")
@use_kwargs({"subnet": fields.Str()}, locations=("query",))
def get_leases_for_subnet(**kwargs):
    if "subnet" not in kwargs:
        return jsonify({"msg": "subnet parameter is required"}), 400

    url = C.DHCP_BASE + "Scope"
    response = None
    subnet = re.sub(r"/\d+$", "", kwargs["subnet"])
    octets = subnet.split(".")
    for i, octet in enumerate(octets):
        if i < 2:
            continue
        if int(octet) == 0:
            octets[i] = ".*"

    subnet_re = "\\.".join(octets)

    try:
        (scopes, response) = get_items_pages("GET", url, params={"subnet": subnet_re}, headers=CNR_HEADERS, verify=False)
        response.raise_for_status()
    except Exception as e:
        status_code = 500
        if response:
            status_code = response.status_code
        return (
            jsonify({"msg": "Error getting scope for subnet {}: {}".format(kwargs["subnet"], getattr(e, "message", repr(e)))}),
            status_code,
        )

    if len(scopes) == 0:
        return jsonify({"msg": "Error getting scope for subnet {}".format(kwargs["subnet"])}), 400

    names = []

    for scope in scopes:
        names.append(scope["name"])

    url = C.DHCP_BASE + "Lease"
    result = []

    try:
        (result, response) = get_items_pages(
            "GET", url, params={"state": "leased", "address": subnet_re}, headers=CNR_HEADERS, verify=False
        )
        response.raise_for_status()
    except Exception as e:
        status_code = 500
        if response:
            status_code = response.status_code
        return (
            jsonify({"msg": "Error getting leases for subnet {}: {}".format(kwargs["subnet"], getattr(e, "message", repr(e)))}),
            status_code,
        )

    return jsonify(result), 200


if __name__ == "__main__":
    #    app.run(host='10.100.253.13', port=8081, threaded=True)
    ssl_context = {"certfile": "cleu_cert.pem", "keyfile": "cleu_privkey.pem"}
    http_server = WSGIServer((C.WSGI_SERVER, PORT), app, **ssl_context)
    http_server.serve_forever()
