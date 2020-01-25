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

from flask import Flask
from flask import Response, jsonify
import requests
import json
import CLEUCreds
from gevent.pywsgi import WSGIServer
from webargs.flaskparser import use_kwargs
from webargs import fields
from cleu.config import Config as C


PORT = 8084

app = Flask("DHCP Abstraction API")

CNR_HEADERS = {"Accept": "application/json", "Content-Type": "application/json", "Authorization": CLEUCreds.JCLARKE_BASIC}


@app.route("/api/v1/subnetLookup")
@use_kwargs({"subnet": fields.Str()}, locations=("query",))
def get_leases_for_subnet(**kwargs):
    if not "subnet" in kwargs:
        return Response(jsonify({"msg": "subnet parameter is required"}), mimetype="application/json", status=400)

    url = C.DHCP_BASE + "Scope"
    response = None

    try:
        response = requests.request("GET", url, params={"subnet": kwargs["subnet"]}, headers=CNR_HEADERS, verify=False)
        response.raise_for_status()
    except Exception as e:
        status_code = 500
        if response:
            status_code = response.status_code
        return Response(
            jsonify({"msg": "Error getting scope for subnet {}: {}".format(kwargs["subnet"], getattr(e, "message", repr(e)))}),
            mimetype="application/json",
            status=status_code,
        )

    j = response.json()
    if not "name" in j:
        return Response(
            jsonify({"msg": "Error getting scope for subnet {}".format(kwargs["subnet"])}), mimetype="application/json", status=500
        )

    url = C.DHCP_BASE + "Lease"
    subnet_re = "\\.".join(kwargs["subnet"].split(".")[:2]) + "\\..*"
    result = []

    while True:
        try:
            response = requests.request("GET", url, params={"state": "leased", "address": subnet_re}, headers=CNR_HEADERS, verify=False)
            response.raise_for_status()
        except Exception as e:
            status_code = 500
            if response:
                status_code = response.status_code
            return Response(
                jsonify({"msg": "Error getting leases for subnet {}: {}".format(kwargs["subnet"], getattr(e, "message", repr(e)))}),
                mimetype="application/json",
                status=staus_code,
            )

        j = response.json()
        result += j

        if response.headers.get("Link"):
            links = requests.util.parse_header_links(response.headers.get("Link"))
            for link in links:
                if "rel" in link and link["rel"] == "next":
                    url = link["url"]
                    break
        else:
            break

    return Response(jsonify(result), mimetype="application/json", status=200)


if __name__ == "__main__":
    #    app.run(host='10.100.253.13', port=8081, threaded=True)
    http_server = WSGIServer((C.WSGI_SERVER, PORT), app)
    http_server.serve_forever()
