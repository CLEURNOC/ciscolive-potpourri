#!/usr/bin/env python
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

from flask import Flask
from flask import Response, request
import requests
import xmltodict
from gevent.pywsgi import WSGIServer
from cleu.config import Config as C  # type: ignore

PORT = 9999
WEBHOOK_URL = "https://webexapis.com/v1/webhooks/incoming/Y2lzY29zcGFyazovL3VzL1dFQkhPT0svYTJmNzhkN2MtNDBmYi00YTcyLThjMGMtMmQzNzUyMWYzZDky"

app = Flask("NetApp Alert Gateway")


@app.route("/event", methods=["POST"])
def ontap_to_webex():
    event_data = request.data.decode("utf-8")
    event_dict = xmltodict.parse(event_data)
    sevstr = event_dict["netapp"]["ems-message-info"]["severity"]
    if sevstr == "alert":
        sev = "🚨🚨"
    else:
        sev = "✴️ "

    payload = {"markdown": f"{sev} **NetApp {sevstr.capitalize} Event**: {event_dict['netapp']['ems-message-info']['event']}"}
    requests.post(WEBHOOK_URL, json=payload)

    return Response("<result>OK</result>", mimetype="text/xml")


if __name__ == "__main__":
    #    app.run(host='10.100.253.13', port=8081, threaded=True)
    http_server = WSGIServer((C.WSGI_SERVER, PORT), app)
    http_server.serve_forever()
