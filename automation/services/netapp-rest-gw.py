#!/usr/bin/env python3
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

import logging
from typing import Any

import CLEUCreds  # type: ignore
import requests
import xmltodict
from cleu.config import Config as C  # type: ignore
from flask import Flask, Response, request
from gevent.pywsgi import WSGIServer

PORT = 9999
WEBHOOK_URL = CLEUCreds.NETAPP_WEBHOOK_GW

logger = logging.getLogger(__name__)
app = Flask("NetApp Alert Gateway")


@app.route("/event", methods=["POST"])
def ontap_to_webex() -> Response:
    """Process NetApp ONTAP events and forward to Webex."""
    try:
        event_data = request.data.decode("utf-8")
        event_dict: dict[str, Any] = xmltodict.parse(event_data)

        logger.info(f"Received NetApp event: {event_dict.get('netapp', {}).get('ems-message-info', {}).get('event', 'unknown')}")

        sevstr = event_dict["netapp"]["ems-message-info"]["severity"]
        sev = "🚨🚨" if sevstr == "alert" else "✴️"

        payload = {"markdown": f"{sev} **NetApp {sevstr.capitalize()} Event**: {event_dict['netapp']['ems-message-info']['event']}"}

        response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
        response.raise_for_status()
        logger.info(f"Successfully sent {sevstr} event to Webex")

    except KeyError as e:
        logger.error(f"Missing expected field in NetApp event: {e}", exc_info=True)
        return Response("<result>ERROR: Invalid event format</result>", status=400, mimetype="text/xml")
    except requests.RequestException as e:
        logger.error(f"Failed to send event to Webex: {e}", exc_info=True)
        return Response("<result>ERROR: Failed to forward event</result>", status=502, mimetype="text/xml")
    except Exception as e:
        logger.error(f"Unexpected error processing NetApp event: {e}", exc_info=True)
        return Response("<result>ERROR: Internal error</result>", status=500, mimetype="text/xml")

    return Response("<result>OK</result>", mimetype="text/xml")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    logger.info(f"Starting NetApp Alert Gateway on {C.WSGI_SERVER}:{PORT}")
    http_server = WSGIServer((C.WSGI_SERVER, PORT), app)

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down NetApp Alert Gateway")
        http_server.stop()
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        raise
