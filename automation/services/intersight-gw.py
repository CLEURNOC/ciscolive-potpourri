#!/usr/bin/env python
#
# Copyright (c) 2026  Joe Clarke <jclarke@cisco.com>
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

import json
import logging

import CLEUCreds  # type: ignore
import requests
from cleu.config import Config as C  # type: ignore
from flask import Flask, Response, jsonify, request
from gevent.pywsgi import WSGIServer

PORT = 9915
WEBHOOK_URL = CLEUCreds.INTERSIGHT_WEBHOOK_GW

logger = logging.getLogger(__name__)
app = Flask("Intersight Alert Gateway")


@app.route("/event", methods=["POST"])
def intersight_to_webex() -> Response:
    """Process Intersight events and forward to Webex."""
    try:
        event_data = json.loads(request.data.decode("utf-8"))

        logger.info(f"Received Intersight event: {event_data}")

        severity = event_data.get("Severity", "unknown").lower()
        if severity == "critical":
            sev = "🚨🚨"
        elif severity == "warning":
            sev = "⚠️"
        else:
            sev = "✅"

        description = event_data.get("Description")
        if description:
            payload = {"markdown": f"{sev} **Intersight {severity.capitalize()} Event**: {description}"}

            response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status()
            logger.info(f"Successfully sent {severity} event to Webex")

    except requests.RequestException as e:
        logger.error(f"Failed to send event to Webex: {e}", exc_info=True)
        return Response(jsonify({"error": "Failed to forward event"}), status=502, mimetype="application/json")
    except Exception as e:
        logger.error(f"Unexpected error processing NetApp event: {e}", exc_info=True)
        return Response(jsonify({"error": "Internal error"}), status=500, mimetype="application/json")

    return Response(jsonify({"result": "OK"}), mimetype="application/json")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    logger.info(f"Starting Intersight Alert Gateway on {C.WSGI_SERVER}:{PORT}")
    http_server = WSGIServer((C.WSGI_SERVER, PORT), app)

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Intersight Alert Gateway")
        http_server.stop()
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        raise
