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
import hmac
import base64

import CLEUCreds  # type: ignore
import requests
from flask import Flask, Response, jsonify, request
from gevent.pywsgi import WSGIServer

PORT = 9915
WEBHOOK_URL = CLEUCreds.INTERSIGHT_WEBHOOK_GW

logger = logging.getLogger(__name__)
app = Flask("Intersight Alert Gateway")


def validate_signature(payload: bytes, signature: str, algorithm: str) -> bool:
    """Validate HMAC signature of the incoming request."""
    sig_header = signature.strip()
    hashed_payload = hmac.new(CLEUCreds.INTERSIGHT_WEBHOOK_SECRET.encode("UTF-8"), payload, algorithm)
    signature = base64.b64encode(hashed_payload.digest()).decode("utf-8").strip()
    if signature != sig_header:
        logger.error("Received invalid signature from callback; expected %s, received %s" % (signature, sig_header))
        return False

    return True


@app.route("/event", methods=["POST"])
def intersight_to_webex() -> Response:
    """Process Intersight events and forward to Webex."""
    digest = request.headers.get("digest", "")
    try:
        algo, signature = digest.split("=")
        algo = algo.lower()
        if not validate_signature(request.data, signature, algo):
            return jsonify({"error": "Invalid signature"}), 401
    except Exception:
        logger.error("Received invalid authorization header from callback: %s" % digest)
        return jsonify({"error": "Invalid authorization header"}), 400

    try:
        event_data = json.loads(request.data.decode("utf-8"))
        event_details = event_data.get("Event", {})

        logger.info(f"Received Intersight event: {event_data}")

        severity = event_details.get("Severity", "unknown").lower()
        if severity == "critical":
            sev = "🚨🚨"
        elif severity == "warning":
            sev = "⚠️"
        else:
            sev = "✅"

        description = event_details.get("Description")
        if description:
            payload = {"markdown": f"{sev} **Intersight {severity.capitalize()} Event**: {description}"}

            response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status()
            logger.info(f"Successfully sent {severity} event to Webex")

    except requests.RequestException as e:
        logger.error(f"Failed to send event to Webex: {e}", exc_info=True)
        return jsonify({"error": "Failed to forward event"}), 502
    except Exception as e:
        logger.error(f"Unexpected error processing Intersight event: {e}", exc_info=True)
        return jsonify({"error": "Internal error"}), 500

    return jsonify({"result": "OK"})


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    logger.info(f"Starting Intersight Alert Gateway on 127.0.0.1:{PORT}")
    http_server = WSGIServer(("127.0.0.1", PORT), app)

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Intersight Alert Gateway")
        http_server.stop()
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        raise
