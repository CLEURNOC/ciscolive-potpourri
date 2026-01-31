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

import base64
import hashlib
import hmac
import json
import logging
from urllib.parse import urlparse

import CLEUCreds  # type: ignore
import requests
from flask import Flask, Request, Response, jsonify, request
from gevent.pywsgi import WSGIServer

PORT = 9915
WEBHOOK_URL = CLEUCreds.INTERSIGHT_WEBHOOK_GW

logger = logging.getLogger(__name__)
app = Flask("Intersight Alert Gateway")


def get_sha256_digest(data: bytes) -> hashlib._hashlib.HASH:
    """
    Generates a SHA256 digest from a String.
    :param data: data string set by user
    :return: instance of digest object
    """

    digest = hashlib.sha256()
    digest.update(data)

    return digest


def prepare_str_to_sign(req_tgt: str, hdrs: dict) -> str:
    """
    Concatenates Intersight headers in preparation to be signed
    :param req_tgt : http method plus endpoint
    :param hdrs: dict with header keys
    :return: concatenated header authorization string
    """
    sign_str = ""
    sign_str = sign_str + "(request-target): " + req_tgt + "\n"

    length = len(hdrs.items())

    i = 0
    for key, value in hdrs.items():
        sign_str = sign_str + key.lower() + ": " + value
        if i < length - 1:
            sign_str = sign_str + "\n"
        i += 1

    return sign_str


def get_auth_header(hdrs: dict, signed_msg: bytes, key_id: str) -> str:
    """
    Assmeble an Intersight formatted authorization header
    :param hdrs : object with header keys
    :param signed_msg: base64 encoded sha256 hashed body
    :return: concatenated authorization header
    """

    auth_str = "Signature"

    auth_str = auth_str + " " + 'keyId="' + key_id + '", ' + 'algorithm="' + "hmac-sha256" + '",'

    auth_str = auth_str + ' headers="(request-target)'

    for key, dummy in hdrs.items():
        auth_str = auth_str + " " + key.lower()
    auth_str = auth_str + '"'

    auth_str = auth_str + "," + ' signature="' + signed_msg.decode("ascii") + '"'

    return auth_str


def verify_auth_header(event: Request) -> bool:
    authorization = event.headers.get("Authorization")
    if not authorization:
        logger.error("Missing Authorization header")
        return False

    # Generate the expected authorization header
    host_uri = CLEUCreds.INTERSIGHT_WEBHOOK_URI
    target_host = urlparse(host_uri).netloc
    target_path = urlparse(host_uri).path
    request_target = "post" + " " + target_path

    body_digest = get_sha256_digest(event.data)
    b64_body_digest = base64.b64encode(body_digest.digest())
    auth_header = {
        "Host": target_host,
        "Date": event.headers.get("Date"),
        "Digest": "SHA-256=" + b64_body_digest.decode("ascii"),
        "Content-Type": "application/json",
        "Content-Length": str(len(event.data.decode("ascii"))),
    }
    if auth_header["Digest"] != event.headers.get("Digest", ""):
        logger.error(f"Digest mismatch: expected {auth_header['Digest']}, got {event.headers.get('Digest', '')}")
        return False

    string_to_sign = prepare_str_to_sign(request_target, auth_header)
    webhook_secret = CLEUCreds.INTERSIGHT_WEBHOOK_SECRET
    sign = hmac.new(webhook_secret.encode(), msg=string_to_sign.encode(), digestmod=hashlib.sha256).digest()
    b64_signature = base64.b64encode(sign)
    key_id = CLEUCreds.INTERSIGHT_WEBHOOK_KEY_ID
    expected_auth = get_auth_header(auth_header, b64_signature, key_id)

    if expected_auth != authorization:
        logger.error("Authorization header mismatch")
        return False

    return True


@app.route("/event", methods=["POST"])
def intersight_to_webex() -> Response:
    """Process Intersight events and forward to Webex."""
    if not verify_auth_header(request):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        event_data = json.loads(request.data.decode("utf-8"))
        event_details = event_data.get("Event", {})

        logger.info(f"Received Intersight event: {event_data}")
        if not event_details:
            event_details = {}

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
