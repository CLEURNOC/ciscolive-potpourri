#!/usr/bin/env python

from flask import Flask, jsonify, request
import json
import os
import logging
from sparker import Sparker, MessageType  # type: ignore
from typing import Dict
import re
from hashlib import sha1
import hmac
from subprocess import run
from shlex import split, quote
import traceback
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

SPARK_ROOM = "KBYG Queries"
CALLBACK_URL = "https://cleur-kbyg-hook.ciscolive.network/chat"
BOT_NAME = "KBYG Bot"
ME = "livenocbot@sparkbot.io"

COLLECTION_NAME = "kbyg-rag"
CHROMA_PATH = "/home/jclarke/kbyg-chroma"

KBYG_FILE = "home/jclarke/kbyg.pdf"

EMBEDDING_MODEL = "nomic-embed-text"
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


def handle_message(msg: str, person: Dict[str, str]) -> None:
    cmd = split("ssh -t dc1-ollama-node-6.ciscolive.network ./kbyg.sh")
    cmd.append(quote(msg))
    res = run(cmd, capture_output=True)
    if res.returncode != 0:
        spark.post_to_spark(
            C.WEBEX_TEAM, SPARK_ROOM, "Sorry, %s.  I couldn't find anything regarding your question 🥺" % person["nickName"]
        )
    else:
        spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, res.stdout.decode("utf-8").strip())


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
        person = {"from_email": sender, "nickName": "mate", "username": "mate"}
    else:
        person["from_email"] = sender
        person["username"] = re.sub(r"@.+$", "", person["from_email"])

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


spark = Sparker(token=CLEUCreds.SPARK_TOKEN, logit=True)

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
