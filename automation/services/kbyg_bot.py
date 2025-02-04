#!/usr/bin/env python

from flask import Flask, jsonify, request
import json
import os
import logging
from sparker import Sparker, MessageType  # type: ignore
from typing import Tuple, Dict
import re
from hashlib import sha1
import hmac
import base64
from langchain_community.document_loaders import UnstructuredPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores.chroma import Chroma
from langchain_community.chat_models import ChatOllama
from langchain.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain.retrievers.multi_query import MultiQueryRetriever

import traceback
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

SPARK_ROOM = "KBYG Queries"
CALLBACK_URL = "https://cleur-dhcp-hook.ciscolive.network/kbyg"
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


def get_vector_db() -> Chroma:
    llama_auth = base64.b64encode(f"{CLEUCreds.LLAMA_USER}:{CLEUCreds.LLAMA_PASSWORD}")
    embedding = OllamaEmbeddings(
        model=EMBEDDING_MODEL, show_progress=True, base_url=C.LLAMA_URL, headers={"Authorization": f"Basic {llama_auth}"}
    )

    db = Chroma(collection_name=COLLECTION_NAME, persist_directory=CHROMA_PATH, embedding_function=embedding)

    return db


def load_and_split_data(file: str) -> list:
    """Load the PDF and split it."""
    loader = UnstructuredPDFLoader(file_path=file)
    data = loader.load()
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=7500, chunk_overlap=100)
    chunks = text_splitter.split_documents(data)

    return chunks


def embed(file: str) -> None:
    """Load and split the file, and then add the chunks to the vector DB."""
    chunks = load_and_split_data(file)
    db = get_vector_db()
    db.add_documents(chunks)
    db.persist()


def get_prompt() -> Tuple[PromptTemplate, PromptTemplate]:
    """Get the prompts for the AI."""
    QUERY_PROMPT = PromptTemplate(
        input_variables=["question"],
        template="""You are an AI language model assistant versed in the CiscoLive Know Before You Go. Your task is to generate five
        different versions of the given user question to retrieve relevant documents from
        a vector database. By generating multiple perspectives on the user question, your
        goal is to help the user overcome some of the limitations of the distance-based
        similarity search. Provide these alternative questions separated by newlines.
        Original question: {question}""",
    )

    template = """Answer the question based ONLY on the following context:
    {context}
    Question: {question}
    """

    prompt = ChatPromptTemplate.from_template(template)

    return (QUERY_PROMPT, prompt)


def handle_message(msg: str, person: Dict[str, str]) -> None:
    llm = ChatOllama(base_url=C.LLAMA_URL, auth=(CLEUCreds.LLAMA_USER, CLEUCreds.LLAMA_PASSWORD), model=MODEL)
    db = get_vector_db()

    QUERY_PROMPT, prompt = get_prompt()

    retriever = MultiQueryRetriever.from_llm(db.as_retriever(), llm, prompt=QUERY_PROMPT)

    chain = {"context": retriever, "question": RunnablePassthrough()} | prompt | llm | StrOutputParser()

    response = chain.invoke(input)

    spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, response)


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

embed(KBYG_FILE)

try:
    webhook_id = register_webhook(spark)
except Exception as e:
    logging.exception("Failed to register Webex webhook callback: %s" % str(e))
    exit(1)
