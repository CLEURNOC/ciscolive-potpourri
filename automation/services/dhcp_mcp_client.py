#!/usr/bin/env python
#
# Copyright (c) 2025  Joe Clarke <jclarke@cisco.com>
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

import hmac
import json
import logging
import os
import re
import traceback
from contextlib import asynccontextmanager
from hashlib import sha1
from typing import Any, Dict, List

import CLEUCreds  # type: ignore
import fastmcp
import uvicorn
from cleu.config import Config as C  # type: ignore
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastmcp.client.transports import StdioTransport
from ollama import ChatResponse, Client
from sparker import MessageType, Sparker  # type: ignore

SPARK_ROOM = os.getenv("DHCP_BOT_SPARK_ROOM", "DHCP Queries")
CALLBACK_URL = os.getenv("DHCP_BOT_CALLBACK_URL", "https://cleur-dhcp-hook.ciscolive.network/chat")
BOT_NAME = os.getenv("DHCP_BOT_NAME", "DHCP Agent")
ME = os.getenv("DHCP_BOT_ME", "livenocbot@sparkbot.io")

NEW_MSG_PLACEHOLDER = "Let **ChatNOC** work on that for you..."
THREAD_MSG_PLACEHOLDER = "Thinkin' about it..."

MODEL = os.getenv("DHCP_BOT_MODEL", "gpt-oss")

webhook_id = None
mcp_client = None
spark = Sparker(token=CLEUCreds.SPARK_TOKEN, logit=True)

# Set our initial logging level.
log_level = os.getenv("LOG_LEVEL")
if not log_level:
    log_level = "INFO"

logging.basicConfig(
    format="[%(asctime)s.%(msecs)03d] [%(levelname)s] [%(filename)s] [%(funcName)s():%(lineno)s] [PID:%(process)d TID:%(thread)d] %(message)s"
)
logging.getLogger().setLevel(log_level)
logger = logging.getLogger("noc-mcp-client")


def register_webhook(spark: Sparker) -> str:
    """Register a callback URL for our bot."""
    webhook = spark.get_webhook_for_url(CALLBACK_URL)
    if webhook:
        spark.unregister_webhook(webhook["id"])

    webhook = spark.register_webhook(
        name=f"{BOT_NAME} Webhook", callback_url=CALLBACK_URL, resource="messages", event="created", secret=CLEUCreds.CALLBACK_TOKEN
    )
    if not webhook:
        raise Exception("Failed to register the webhook callback.")

    return webhook["id"]


@asynccontextmanager
async def cleanup(_: FastAPI):
    """Cleanup on exit."""

    # This will be run at startup.
    yield
    # This will be run at shutdown.

    if mcp_client:
        try:
            await mcp_client.close()
        except Exception:
            pass

    if webhook_id:
        spark.unregister_webhook(webhook_id)


if not CALLBACK_URL.endswith("/chat"):
    logger.error("CALLBACK_URL must end with /chat")
    exit(1)

team_id = spark.get_team_id(C.WEBEX_TEAM)
if not team_id:
    logger.error("Failed to get Webex Team ID")
    exit(1)

room_id = spark.get_room_id(team_id, SPARK_ROOM)
if not room_id:
    logger.error("Failed to get Webex Room ID")
    exit(1)

try:
    webhook_id = register_webhook(spark)
except Exception as e:
    logger.exception("Failed to register Webex webhook callback: %s" % str(e))
    exit(1)

app = FastAPI(title=BOT_NAME, lifespan=cleanup)


# This code borrowed from https://github.com/andreamoro/ollama-fastmcp-wrapper/blob/master/ollama_wrapper.py
async def fix_parameters(tools: List[Dict[str, Any]], tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Coerce parameters to their expected types based on
    the schema defined by the MCP Server."""

    tool = next((t for t in tools if t["function"]["name"] == tool_name), None)
    if not tool:
        raise Exception(f"Tool {tool_name} not found")

    spec = tool.get("function").get("parameters").get("properties")
    coerced_params = {}
    for key, value in parameters.items():
        expected_type = spec.get(key, {}).get("type")
        if expected_type == "integer":
            try:
                coerced_params[key] = int(value)
            except Exception:
                pass
        elif expected_type == "float":
            try:
                coerced_params[key] = float(value)
            except Exception:
                pass
        elif expected_type == "string":
            coerced_params[key] = str(value)
        elif expected_type == "boolean":
            if isinstance(value, str):
                coerced_params[key] = value.lower() in ("true", "1", "yes")
            else:
                coerced_params[key] = bool(value)
        else:
            coerced_params[key] = value
    # Return coerced parameters
    return coerced_params


tls_verify = os.getenv("DHCP_BOT_TLS_VERIFY", "true").lower() == "true"

ollama_client = Client(host=C.LLAMA_URL, auth=(CLEUCreds.LLAMA_USER, CLEUCreds.LLAMA_PASSWORD), verify=tls_verify)
mcp_server_env = {
    "DEBUG": log_level.lower() == "debug",
    "DHCP_BOT_TLS_VERIFY": tls_verify,
    "NETBOX_SERVER": C.NETBOX_SERVER,
    "NETBOX_API_TOKEN": CLEUCreds.NETBOX_API_TOKEN,
    "CPNR_USERNAME": CLEUCreds.CPNR_USERNAME,
    "CPNR_PASSWORD": CLEUCreds.CPNR_PASSWORD,
    "ISE_API_USER": CLEUCreds.ISE_API_USER,
    "ISE_API_PASS": CLEUCreds.ISE_API_PASS,
    "COLLAB_WEBEX_TOKEN": CLEUCreds.COLLAB_WEBEX_TOKEN,
    "ISE_SERVER": C.ISE_SERVER,
    "DHCP_SERVER": C.DHCP_SERVER,
    "DNACS": ",".join(C.DNACS),
    "DHCP_BASE": C.DHCP_BASE,
    "DNS_DOMAIN": C.DNS_DOMAIN,
}
transport = StdioTransport(
    command="uv",
    args=[
        "run",
        "--project",
        "/home/jclarke/dhcp_agent",
        "--with",
        "fastapi",
        "--with",
        "fastmcp",
        "--with",
        "httpx",
        "--with",
        "pynetbox",
        "fastmcp",
        "run",
        "/home/jclarke/dhcp_agent/dhcp_mcp_server.py:server_mcp",
    ],
    env=mcp_server_env,
)

mcp_client = fastmcp.Client(transport)


def strip_markdown(text: str) -> str:
    """
    Remove common markdown formatting from a string.
    """
    # Remove code blocks and inline code
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    # Remove bold, italics, strikethrough
    text = re.sub(r"\*\*([^\*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^\*]+)\*", r"\1", text)
    text = re.sub(r"__([^_]+)__", r"\1", text)
    text = re.sub(r"_([^_]+)_", r"\1", text)
    text = re.sub(r"~~([^~]+)~~", r"\1", text)
    # Remove headers
    text = re.sub(r"^#+\s*", "", text, flags=re.MULTILINE)
    # Remove links and images
    text = re.sub(r"!\[.*?\]\(.*?\)", "", text)
    text = re.sub(r"\[(.*?)\]\(.*?\)", r"\1", text)
    # Remove blockquotes
    text = re.sub(r"^>\s*", "", text, flags=re.MULTILINE)
    # Remove horizontal rules
    text = re.sub(r"^(-{3,}|\*{3,}|_{3,})$", "", text, flags=re.MULTILINE)
    # Remove unordered and ordered list markers
    text = re.sub(r"^(\s*[-*+]\s+)", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*\d+\.\s+", "", text, flags=re.MULTILINE)
    # Remove remaining markdown characters
    text = text.replace("\\", "")
    return text.strip()


async def handle_message(msgs: List[Dict[str, str]], person: Dict[str, str], parent: str = None) -> None:
    """Handle the Webex message using GenAI."""

    NETWORK_INFO_AGENT_SYSTEM_PROMPT = """
You are a helpful network automation assistant with tool-calling capabilities. Your primary role is to analyze each user prompt and determine if it can be answered using only the available, explicitly listed tools.

Key Instructions:

1. Tool Usage Restrictions:
   - Only use tools from the currently provided, explicit tool list.
   - Never invent, suggest, or reference tools or functions that are not listed as available.
   - If a user requests an action or tool that is not valid or available, politely inform them and suggest only supported actions.

2. Function Calls:
   - Use real-time data sources or functions first, before falling back to brave_search.
   - Every function call must strictly follow the specified format, including all required parameters.
   - Place each function call reply on a single line—no line breaks within replies.
   - Always call all relevant functions if multiple arguments or data sources are applicable.

3. Response Formatting:
   - When you receive tool responses, identify the data source by name and clearly attribute each part of your answer to its source.
   - Use markdown to highlight key information and make the output easy to read.
   - Address the user by their name in your response.
   - Use emojis to enhance clarity or engagement, where appropriate.
   - If any data source returns no results, skip it in your final output.

4. Content and Compliance:
   - Never use or reference variables in your output.
   - Do not permit actions or operations not directly supported by the available tools.
   - Provide all data returned by each tool without omission or modification.
   - Do not fabricate, guess, or fill in missing information.

Output Format:
Always return your response in clear, markdown-formatted text.  Do not use markdown tables.

Examples:

User: "Show me the current switch status."
Agent:
Hi [UserName]!
Here’s the information you requested:
- **Switch Status** (from `switch_status_tool`):
  - Port 1: Up 🟢
  - Port 2: Down 🔴

User: "Can you use `magic_router_tool` to reboot my router?"
Agent:
Hi [UserName]!
Sorry, the tool `magic_router_tool` is not available. Please ask about supported actions or choose from the listed tools. 😊

Notes:
- If a user asks for real-time data, always attempt real-time tools first before using brave_search.
- If a user requests an unsupported or non-existent tool, explicitly state that it is unavailable.
- Always attribute information to its specific data source.
- Never invent or imagine new tools, actions, or responses.

Steps:

1. Analyze the user prompt for intent and requested action.
2. Check if the request matches any available tool (from the current tool list).
3. If yes, perform the function call(s) in the correct format with all required parameters.
4. Upon receiving responses, format the answer, clearly attributing data to its source, using markdown and emojis as appropriate.
5. If a tool or request is invalid, reply with a polite, clear explanation and suggest supported actions.
6. Skip empty or null responses from data sources.
7. Address the user by name in every response.

This prompt is constant and must not be altered or removed.
"""

    messages = [
        {
            "role": "system",
            "content": NETWORK_INFO_AGENT_SYSTEM_PROMPT,
        },
        {"role": "user", "content": f"Hi! My name is {person['nickName']} and my username is {person['username']}."},
    ]

    messages += msgs

    available_functions = []
    tool_meta = {}
    async with mcp_client:
        mcp_tools = await mcp_client.list_tools()
        for tool in mcp_tools:
            ollama_tool = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema if hasattr(tool, "inputSchema") else {},
                },
            }
            available_functions.append(ollama_tool)
            tool_meta[tool.name] = tool.meta if hasattr(tool, "meta") else {}

    while True:
        response: ChatResponse = ollama_client.chat(MODEL, messages=messages, tools=available_functions, options={"temperature": 0})
        if "tool_calls" in response.get("message", {}):
            messages.append(response.message)
            for tool in response.message.tool_calls:
                func = tool.function.name
                args = tool.function.arguments
                tid = tool.get("id", func)
                if next((t for t in available_functions if t["function"]["name"] == func), None):
                    if func in tool_meta and "auth_list" in tool_meta[func]:
                        if person["from_email"] not in tool_meta[func]["auth_list"]:
                            spark.post_to_spark(
                                C.WEBEX_TEAM, SPARK_ROOM, f"I'm sorry, {person['nickName']}.  I can't do that for you.", parent=parent
                            )
                            continue

                    logger.debug("Calling function %s with arguments %s" % (func, str(args)))
                    try:
                        args = await fix_parameters(available_functions, func, args)
                        async with mcp_client:
                            result = await mcp_client.call_tool(func, args)

                            # FastMCP returns results in a more direct format
                            if hasattr(result, "content"):
                                messages.append({"role": "tool", "content": str(result.content), "tool_call_id": tid})
                            elif isinstance(result, dict) and "content" in result:
                                messages.append({"role": "tool", "content": str(result["content"]), "tool_call_id": tid})
                            else:
                                messages.append({"role": "tool", "content": str(result), "tool_call_id": tid})
                    except Exception as e:
                        logger.exception("Function %s encountered an error: %s" % (func, str(e)))
                        messages.append({"role": "tool", "content": "An exception occurred: %s" % str(e), "tool_call_id": tid})
                else:
                    logger.error("Failed to find a function named %s" % func)
                    messages.append(
                        {
                            "role": "tool",
                            "content": "You're asking me to do a naughty thing.  I don't have a tool called %s." % func,
                            "tool_call_id": tid,
                        }
                    )
        else:
            messages.append({"role": "assistant", "content": response.message.content})
            break

    fresponse = []
    if response and response.message.content:
        for line in response.message.content.split("\n"):
            try:
                # The LLM may still choose to try and call an unavailable tool.
                json.loads(line)
            except Exception:
                fresponse.append(line)

    if len(fresponse) > 0:
        spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, "\n".join(fresponse), parent=parent)
    else:
        spark.post_to_spark(
            C.WEBEX_TEAM, SPARK_ROOM, "Sorry, %s.  I couldn't find anything regarding your question 🥺" % person["nickName"], parent=parent
        )


@app.post("/chat")
async def receive_callback(request: Request) -> Response:
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
        logger.info("Received POST without a Webex signature header.")
        return JSONResponse(content={"error": "Invalid message"}, status_code=401)

    payload = await request.body()
    logger.debug("Received payload: %s" % payload)

    sig_header = sig_header.strip().lower()
    hashed_payload = hmac.new(CLEUCreds.CALLBACK_TOKEN.encode("UTF-8"), payload, sha1)
    signature = hashed_payload.hexdigest().strip().lower()
    if signature != sig_header:
        logger.error("Received invalid signature from callback; expected %s, received %s" % (signature, sig_header))
        return JSONResponse(content={"error": "Message is not authentic"}, status_code=403)

    # Perform additional data validation on the payload.
    try:
        record = json.loads(payload)
    except Exception as e:
        logger.exception("Failed to parse JSON callback payload: %s" % str(e))
        return JSONResponse(content={"error": "Invalid JSON"}, status_code=422)

    if "data" not in record or "personEmail" not in record["data"] or "personId" not in record["data"] or "id" not in record["data"]:
        logger.error("Unexpected payload from Webex callback; did the API change? Payload: %s" % payload)
        return JSONResponse(content={"error": "Unexpected callback payload"}, status_code=422)

    sender = record["data"]["personEmail"]

    if sender == ME:
        logger.debug("Person email is our bot")
        return Response(status_code=204)

    if room_id != record["data"]["roomId"]:
        logger.error("Webex Room ID is not the same as in the message (%s vs. %s)" % (room_id, record["data"]["roomId"]))
        return JSONResponse(content={"error": "Room ID is not what we expect"}, status_code=422)

    mid = record["data"]["id"]

    msg = spark.get_message(mid)
    if not msg:
        logger.error("Did not get a message")
        return JSONResponse(content={"error": "Did not get a message"}, status_code=422)

    messages = [{"role": "user", "content": msg["text"]}]
    current_parent = None
    this_mid = mid

    # Build conversation history by traversing parent messages
    while "parentId" in msg and msg["parentId"] != mid:
        parent_id = msg["parentId"]
        parent_msg = spark.get_message(parent_id)
        if not parent_msg:
            break
        thread_msgs = spark.get_messages(room_id, parentId=parent_id)
        if thread_msgs and len(thread_msgs) > 0:
            for tmsg in thread_msgs:
                if tmsg["id"] == this_mid:
                    continue
                # Skip messages without text or with placeholder text
                if (
                    "text" not in tmsg
                    or strip_markdown(THREAD_MSG_PLACEHOLDER) in tmsg["text"]
                    or strip_markdown(NEW_MSG_PLACEHOLDER) in tmsg["text"]
                ):
                    continue
                role = "assistant" if tmsg["personEmail"] == ME else "user"
                messages.insert(0, {"role": role, "content": tmsg["text"]})
        role = "assistant" if parent_msg["personEmail"] == ME else "user"
        messages.insert(0, {"role": role, "content": parent_msg["text"]})
        current_parent = parent_id if not current_parent else current_parent
        mid = parent_id
        msg = parent_msg

    person = spark.get_person(record["data"]["personId"])
    if not person:
        person = {"from_email": sender, "nickName": "mate", "username": "mate"}
    else:
        person["from_email"] = sender
        person["username"] = re.sub(r"@.+$", "", person["from_email"])

    if current_parent:
        spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, THREAD_MSG_PLACEHOLDER, parent=current_parent)
    else:
        spark.post_to_spark(C.WEBEX_TEAM, SPARK_ROOM, f"Hey, {person['nickName']}!  {NEW_MSG_PLACEHOLDER}", parent=this_mid)

    try:
        await handle_message(messages, person, current_parent or this_mid)
    except Exception as e:
        logger.exception("Failed to handle message from %s: %s" % (person["nickName"], str(e)))
        # Don't send this to the parent as it's a bug in the transaction.
        spark.post_to_spark(
            C.WEBEX_TEAM, SPARK_ROOM, "Whoops, I encountered an error:<br>\n```\n%s\n```" % traceback.format_exc(), MessageType.BAD
        )
        return JSONResponse(content={"error": "Failed to handle message"}, status_code=500)

    return Response(status_code=204)


uvicorn.run(app, port=9999)
