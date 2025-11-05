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
from dataclasses import dataclass
from hashlib import sha1
from typing import Any, Dict, List, Optional

import CLEUCreds  # type: ignore
import fastmcp
import uvicorn
from cleu.config import Config as C  # type: ignore
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastmcp.client.transports import StdioTransport
from ollama import ChatResponse, Client
from sparker import MessageType, Sparker  # type: ignore

NEW_MSG_PLACEHOLDER = "Let **ChatNOC** work on that for you..."
THREAD_MSG_PLACEHOLDER = "Thinkin' about it..."

BOT_NAME = os.getenv("DHCP_BOT_NAME", "DHCP Agent")


@dataclass
class BotConfig(object):
    """Centralized configuration management"""

    spark_room: str
    callback_url: str
    bot_name: str
    bot_email: str
    model: str
    log_level: str
    tls_verify: bool

    @classmethod
    def from_env(cls) -> "BotConfig":
        """Create BotConfig from environment variables"""
        config = cls(
            spark_room=os.getenv("DHCP_BOT_SPARK_ROOM", "DHCP Queries"),
            callback_url=os.getenv("DHCP_BOT_CALLBACK_URL", "https://cleur-dhcp-hook.ciscolive.network/chat"),
            bot_name=BOT_NAME,
            bot_email=os.getenv("DHCP_BOT_ME", "livenocbot@sparkbot.io"),
            model=os.getenv("DHCP_BOT_MODEL", "gpt-oss"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            tls_verify=os.getenv("DHCP_BOT_TLS_VERIFY", "true").lower() == "true",
        )

        # Validate required configuration
        if not config.callback_url.endswith("/chat"):
            raise ValueError("CALLBACK_URL must end with /chat")

        return config


class BotState(object):
    """Manages bot state and resources"""

    def __init__(self):
        self.webhook_id: Optional[str] = None
        self.mcp_client: Optional[fastmcp.Client] = None
        self.spark: Optional[Sparker] = None
        self.room_id: Optional[str] = None
        self.ollama_client: Optional[Client] = None
        self.config: Optional[BotConfig] = None
        self.logger: Optional[logging.Logger] = None
        self.available_functions: List[Dict[str, Any]] = []
        self.tool_meta: Dict[str, Any] = {}

    async def initialize(self) -> None:
        """Initialize all bot components"""
        self.config = BotConfig.from_env()

        # Initialize logging
        logging.basicConfig(
            format="[%(asctime)s.%(msecs)03d] [%(levelname)s] [%(filename)s] [%(funcName)s():%(lineno)s] [PID:%(process)d TID:%(thread)d] %(message)s"
        )
        logging.getLogger().setLevel(self.config.log_level)
        self.logger = logging.getLogger("noc-mcp-client")
        self.logger.info("Initializing bot state...")

        # Initialize Spark client
        self.spark = Sparker(token=CLEUCreds.SPARK_TOKEN, logit=True)

        # Get team and room IDs
        team_id = await self.spark.get_team_id_async(C.WEBEX_TEAM)
        if not team_id:
            raise RuntimeError("Failed to get Webex Team ID")

        self.room_id = await self.spark.get_room_id_async(team_id, self.config.spark_room)
        if not self.room_id:
            raise RuntimeError("Failed to get Webex Room ID")

        # Register webhook
        try:
            self.webhook_id = await self._register_webhook()
        except Exception as e:
            self.logger.exception("Failed to register Webex webhook callback: %s", str(e))
            raise

        # Initialize Ollama client
        tls_verify = os.getenv("DHCP_BOT_TLS_VERIFY", "true").lower() == "true"
        self.ollama_client = Client(host=C.LLAMA_URL, auth=(CLEUCreds.LLAMA_USER, CLEUCreds.LLAMA_PASSWORD), verify=tls_verify, timeout=240)

        # Initialize MCP client
        self.mcp_client = self._create_mcp_client(tls_verify)

        # Initialize tool list
        await self._initialize_tool_list()

        self.logger.info("Bot state initialized successfully")

    async def _register_webhook(self) -> str:
        """Register a callback URL for our bot."""
        webhook = await self.spark.get_webhook_for_url_async(self.config.callback_url)
        if webhook:
            await self.spark.unregister_webhook_async(webhook["id"])

        webhook = await self.spark.register_webhook_async(
            name=f"{self.config.bot_name} Webhook",
            callback_url=self.config.callback_url,
            resource="messages",
            event="created",
            secret=CLEUCreds.CALLBACK_TOKEN,
        )
        if not webhook:
            raise Exception("Failed to register the webhook callback.")

        return webhook["id"]

    def _create_mcp_client(self, tls_verify: bool) -> fastmcp.Client:
        """Create MCP client with proper environment setup"""
        mcp_server_env = {
            "DEBUG": str(self.config.log_level.lower() == "debug"),
            "DHCP_BOT_TLS_VERIFY": str(tls_verify),
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
            command="python",
            args=["dhcp_mcp_server.py"],
            cwd=os.getcwd(),
            env=mcp_server_env,
        )
        return fastmcp.Client(transport)

    async def _initialize_tool_list(self) -> None:
        """Initialize the tool list in the MCP client"""
        if not self.mcp_client:
            raise RuntimeError("MCP client is not initialized")

        async with self.mcp_client:
            mcp_tools = await self.mcp_client.list_tools()
            for tool in mcp_tools:
                ollama_tool = {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.inputSchema if hasattr(tool, "inputSchema") else {},
                    },
                }
                self.available_functions.append(ollama_tool)
                self.tool_meta[tool.name] = tool.meta if hasattr(tool, "meta") else {}

    async def cleanup(self) -> None:
        """Cleanup all resources"""
        self.logger.info("Cleaning up bot state...")
        errors = []

        if self.mcp_client:
            try:
                await self.mcp_client.close()
                self.logger.debug("MCP client closed successfully")
            except Exception as e:
                errors.append(f"MCP client cleanup failed: {e}")

        if self.webhook_id and self.spark:
            try:
                await self.spark.unregister_webhook_async(self.webhook_id)
                self.logger.debug("Webhook unregistered successfully")
            except Exception as e:
                errors.append(f"Webhook cleanup failed: {e}")

        if errors:
            self.logger.warning(f"Cleanup issues: {', '.join(errors)}")
        else:
            self.logger.info("Bot state cleaned up successfully")


# Global bot state instance
bot_state = BotState()


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Manage application lifespan with proper initialization and cleanup."""

    # Startup
    try:
        await bot_state.initialize()
        bot_state.logger.info("Application startup completed successfully")
        yield
    except Exception as e:
        bot_state.logger.exception("Failed to initialize application: %s", str(e))
        raise

    # Shutdown
    try:
        await bot_state.cleanup()
        bot_state.logger.info("Application shutdown completed successfully")
    except Exception as e:
        bot_state.logger.exception("Error during application shutdown: %s", str(e))


app = FastAPI(title=BOT_NAME, lifespan=lifespan)


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


class MessageProcessor(object):
    """Handles message processing logic"""

    async def process_conversation(self, msgs: List[Dict], person: Dict, parent: str = None):
        """Process a conversation with the AI model"""
        NETWORK_INFO_AGENT_SYSTEM_PROMPT = """
You are a helpful network automation assistant with tool-calling capabilities working in the Cisco Live Europe network operations center (NOC). Your primary role is to analyze each user prompt and determine if it can be answered using only the available, explicitly listed tools.

Key Instructions:

1. Tool Usage and Chaining:
   - Use only tools from the currently provided, explicit tool list.
   - Never invent, suggest, or reference tools or functions that are not listed as available.
   - To provide the most complete and accurate response, run as many relevant tools as needed, even if multiple tools are required to answer a single prompt.
   - Where appropriate, use the output from one tool as the input for another to fulfill complex or multi-step requests. Chain tool calls in logical order to maximize value for the user.
   - If a user requests an action or tool that is not valid or available, politely inform them and suggest only supported actions.

2. Function Calls:
   - Use real-time data sources or functions first, before falling back to brave_search.
   - Every function call must strictly follow the specified format, including all required parameters.
   - Place each function call reply on a single line—no line breaks within replies.
   - Always call all relevant functions if multiple arguments or data sources are applicable.

3. Response Formatting:
   - When you receive tool responses, identify the data source by name and clearly attribute each part of your answer to its source.
   - Crucially, only use markdown formatting that is explicitly supported by Webex. This means you MUST NOT use markdown tables under any circumstances. Instead, present structured information using bullet points, bolding, and clear line breaks to ensure readability.
   - Address the user by their name in your response.
   - Use emojis to enhance clarity or engagement, where appropriate.
   - If any data source returns no results, skip it in your final output.

4. Content and Compliance:
   - Never use or reference variables in your output.
   - Do not permit actions or operations not directly supported by the available tools.
   - Provide all data returned by each tool without omission or modification.
   - Do not fabricate, guess, or fill in missing information.

Output Format:
Always return your response in clear, markdown-formatted text. Strictly adhere to Webex markdown capabilities; markdown tables are absolutely forbidden.

Examples:

User: "Show me devices with errors and get their current interface status."
Agent:
Hi [UserName]!
Here’s the information you requested:
- **Devices with Errors** (from `device_error_report_tool`):
  - DeviceA
  - DeviceB
- **Interface Status** (from `interface_status_tool`):
  - DeviceA: Port 1: Up 🟢, Port 2: Down 🔴
  - DeviceB: Port 3: Up 🟢

User: "Can you use `magic_router_tool` to reboot my router?"
Agent:
Hi [UserName]!
Sorry, the tool `magic_router_tool` is not available. Please ask about supported actions or choose from the listed tools. 😊

Notes:
- Crucial Note on Formatting: Markdown tables are explicitly forbidden due to Webex markdown limitations. Always use alternative formatting like bullet points, bolding, or clear line-separated text for structured data.
- If a user asks for real-time data, always attempt real-time tools first before using brave_search.
- If a user requests an unsupported or non-existent tool, explicitly state that it is unavailable.
- Always attribute information to its specific data source.
- Never invent or imagine new tools, actions, or responses.
- For complex requests, run all tools required in sequence, using outputs from one as needed for inputs to another, until you have gathered all relevant data.

Steps:

1. Analyze the user prompt for intent and requested action.
2. Check if the request matches any available tool (from the current tool list).
3. If yes, determine which tools to call, and in what sequence, to fully answer the prompt. If outputs from one tool can be used as inputs for another, chain the tool calls accordingly.
4. Perform the function call(s) in the correct format with all required parameters.
5. Upon receiving responses, format the answer, clearly attributing data to its source, using only Webex-compatible markdown (e.g., bullet points, bolding, italics, headers, but absolutely NO markdown tables) and emojis as appropriate.
6. If a tool or request is invalid, reply with a polite, clear explanation and suggest supported actions.
7. Skip empty or null responses from data sources.
8. Address the user by name in every response.

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

        available_functions = bot_state.available_functions
        tool_meta = bot_state.tool_meta

        while True:
            response: ChatResponse = bot_state.ollama_client.chat(
                bot_state.config.model, messages=messages, tools=available_functions, options={"temperature": 0}
            )
            if "tool_calls" in response.get("message", {}):
                messages.append(response.message)
                for tool in response.message.tool_calls:
                    func = tool.function.name
                    args = tool.function.arguments
                    tid = tool.get("id", func)
                    if next((t for t in available_functions if t["function"]["name"] == func), None):
                        if func in tool_meta and "auth_list" in tool_meta[func]:
                            if person["from_email"] not in tool_meta[func]["auth_list"]:
                                await bot_state.spark.post_to_spark_async(
                                    C.WEBEX_TEAM,
                                    bot_state.config.spark_room,
                                    f"I'm sorry, {person['nickName']}.  I can't do that for you.",
                                    parent=parent,
                                )
                                continue

                        bot_state.logger.debug("Calling function %s with arguments %s" % (func, str(args)))
                        try:
                            args = await fix_parameters(available_functions, func, args)
                            async with bot_state.mcp_client:
                                result = await bot_state.mcp_client.call_tool(func, args)

                                # FastMCP returns results in a more direct format
                                if hasattr(result, "content"):
                                    messages.append({"role": "tool", "content": str(result.content), "tool_call_id": tid})
                                elif isinstance(result, dict) and "content" in result:
                                    messages.append({"role": "tool", "content": str(result["content"]), "tool_call_id": tid})
                                else:
                                    messages.append({"role": "tool", "content": str(result), "tool_call_id": tid})
                        except Exception as e:
                            bot_state.logger.exception("Function %s encountered an error: %s" % (func, str(e)))
                            messages.append({"role": "tool", "content": "An exception occurred: %s" % str(e), "tool_call_id": tid})
                    else:
                        bot_state.logger.error("Failed to find a function named %s" % func)
                        messages.append(
                            {
                                "role": "tool",
                                "content": "You're asking me to do a naughty thing.  I don't have a tool called %s." % func,
                                "tool_call_id": tid,
                            }
                        )
            else:
                # messages.append({"role": "assistant", "content": response.message.content})
                break

        # fresponse = []
        # if response and response.message.content:
        #     for line in response.message.content.split("\n"):
        #         try:
        #             # The LLM may still choose to try and call an unavailable tool.
        #             json.loads(line)
        #         except Exception:
        #             fresponse.append(line)

        if response and response.message.content:
            await bot_state.spark.post_to_spark_async(C.WEBEX_TEAM, bot_state.config.spark_room, response.message.content, parent=parent)
        else:
            await bot_state.spark.post_to_spark_async(
                C.WEBEX_TEAM,
                bot_state.config.spark_room,
                "Sorry, %s.  I couldn't find anything regarding your question 🥺" % person["nickName"],
                parent=parent,
            )


class WebhookHandler(object):
    """Handles webhook validation and processing"""

    def validate_signature(self, signature: str, payload: bytes) -> bool:
        """Validate webhook signature"""

        sig_header = signature.strip().lower()
        hashed_payload = hmac.new(CLEUCreds.CALLBACK_TOKEN.encode("UTF-8"), payload, sha1)
        signature = hashed_payload.hexdigest().strip().lower()
        if signature != sig_header:
            bot_state.logger.error("Received invalid signature from callback; expected %s, received %s" % (signature, sig_header))
            return False

        return True

    def validate_payload(self, payload: dict) -> bool:
        """Validate webhook payload structure"""

        if (
            "data" not in payload
            or "personEmail" not in payload["data"]
            or "personId" not in payload["data"]
            or "id" not in payload["data"]
        ):
            bot_state.logger.error("Unexpected payload from Webex callback; did the API change? Payload: %s" % payload)
            return False

        return True

    async def build_conversation_history(self, msg: dict, room_id: str) -> tuple[List[Dict], Optional[str], Optional[str]]:
        """Build conversation history from Webex messages"""

        messages = [{"role": "user", "content": msg["text"]}]
        current_parent = None
        this_mid = msg["id"]

        # Build conversation history by traversing parent messages
        while "parentId" in msg and msg["parentId"] != this_mid:
            parent_id = msg["parentId"]
            parent_msg = await bot_state.spark.get_message_async(parent_id)
            if not parent_msg:
                break
            thread_msgs = await bot_state.spark.get_messages_async(room_id, parentId=parent_id)
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
                    role = "assistant" if tmsg["personEmail"] == bot_state.config.bot_email else "user"
                    messages.insert(0, {"role": role, "content": tmsg["text"]})
            role = "assistant" if parent_msg["personEmail"] == bot_state.config.bot_email else "user"
            messages.insert(0, {"role": role, "content": parent_msg["text"]})
            current_parent = parent_id if not current_parent else current_parent
            this_mid = parent_id
            msg = parent_msg

        return messages, current_parent, this_mid


# Refactored receive_callback function
@app.post("/chat")
async def receive_callback(request: Request) -> Response:
    handler = WebhookHandler()
    processor = MessageProcessor()

    # Validate and parse
    sig_header = request.headers.get("x-spark-signature")
    if not sig_header:
        # We didn't get a Webex header at all.  Someone is testing our
        # service.
        bot_state.logger.info("Received POST without a Webex signature header.")
        return JSONResponse(content={"error": "Invalid message"}, status_code=401)

    payload = await request.body()
    bot_state.logger.debug("Received payload: %s" % payload)

    if not handler.validate_signature(sig_header, payload):
        return JSONResponse(content={"error": "Message is not authentic"}, status_code=403)

    # Perform additional data validation on the payload.
    try:
        record = json.loads(payload)
    except Exception as e:
        bot_state.logger.exception("Failed to parse JSON callback payload: %s" % str(e))
        return JSONResponse(content={"error": "Invalid JSON"}, status_code=422)

    if not handler.validate_payload(record):
        return JSONResponse(content={"error": "Unexpected callback payload"}, status_code=422)

    sender = record["data"]["personEmail"]

    if sender == bot_state.config.bot_email:
        bot_state.logger.debug("Person email is our bot")
        return Response(status_code=204)

    if bot_state.room_id != record["data"]["roomId"]:
        bot_state.logger.error(
            "Webex Room ID is not the same as in the message (%s vs. %s)" % (bot_state.room_id, record["data"]["roomId"])
        )
        return JSONResponse(content={"error": "Room ID is not what we expect"}, status_code=422)

    mid = record["data"]["id"]

    msg = await bot_state.spark.get_message_async(mid)
    if not msg:
        bot_state.logger.error("Did not get a message")
        return JSONResponse(content={"error": "Did not get a message"}, status_code=422)

    messages, current_parent, this_mid = await handler.build_conversation_history(msg, bot_state.room_id)

    person = await bot_state.spark.get_person_async(record["data"]["personId"])
    if not person:
        person = {"from_email": sender, "nickName": "mate", "username": "mate"}
    else:
        person["from_email"] = sender
        person["username"] = re.sub(r"@.+$", "", person["from_email"])

    if current_parent:
        await bot_state.spark.post_to_spark_async(C.WEBEX_TEAM, bot_state.config.spark_room, THREAD_MSG_PLACEHOLDER, parent=current_parent)
    else:
        await bot_state.spark.post_to_spark_async(
            C.WEBEX_TEAM, bot_state.config.spark_room, f"Hey, {person['nickName']}!  {NEW_MSG_PLACEHOLDER}", parent=this_mid
        )

    # Process message
    try:
        await processor.process_conversation(messages, person, current_parent or this_mid)
    except Exception as e:
        bot_state.logger.exception("Failed to handle message from %s: %s" % (person["nickName"], str(e)))
        # Don't send this to the parent as it's a bug in the transaction.
        await bot_state.spark.post_to_spark_async(
            C.WEBEX_TEAM,
            bot_state.config.spark_room,
            "Whoops, I encountered an error:<br>\n```\n%s\n```" % traceback.format_exc(),
            MessageType.BAD,
        )
        return JSONResponse(content={"error": "Failed to handle message"}, status_code=500)

    return Response(status_code=204)


if __name__ == "__main__":
    uvicorn.run(app, port=9999)
