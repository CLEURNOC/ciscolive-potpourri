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

"""
Modern, thread-safe Webex API client with sync and async support.

This module provides a refactored interface to the Webex (formerly Spark) API
with support for both synchronous and asynchronous operations, thread-safety,
and improved performance through connection pooling and caching.

BACKWARD COMPATIBILITY:
All existing synchronous methods are preserved. New async methods are suffixed with '_async'.
Existing code will continue to work without modifications.

IMPROVEMENTS:
- Thread-safe caching with TTL
- Connection pooling for better performance
- Async support for high-concurrency scenarios
- Better error handling and logging
- Type hints throughout
- Context manager support for automatic cleanup

USAGE:
    # Synchronous (backward compatible):
    spark = Sparker(token="your-token", logit=True)
    spark.post_to_spark(None, "Room Name", "Hello!")

    # Asynchronous:
    async with Sparker(token="your-token") as spark:
        await spark.post_to_spark_async(None, "Room Name", "Hello!")
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, unique
from functools import wraps
from io import BytesIO
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Union

try:
    import httpx

    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False
    httpx = None  # type: ignore

import requests
from requests.adapters import HTTPAdapter
from requests_toolbelt import MultipartEncoder
from urllib3.util.retry import Retry


@unique
class ResourceType(Enum):
    """Types of Webex resources for membership operations."""

    ROOM = 1
    TEAM = 2


@unique
class MessageType(Enum):
    """Message type prefixes for visual indicators."""

    GOOD = "✅ "
    BAD = "🚨🚨 "
    WARNING = "✴️ "
    NEUTRAL = ""


@dataclass
class WebexConfig:
    """Configuration for Webex API client."""

    api_base: str = "https://webexapis.com/v1/"
    max_retries: int = 5
    max_card_len: int = 22737
    max_msg_len: int = 7435
    timeout: int = 30
    pool_connections: int = 10
    pool_maxsize: int = 20
    cache_ttl: int = 300  # Cache TTL in seconds


@dataclass
class CacheEntry:
    """Cache entry with timestamp for TTL management."""

    value: Any
    timestamp: float = field(default_factory=time.time)

    def is_expired(self, ttl: int) -> bool:
        """Check if cache entry has exceeded TTL."""
        return (time.time() - self.timestamp) > ttl


class ThreadSafeCache:
    """Thread-safe cache with TTL support."""

    def __init__(self, ttl: int = 300):
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = Lock()
        self._ttl = ttl

    def get(self, key: str) -> Optional[Any]:
        """Retrieve value from cache if not expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry and not entry.is_expired(self._ttl):
                return entry.value
            elif entry:
                del self._cache[key]
            return None

    def set(self, key: str, value: Any) -> None:
        """Store value in cache with current timestamp."""
        with self._lock:
            self._cache[key] = CacheEntry(value=value)

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()

    def invalidate(self, key: str) -> None:
        """Remove specific cache entry."""
        with self._lock:
            self._cache.pop(key, None)


def ensure_token(method: Callable) -> Callable:
    """Decorator to ensure token is set before API calls."""

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.check_token():
            return None
        return method(self, *args, **kwargs)

    @wraps(method)
    async def async_wrapper(self, *args, **kwargs):
        if not self.check_token():
            return None
        return await method(self, *args, **kwargs)

    if asyncio.iscoroutinefunction(method):
        return async_wrapper
    return wrapper


class Sparker:
    """
    Webex (Spark) API client with sync/async support.

    This class provides a modern, thread-safe interface to the Webex API
    with support for both synchronous and asynchronous operations.

    Args:
        token: Webex API token
        logit: Enable logging to Python logging module
        config: Optional WebexConfig for custom configuration

    Example:
        # Synchronous usage (backward compatible)
        spark = Sparker(token="your-token")
        spark.post_to_spark(None, "Room Name", "Hello, World!")

        # Asynchronous usage
        async with Sparker(token="your-token") as spark:
            await spark.post_to_spark_async(None, "Room Name", "Hello, World!")
    """

    # Class constants
    SPARK_API = "https://webexapis.com/v1/"

    def __init__(
        self, token: Optional[str] = None, logit: bool = False, config: Optional[WebexConfig] = None, **kwargs  # For backward compatibility
    ):
        self._config = config or WebexConfig()
        self._token = f"Bearer {token}" if token else None
        self._logit = logit or kwargs.get("logit", False)
        self._logger = logging.getLogger(__name__) if self._logit else None

        # Thread-safe caches
        self._team_cache = ThreadSafeCache(ttl=self._config.cache_ttl)
        self._room_cache = ThreadSafeCache(ttl=self._config.cache_ttl)

        # Session management
        self._session: Optional[requests.Session] = None
        self._async_session: Optional["httpx.AsyncClient"] = None  # type: ignore
        self._session_lock = Lock()

        # Setup logging
        if self._logit and self._logger and not self._logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)

    def _get_session(self) -> requests.Session:
        """Get or create thread-safe requests session with connection pooling."""
        if self._session is None:
            with self._session_lock:
                if self._session is None:  # Double-check locking
                    self._session = requests.Session()
                    retry_strategy = Retry(
                        total=self._config.max_retries,
                        backoff_factor=1,
                        status_forcelist=[429, 500, 502, 503, 504],
                        allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"],
                        respect_retry_after_header=True,  # Respect retry-after header for 429/503
                        raise_on_status=False,
                    )
                    adapter = HTTPAdapter(
                        max_retries=retry_strategy,
                        pool_connections=self._config.pool_connections,
                        pool_maxsize=self._config.pool_maxsize,
                    )
                    self._session.mount("http://", adapter)
                    self._session.mount("https://", adapter)
        return self._session

    async def _get_async_session(self) -> "httpx.AsyncClient":  # type: ignore
        """Get or create async session."""
        if not ASYNC_AVAILABLE:
            raise RuntimeError("httpx is not installed. Install it to use async methods.")

        if self._async_session is None or self._async_session.is_closed:
            limits = httpx.Limits(  # type: ignore
                max_connections=self._config.pool_maxsize,
                max_keepalive_connections=self._config.pool_connections,
            )
            self._async_session = httpx.AsyncClient(  # type: ignore
                limits=limits,
                timeout=self._config.timeout,
            )
        return self._async_session

    @property
    def headers(self) -> Dict[str, str]:
        """Get headers with authorization token."""
        return {"authorization": self._token} if self._token else {}

    @property
    def token(self) -> Optional[str]:
        """Get current token."""
        return self._token

    @token.setter
    def token(self, token: str) -> None:
        """Set new token and clear caches."""
        self._token = f"Bearer {token}" if token else None
        self._team_cache.clear()
        self._room_cache.clear()

    def check_token(self) -> bool:
        """Verify that token is set."""
        if not self._token:
            msg = "Webex token is not set!"
            if self._logit and self._logger:
                self._logger.error(msg)
            else:
                print(msg)
            return False
        return True

    def _log_error(self, msg: str, exc: Optional[Exception] = None) -> None:
        """Log error message."""
        if self._logit and self._logger:
            if exc:
                self._logger.exception(msg)
            else:
                self._logger.error(msg)
        else:
            print(msg)

    def _request_with_retry_new(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Execute HTTP request with retry logic and exponential backoff.

        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Additional arguments for requests

        Returns:
            Response object or None on failure
        """
        session = self._get_session()
        kwargs.setdefault("headers", {}).update(self.headers)
        kwargs.setdefault("timeout", self._config.timeout)

        try:
            response = session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            msg = f"Request failed: {url} - {getattr(e, 'message', repr(e))}"
            self._log_error(msg, e)
            return None

    async def _async_request_with_retry(self, method: str, url: str, **kwargs) -> Optional[Any]:
        """
        Execute async HTTP request with retry logic and exponential backoff.

        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Additional arguments for request

        Returns:
            Response object or None on failure
        """
        if not ASYNC_AVAILABLE:
            raise RuntimeError("httpx is not installed. Install it to use async methods.")

        session = await self._get_async_session()
        kwargs.setdefault("headers", {}).update(self.headers)

        backoff = 1

        for attempt in range(self._config.max_retries):
            try:
                response = await session.request(method, url, **kwargs)
                # Success - return response data
                if response.status_code < 400:
                    return response

                # Rate limit or server error - retry with backoff
                if response.status_code in (429, 500, 502, 503, 504):
                    if attempt == self._config.max_retries - 1:
                        # Last attempt - log and return None
                        msg = f"Request failed after {self._config.max_retries} retries: {url} - HTTP {response.status_code}"
                        self._log_error(msg)
                        return None

                    # Get retry-after header for 429
                    if response.status_code == 429:
                        retry_after = response.headers.get("retry-after")
                        if retry_after:
                            try:
                                backoff = int(retry_after)
                            except ValueError:
                                pass

                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue

                # Client error (4xx except 429) - don't retry
                msg = f"Client error: {url} - HTTP {response.status_code}"
                self._log_error(msg)
                return None

            except asyncio.TimeoutError:
                if attempt == self._config.max_retries - 1:
                    msg = f"Request timeout after {self._config.max_retries} retries: {url}"
                    self._log_error(msg)
                    return None
                await asyncio.sleep(backoff)
                backoff *= 2
                continue

            except Exception as e:
                if attempt == self._config.max_retries - 1:
                    msg = f"Request failed: {url} - {repr(e)}"
                    self._log_error(msg, e)
                    return None
                await asyncio.sleep(backoff)
                backoff *= 2
                continue

        return None

    def _get_items_pages_new(self, method: str, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Retrieve all items from paginated API response.

        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Additional arguments for request

        Returns:
            List of all items from paginated response
        """
        result = []
        current_url = url
        params = kwargs.pop("params", None)

        while current_url:
            if params:
                kwargs["params"] = params

            response = self._request_with_retry_new(method, current_url, **kwargs)
            if not response:
                break

            try:
                data = response.json()
                result.extend(data.get("items", []))

                # Check for next page
                current_url = None
                params = None
                if "Link" in response.headers:
                    links = requests.utils.parse_header_links(response.headers["Link"])
                    for link in links:
                        if link.get("rel") == "next":
                            current_url = link["url"]
                            break
            except (ValueError, KeyError) as e:
                msg = f"Failed to parse paginated response: {repr(e)}"
                self._log_error(msg, e)
                break

        return result

    async def _async_get_items_pages(self, method: str, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Retrieve all items from paginated API response asynchronously.

        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Additional arguments for request

        Returns:
            List of all items from paginated response
        """
        if not ASYNC_AVAILABLE:
            raise RuntimeError("httpx is not installed. Install it to use async methods.")

        result = []
        current_url = url
        params = kwargs.pop("params", None)

        while current_url:
            if params:
                kwargs["params"] = params

            response = await self._async_request_with_retry(method, current_url, **kwargs)
            if not response:
                break

            try:
                data = await response.json()
                result.extend(data.get("items", []))

                # Check for next page
                current_url = None
                params = None
                if "Link" in response.headers:
                    links = requests.utils.parse_header_links(response.headers["Link"])
                    for link in links:
                        if link.get("rel") == "next":
                            current_url = link["url"]
                            break
            except Exception as e:
                msg = f"Failed to parse paginated response: {repr(e)}"
                self._log_error(msg, e)
                break

        return result

    # ==================== WEBHOOK METHODS ====================

    @ensure_token
    def get_webhook_for_url(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Find webhook by target URL."""
        url = f"{self._config.api_base}webhooks"
        items = self._get_items_pages_new("GET", url)

        for hook in items:
            if hook.get("targetUrl") == target_url:
                return hook

        return None

    @ensure_token
    async def get_webhook_for_url_async(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Async version of get_webhook_for_url."""
        url = f"{self._config.api_base}webhooks"
        items = await self._async_get_items_pages("GET", url)

        for hook in items:
            if hook.get("targetUrl") == target_url:
                return hook

        return None

    @ensure_token
    def register_webhook(self, name: str, callback_url: str, resource: str, event: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Register a new webhook."""
        url = f"{self._config.api_base}webhooks"
        payload = {
            "name": name,
            "targetUrl": callback_url,
            "resource": resource,
            "event": event,
        }

        if "filter" in kwargs:
            payload["filter"] = kwargs["filter"]
        if "secret" in kwargs:
            payload["secret"] = kwargs["secret"]

        response = self._request_with_retry_new("POST", url, json=payload)
        return response.json() if response else None

    @ensure_token
    async def register_webhook_async(self, name: str, callback_url: str, resource: str, event: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Async version of register_webhook."""
        url = f"{self._config.api_base}webhooks"
        payload = {
            "name": name,
            "targetUrl": callback_url,
            "resource": resource,
            "event": event,
        }

        if "filter" in kwargs:
            payload["filter"] = kwargs["filter"]
        if "secret" in kwargs:
            payload["secret"] = kwargs["secret"]

        response = await self._async_request_with_retry("POST", url, json=payload)
        if response:
            try:
                return await response.json()
            except Exception as e:
                self._log_error(f"Failed to parse webhook response: {repr(e)}", e)
        return None

    @ensure_token
    def unregister_webhook(self, webhook_id: str) -> None:
        """Delete a webhook."""
        url = f"{self._config.api_base}webhooks/{webhook_id}"
        self._request_with_retry_new("DELETE", url)

    @ensure_token
    async def unregister_webhook_async(self, webhook_id: str) -> None:
        """Async version of unregister_webhook."""
        url = f"{self._config.api_base}webhooks/{webhook_id}"
        await self._async_request_with_retry("DELETE", url)

    # ==================== MESSAGE METHODS ====================

    @ensure_token
    def get_message(self, mid: str) -> Optional[Dict[str, Any]]:
        """Get message by ID."""
        url = f"{self._config.api_base}messages/{mid}"
        response = self._request_with_retry_new("GET", url)
        return response.json() if response else None

    @ensure_token
    async def get_message_async(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Async version of get_message."""
        url = f"{self._config.api_base}messages/{message_id}"
        response = await self._async_request_with_retry("GET", url)
        if response:
            try:
                return await response.json()
            except Exception as e:
                self._log_error(f"Failed to parse message response: {repr(e)}", e)
        return None

    @ensure_token
    def get_messages(self, room_id: str, **kwargs) -> Optional[List[Dict[str, Any]]]:
        """Get messages from a room."""
        url = f"{self._config.api_base}messages"
        params = {"roomId": room_id}
        params.update(kwargs)
        return self._get_items_pages_new("GET", url, params=params)

    @ensure_token
    async def get_messages_async(self, room_id: str, **kwargs) -> Optional[List[Dict[str, Any]]]:
        """Async version of get_messages."""
        url = f"{self._config.api_base}messages"
        params = {"roomId": room_id}
        params.update(kwargs)
        return await self._async_get_items_pages("GET", url, params=params)

    @ensure_token
    def get_card_response(self, did: str) -> Optional[Dict[str, Any]]:
        """Get adaptive card response data."""
        url = f"{self._config.api_base}attachment/actions/{did}"
        response = self._request_with_retry_new("GET", url)
        return response.json() if response else None

    @ensure_token
    async def get_card_response_async(self, attachment_id: str) -> Optional[Dict[str, Any]]:
        """Async version of get_card_response."""
        url = f"{self._config.api_base}attachment/actions/{attachment_id}"
        response = await self._async_request_with_retry("GET", url)
        if response:
            try:
                return await response.json()
            except Exception as e:
                self._log_error(f"Failed to parse card response: {repr(e)}", e)
        return None

    @ensure_token
    def get_person(self, pid: str) -> Optional[Dict[str, Any]]:
        """Get person by ID."""
        url = f"{self._config.api_base}people/{pid}"
        response = self._request_with_retry_new("GET", url)
        return response.json() if response else None

    @ensure_token
    async def get_person_async(self, person_id: str) -> Optional[Dict[str, Any]]:
        """Async version of get_person."""
        url = f"{self._config.api_base}people/{person_id}"
        response = await self._async_request_with_retry("GET", url)
        if response:
            try:
                return await response.json()
            except Exception as e:
                self._log_error(f"Failed to parse person response: {repr(e)}", e)
        return None

    @ensure_token
    def get_team_id(self, team: str) -> Optional[str]:
        """Get team ID by name (cached)."""
        # Check cache first
        cached = self._team_cache.get(team)
        if cached:
            return cached

        url = f"{self._config.api_base}teams"
        items = self._get_items_pages_new("GET", url)

        for t in items:
            if t.get("name") == team:
                team_id = t["id"]
                self._team_cache.set(team, team_id)
                return team_id

        self._log_error(f"Error finding team ID for {team}")
        return None

    @ensure_token
    async def get_team_id_async(self, team: str) -> Optional[str]:
        """Async version of get_team_id."""
        # Check cache first
        cached = self._team_cache.get(team)
        if cached:
            return cached

        url = f"{self._config.api_base}teams"
        items = await self._async_get_items_pages("GET", url)

        for t in items:
            if t.get("name") == team:
                team_id = t["id"]
                self._team_cache.set(team, team_id)
                return team_id

        self._log_error(f"Team not found: {team}")
        return None

    @ensure_token
    def get_room_id(self, team_id: Optional[str], room: str) -> Optional[str]:
        """Get room ID by name (cached)."""
        if team_id is None:
            team_id = ""

        cache_key = f"{team_id}:{room}"

        # Check cache first
        cached = self._room_cache.get(cache_key)
        if cached:
            return cached

        url = f"{self._config.api_base}rooms"
        params = {}
        if team_id:
            params["teamId"] = team_id

        items = self._get_items_pages_new("GET", url, params=params)

        for r in items:
            if r.get("title") == room:
                room_id = r["id"]
                self._room_cache.set(cache_key, room_id)
                return room_id

        self._log_error(f"Failed to find room ID for {room}")
        return None

    @ensure_token
    async def get_room_id_async(self, team_id: Optional[str], room: str) -> Optional[str]:
        """Async version of get_room_id."""
        if team_id is None:
            team_id = ""

        cache_key = f"{team_id}:{room}"

        # Check cache first
        cached = self._room_cache.get(cache_key)
        if cached:
            return cached

        url = f"{self._config.api_base}rooms"
        params = {}
        if team_id:
            params["teamId"] = team_id

        items = await self._async_get_items_pages("GET", url, params=params)

        for r in items:
            if r.get("title") == room:
                room_id = r["id"]
                self._room_cache.set(cache_key, room_id)
                return room_id

        self._log_error(f"Room not found: {room}")
        return None

    @ensure_token
    def get_members(self, resource: str, type: ResourceType = ResourceType.TEAM) -> Optional[List[Dict[str, Any]]]:
        """Get members of a team or room."""
        params = {}
        url = self._config.api_base

        if type == ResourceType.TEAM:
            rid = self.get_team_id(resource)
            if not rid:
                return None
            url += "team/memberships"
            params["teamId"] = rid
        elif type == ResourceType.ROOM:
            rid = self.get_room_id(None, resource)
            if not rid:
                return None
            url += "memberships"
            params["roomId"] = rid
        else:
            self._log_error("Resource type must be TEAM or ROOM")
            return None

        return self._get_items_pages_new("GET", url, params=params)

    @ensure_token
    async def get_members_async(self, resource: str, type: ResourceType = ResourceType.TEAM) -> Optional[List[Dict[str, Any]]]:
        """Async version of get_members."""
        params = {}
        url = self._config.api_base

        if type == ResourceType.TEAM:
            rid = await self.get_team_id_async(resource)
            if not rid:
                return None
            url += "team/memberships"
            params["teamId"] = rid
        elif type == ResourceType.ROOM:
            rid = await self.get_room_id_async(None, resource)
            if not rid:
                return None
            url += "memberships"
            params["roomId"] = rid
        else:
            self._log_error("Resource type must be TEAM or ROOM")
            return None

        return await self._async_get_items_pages("GET", url, params=params)

    @ensure_token
    def add_members(
        self,
        members: Union[str, Dict[str, str], List[Union[str, Dict[str, str]]]],
        resource: str,
        type: ResourceType = ResourceType.TEAM,
    ) -> bool:
        """Add members to a team or room."""
        payload = {"isModerator": False}
        url = self._config.api_base
        err_occurred = False

        if type == ResourceType.TEAM:
            rid = self.get_team_id(resource)
            if not rid:
                return False
            url += "team/memberships"
            payload["teamId"] = rid
        elif type == ResourceType.ROOM:
            rid = self.get_room_id(None, resource)
            if not rid:
                return False
            url += "memberships"
            payload["roomId"] = rid
        else:
            self._log_error("Resource type must be TEAM or ROOM")
            return False

        mem_list = members if isinstance(members, list) else [members]

        for member in mem_list:
            member_payload = payload.copy()

            if isinstance(member, dict):
                if "personId" in member:
                    member_payload["personId"] = member["personId"]
                else:
                    member_payload["personEmail"] = member.get("personEmail", "")
            else:
                if member:
                    member_payload["personEmail"] = member
                else:
                    continue

            response = self._request_with_retry_new("POST", url, json=member_payload)
            if not response:
                err_occurred = True

        return not err_occurred

    @ensure_token
    async def add_members_async(
        self,
        members: Union[str, Dict[str, str], List[Union[str, Dict[str, str]]]],
        resource: str,
        type: ResourceType = ResourceType.TEAM,
    ) -> bool:
        """Async version of add_members."""
        payload = {"isModerator": False}
        url = self._config.api_base

        if type == ResourceType.TEAM:
            rid = await self.get_team_id_async(resource)
            if not rid:
                return False
            url += "team/memberships"
            payload["teamId"] = rid
        elif type == ResourceType.ROOM:
            rid = await self.get_room_id_async(None, resource)
            if not rid:
                return False
            url += "memberships"
            payload["roomId"] = rid
        else:
            self._log_error("Resource type must be TEAM or ROOM")
            return False

        mem_list = members if isinstance(members, list) else [members]
        success = True

        for member in mem_list:
            member_payload = payload.copy()

            if isinstance(member, dict):
                if "personId" in member:
                    member_payload["personId"] = member["personId"]
                else:
                    member_payload["personEmail"] = member.get("personEmail", "")
            else:
                if member:
                    member_payload["personEmail"] = member
                else:
                    continue

            response = await self._async_request_with_retry("POST", url, json=member_payload)
            if not response:
                success = False

        return success

    def _truncate_message(self, msg: str, additional_len: int = 0) -> str:
        """Truncate message if it exceeds max length."""
        max_len = self._config.max_msg_len - additional_len
        if len(msg) > max_len:
            return msg[:max_len] + "..."
        return msg

    @ensure_token
    def post_to_spark(self, team: Optional[str], room: str, msg: str, mtype: MessageType = MessageType.NEUTRAL, **kwargs) -> bool:
        """Post a message to a room or person."""
        mt = None

        try:
            mt = MessageType(mtype)
        except Exception as e:
            self._log_error(f"Invalid message type: {getattr(e, 'message', repr(e))}")
            return False

        payload = {}

        if "person" in kwargs:
            payload["toPersonEmail"] = kwargs["person"]
        elif "roomId" in kwargs:
            payload["roomId"] = kwargs["roomId"]
        else:
            team_id = None

            if team is not None:
                team_id = self.get_team_id(team)
                if team_id is None:
                    return False

            room_id = self.get_room_id(team_id, room)
            if room_id is None:
                return False

            payload["roomId"] = room_id

        if "parent" in kwargs and kwargs["parent"]:
            payload["parentId"] = kwargs["parent"]

        url = f"{self._config.api_base}messages"
        payload["markdown"] = mt.value + self._truncate_message(msg)

        response = self._request_with_retry_new("POST", url, json=payload)
        return response is not None

    @ensure_token
    async def post_to_spark_async(
        self,
        team: Optional[str],
        room: str,
        msg: str,
        mtype: MessageType = MessageType.NEUTRAL,
        person: Optional[str] = None,
        roomId: Optional[str] = None,
        parent: Optional[str] = None,
    ) -> bool:
        """Async version of post_to_spark."""
        mt = None

        try:
            mt = MessageType(mtype)
        except Exception as e:
            self._log_error(f"Invalid message type: {repr(e)}", e)
            return False

        payload = {}

        if person:
            payload["toPersonEmail"] = person
        elif roomId:
            payload["roomId"] = roomId
        else:
            team_id = await self.get_team_id_async(team) if team else None
            room_id = await self.get_room_id_async(team_id, room)
            if not room_id:
                return False
            payload["roomId"] = room_id

        if parent:
            payload["parentId"] = parent

        url = f"{self._config.api_base}messages"
        payload["markdown"] = mt.value + self._truncate_message(msg)

        response = await self._async_request_with_retry("POST", url, json=payload)
        return response is not None

    @ensure_token
    def delete_message(self, mid: str) -> bool:
        """Delete a message."""
        url = f"{self._config.api_base}messages/{mid}"
        response = self._request_with_retry_new("DELETE", url)
        return response is not None

    @ensure_token
    async def delete_message_async(self, message_id: str) -> bool:
        """Async version of delete_message."""
        url = f"{self._config.api_base}messages/{message_id}"
        response = await self._async_request_with_retry("DELETE", url)
        return response is not None

    @ensure_token
    def post_to_spark_with_card(
        self,
        team: Optional[str],
        room: str,
        person: Optional[str],
        card: Dict[str, Any],
        msg: str = "",
        mtype: MessageType = MessageType.NEUTRAL,
        **kwargs,
    ) -> bool:
        """Post a message with an adaptive card."""
        card_len = len(json.dumps(card))
        if card_len > self._config.max_card_len:
            self._log_error(f"Card length {card_len} exceeds max message length {self._config.max_card_len}")
            return False

        mt = None

        try:
            mt = MessageType(mtype)
        except Exception as e:
            self._log_error(f"Invalid message type: {getattr(e, 'message', repr(e))}")
            return False

        payload = {}

        if person is not None:
            payload["toPersonEmail"] = person
        else:
            team_id = None

            if team is not None:
                team_id = self.get_team_id(team)
            if team_id is None and team is not None:
                return False

            room_id = self.get_room_id(team_id, room)
            if room_id is None:
                return False

            payload["roomId"] = room_id

        if "parent" in kwargs and kwargs["parent"]:
            payload["parentId"] = kwargs["parent"]

        url = f"{self._config.api_base}messages"
        payload["markdown"] = mt.value + self._truncate_message(msg, card_len)
        payload["attachments"] = [card]

        response = self._request_with_retry_new("POST", url, json=payload)
        return response is not None

    @ensure_token
    async def post_to_spark_with_card_async(
        self,
        team: Optional[str],
        room: str,
        person: Optional[str],
        card: Dict[str, Any],
        msg: str = "",
        mtype: MessageType = MessageType.NEUTRAL,
        parent: Optional[str] = None,
    ) -> bool:
        """Async version of post_to_spark_with_card."""
        card_len = len(json.dumps(card))
        if card_len > self._config.max_card_len:
            self._log_error(f"Card length {card_len} exceeds max {self._config.max_card_len}")
            return False

        mt = None

        try:
            mt = MessageType(mtype)
        except Exception as e:
            self._log_error(f"Invalid message type: {repr(e)}", e)
            return False

        payload = {}

        if person:
            payload["toPersonEmail"] = person
        else:
            team_id = await self.get_team_id_async(team) if team else None
            room_id = await self.get_room_id_async(team_id, room)
            if not room_id:
                return False
            payload["roomId"] = room_id

        if parent:
            payload["parentId"] = parent

        url = f"{self._config.api_base}messages"
        payload["markdown"] = mt.value + self._truncate_message(msg, card_len)
        payload["attachments"] = [card]

        response = await self._async_request_with_retry("POST", url, json=payload)
        return response is not None

    @ensure_token
    def get_webex_devices(self) -> Optional[List[Dict[str, Any]]]:
        """Get all Webex devices."""
        url = f"{self._config.api_base}devices"
        return self._get_items_pages_new("GET", url)

    @ensure_token
    async def get_webex_devices_async(self) -> Optional[List[Dict[str, Any]]]:
        """Async version of get_webex_devices."""
        url = f"{self._config.api_base}devices"
        return await self._async_get_items_pages("GET", url)

    @ensure_token
    def get_workspace(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        """Get workspace by ID."""
        url = f"{self._config.api_base}workspaces/{workspace_id}"
        response = self._request_with_retry_new("GET", url)
        return response.json() if response else None

    @ensure_token
    async def get_workspace_async(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        """Async version of get_workspace."""
        url = f"{self._config.api_base}workspaces/{workspace_id}"
        response = await self._async_request_with_retry("GET", url)
        if response:
            try:
                return await response.json()
            except Exception as e:
                self._log_error(f"Failed to parse workspace response: {repr(e)}", e)
        return None

    @ensure_token
    def get_workspace_metric(self, workspace_id: str, metric: str = "temperature") -> Optional[List[Dict[str, Any]]]:
        """Get workspace metrics."""
        url = f"{self._config.api_base}workspaceMetrics"
        if metric not in ("soundLevel", "ambientNoise", "temperature", "humidity", "tvoc", "peopleCount"):
            raise Exception("Unsupported metric: %s" % metric)

        params = {"workspaceId": workspace_id, "metricName": metric}
        return self._get_items_pages_new("GET", url, params=params)

    @ensure_token
    async def get_workspace_metric_async(self, workspace_id: str, metric: str = "temperature") -> Optional[List[Dict[str, Any]]]:
        """Async version of get_workspace_metric."""
        valid_metrics = {
            "soundLevel",
            "ambientNoise",
            "temperature",
            "humidity",
            "tvoc",
            "peopleCount",
        }
        if metric not in valid_metrics:
            raise ValueError(f"Unsupported metric: {metric}")

        url = f"{self._config.api_base}workspaceMetrics"
        params = {"workspaceId": workspace_id, "metricName": metric}
        return await self._async_get_items_pages("GET", url, params=params)

    @ensure_token
    def post_to_spark_with_attach(
        self,
        team: Optional[str],
        room: str,
        msg: str,
        attach: bytes,
        fname: str,
        ftype: str,
        mtype: MessageType = MessageType.NEUTRAL,
        **kwargs,
    ) -> bool:
        """Post a message with a file attachment."""
        mt = None

        try:
            mt = MessageType(mtype)
        except Exception as e:
            self._log_error(f"Invalid message type: {getattr(e, 'message', repr(e))}")
            return False

        team_id = None

        if team is not None:
            team_id = self.get_team_id(team)
        if team_id is None and team is not None:
            return False

        room_id = self.get_room_id(team_id, room)
        if room_id is None:
            return False

        url = f"{self._config.api_base}messages"

        bio = BytesIO(attach)

        payload = {
            "roomId": room_id,
            "markdown": mt.value + self._truncate_message(msg),
            "files": (fname, bio, ftype),
        }

        if "parent" in kwargs and kwargs["parent"]:
            payload["parentId"] = kwargs["parent"]

        m = MultipartEncoder(fields=payload)

        headers = self.headers.copy()
        headers["content-type"] = m.content_type

        try:
            response = self._request_with_retry_new("POST", url, data=m, headers=headers)
            return response is not None
        except Exception as e:
            self._log_error(f"Error posting message: {getattr(e, 'message', repr(e))}")
            return False

    # ==================== CONTEXT MANAGER SUPPORT ====================

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup sessions."""
        self.close()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup sessions."""
        await self.close_async()

    def close(self):
        """Close synchronous session."""
        if self._session:
            self._session.close()
            self._session = None

    async def close_async(self):
        """Close asynchronous session."""
        if self._async_session and not self._async_session.is_closed:
            await self._async_session.aclose()
            self._async_session = None
