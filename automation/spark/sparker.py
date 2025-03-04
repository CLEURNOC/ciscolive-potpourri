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

import requests
from requests_toolbelt import MultipartEncoder
from io import BytesIO
import logging
import time
import json
from enum import Enum, unique


@unique
class ResourceType(Enum):
    ROOM = 1
    TEAM = 2


@unique
class MessageType(Enum):
    GOOD = "✅ "
    BAD = "🚨🚨 "
    WARNING = "✴️ "
    NEUTRAL = ""


class Sparker(object):
    SPARK_API = "https://webexapis.com/v1/"

    RETRIES = 5

    MAX_CARD_LEN = 22737
    MAX_MSG_LEN = 7435

    def __init__(self, **kwargs):
        self._headers = {"authorization": None}
        if "logit" in kwargs:
            self._logit = kwargs["logit"]
        else:
            self._logit = False
        if "token" in kwargs:
            self._headers["authorization"] = "Bearer " + kwargs["token"]
        self._team_cache = {}
        self._room_cache = {}

    @staticmethod
    def _request_with_retry(*args, **kwargs):
        backoff = 1
        i = 0
        while True:
            try:
                response = requests.request(*args, **kwargs)
                response.raise_for_status()
                return response
            except requests.HTTPError as e:
                if (
                    e.response.status_code != 429 and e.response.status_code != 503 and e.response.status_code != 400
                ) or i == Sparker.RETRIES:
                    return e.response

                if e.response.status_code == 400:
                    print("XXX: Body is {}".format(response.text))
                    return e.response

                if e.response.status_code == 429:
                    backoff = int(e.response.headers.get("retry-after"))

                time.sleep(backoff)
                backoff *= 2
                i += 1

    @staticmethod
    def _get_items_pages(*args, **kwargs):
        more_pages = True
        result = []

        while more_pages:
            try:
                response = Sparker._request_with_retry(*args, **kwargs)
                response.raise_for_status()
                result += response.json()["items"]
                if "Link" in response.headers:
                    links = requests.utils.parse_header_links(response.headers["Link"])
                    found_next = False
                    for link in links:
                        if link["rel"] == "next":
                            args = (args[0], link["url"])
                            kwargs.pop("params", None)
                            found_next = True
                            break

                    if found_next:
                        continue

                    more_pages = False
                else:
                    more_pages = False
            except Exception as e:
                raise e

        return result

    @property
    def token(self):
        return self._headers["authorization"]

    @token.setter
    def token(self, token):
        self._headers["authorization"] = "Bearer " + token

    def check_token(self):
        if not self.token:
            if self._logit:
                logging.error("Webex token is not set!")
            else:
                print("Webex token is not set!")

            return False

        return True

    def get_webhook_for_url(self, target_url):
        if not self.check_token():
            return None

        url = self.SPARK_API + "webhooks"

        try:
            items = Sparker._get_items_pages("GET", url, headers=self._headers)
        except Exception as e:
            msg = "Error listing webhooks: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return None

        for hook in items:
            if hook["targetUrl"] == target_url:
                return hook

        return None

    def register_webhook(self, name, callback_url, resource, event, **kwargs):
        if not self.check_token():
            return None

        url = self.SPARK_API + "webhooks"

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

        try:
            response = Sparker._request_with_retry("POST", url, json=payload, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = "Error registering webhook: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return None

        return response.json()

    def unregister_webhook(self, webhook_id):
        if not self.check_token():
            return

        url = self.SPARK_API + "webhooks/" + webhook_id

        try:
            response = Sparker._request_with_retry("DELETE", url, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = "Error unregistering webhook: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return

    def get_message(self, mid):
        if not self.check_token():
            return None

        url = self.SPARK_API + "messages" + "/" + mid

        try:
            response = Sparker._request_with_retry("GET", url, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = "Error getting message with ID {}: {}".format(mid, getattr(e, "message", repr(e)))
            if self._logit:
                logging.error(msg)
            else:
                print(msg)
            return None

        return response.json()

    def get_card_response(self, did):
        if not self.check_token():
            return None

        url = self.SPARK_API + "attachment/actions/" + did

        try:
            response = Sparker._request_with_retry("GET", url, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = "Error getting card data with ID {}: {}".format(did, getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return None

        return response.json()

    def get_person(self, pid):
        if not self.check_token():
            return None

        url = self.SPARK_API + "people" + "/" + pid

        try:
            response = Sparker._request_with_retry("GET", url, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = "Error getting person with ID {}: {}".format(pid, getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return None

        return response.json()

    def get_team_id(self, team):
        if not self.check_token():
            return None

        if team in self._team_cache:
            return self._team_cache[team]

        url = self.SPARK_API + "teams"

        try:
            items = Sparker._get_items_pages("GET", url, headers=self._headers)
        except Exception as e:
            msg = "Error retrieving teams: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return None

        team_id = None
        for t in items:
            if "name" in t and t["name"] == team:
                self._team_cache[team] = t["id"]
                return t["id"]

        if team_id is None:
            msg = "Error finding team ID for {}".format(team)
            if self._logit:
                logging.error(msg)
            else:
                print(msg)

        return None

    def get_room_id(self, team_id, room):
        if not self.check_token():
            return None

        if team_id is None:
            team_id = ""

        if "{}:{}".format(team_id, room) in self._room_cache:
            return self._room_cache["{}:{}".format(team_id, room)]

        url = self.SPARK_API + "rooms"
        params = {}

        if team_id != "":
            params["teamId"] = team_id

        try:
            items = Sparker._get_items_pages("GET", url, headers=self._headers, params=params)
        except Exception as e:
            msg = "Error retrieving room {}: {}".format(room, getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return None

        room_id = None
        for r in items:
            if "title" in r and r["title"] == room:
                self._room_cache["{}:{}".format(team_id, room)] = r["id"]
                return r["id"]

        if room_id is None:
            msg = "Failed to find room ID for {}".format(room)
            if self._logit:
                logging.error(msg)
            else:
                print(msg)

        return None

    def get_members(self, resource, type=ResourceType.TEAM):
        if not self.check_token():
            return None

        payload = {}
        url = self.SPARK_API

        if type == ResourceType.TEAM:
            rid = self.get_team_id(resource)
            if rid is None:
                return None

            url += "team/memberships"
            payload["teamId"] = rid
        elif type == ResourceType.ROOM:
            rid = self.get_room_id(None, resource)
            if rid is None:
                return None

            url += "memberships"
            payload["roomId"] = rid
        else:
            msg = "Resource type must be TEAM or ROOM"
            if self._logit:
                logging.error(msg)
            else:
                print(msg)

            return None

        try:
            items = Sparker._get_items_pages("GET", url, params=payload, headers=self._headers)
        except Exception as e:
            msg = "Error getting resource membership: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return None

        return items

    def add_members(self, members, resource, type=ResourceType.TEAM):
        if not self.check_token():
            return False

        payload = {"isModerator": False}
        url = self.SPARK_API
        err_occurred = False

        if type == ResourceType.TEAM:
            rid = self.get_team_id(resource)
            if rid is None:
                return False

            url += "team/memberships"
            payload["teamId"] = rid
        elif type == ResourceType.ROOM:
            rid = self.get_room_id(None, resource)
            if rid is None:
                return False

            url += "memberships"
            payload["roomId"] = rid
        else:
            msg = "Resource type must be TEAM or ROOM"
            if self._logit:
                logging.error(msg)
            else:
                print(msg)

            return False

        mem_list = members

        if not isinstance(members, list):
            mem_list = [members]

        for member in mem_list:
            try:
                if isinstance(member, dict):
                    if "personId" in member:
                        payload["personId"] = member["personId"]
                        payload.pop("personEmail", None)
                    else:
                        payload["personEmail"] = member["personEmail"]
                        payload.pop("personId", None)
                else:
                    if member != "":
                        payload["personEmail"] = member
                        payload.pop("personId", None)
                    else:
                        continue

                response = Sparker._request_with_retry("POST", url, json=payload, headers=self._headers)
                response.raise_for_status()
            except Exception as e:
                msg = "Error adding member %s to %s: %s" % (
                    member,
                    resource,
                    getattr(e, "message", repr(e)),
                )
                if self._logit:
                    logging.exception(msg)
                else:
                    print(msg)
                err_occurred = True

        return not err_occurred

    def post_to_spark(self, team, room, msg, mtype=MessageType.NEUTRAL, **kwargs):
        if not self.check_token():
            return False

        mt = None

        try:
            mt = MessageType(mtype)
        except Exception as e:
            msg = "Invalid message type: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
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

        url = self.SPARK_API + "messages"

        payload["markdown"] = mt.value + ((msg[: Sparker.MAX_MSG_LEN] + "...") if len(msg) > Sparker.MAX_MSG_LEN else msg)

        try:
            response = Sparker._request_with_retry("POST", url, json=payload, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = "Error posting message: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return False

        return True

    def delete_message(self, mid):
        if not self.check_token():
            return False

        url = self.SPARK_API + "messages/" + mid

        try:
            response = Sparker._request_with_retry("DELETE", url, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            emsg = "Error deleting message: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(emsg)
            else:
                print(emsg)
            return False

        return True

    def post_to_spark_with_card(self, team, room, person, card, msg="", mtype=MessageType.NEUTRAL):
        if not self.check_token():
            return False

        card_len = len(json.dumps(card))
        if card_len > Sparker.MAX_CARD_LEN:
            emsg = f"Card length {card_len} exceeds max message length {Sparker.MAX_CARD_LEN}"
            if self._logit:
                logging.error(emsg)
            else:
                print(emsg)
            return False

        mt = None

        try:
            mt = MessageType(mtype)
        except Exception as e:
            emsg = "Invalid message type: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(emsg)
            else:
                print(emsg)
            return False

        payload = {}

        if person is not None:
            payload["toPersonEmail"] = person
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

        url = self.SPARK_API + "messages"
        payload["markdown"] = mt.value + ((msg[: Sparker.MAX_MSG_LEN] + "...") if len(msg) > Sparker.MAX_MSG_LEN - card_len else msg)
        payload["attachments"] = [card]

        try:
            response = Sparker._request_with_retry("POST", url, json=payload, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            emsg = "Error posting message: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(emsg)
            else:
                print(emsg)
            return False

        return True

    def get_webex_devices(self):
        url = self.SPARK_API + "devices"
        try:
            items = Sparker._get_items_pages("GET", url, headers=self._headers)
        except Exception as e:
            msg = "Error getting devices: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return None

        return items

    def get_workspace(self, workspace_id):
        url = self.SPARK_API + f"workspaces/{workspace_id}"
        try:
            response = Sparker._request_with_retry("GET", url, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = "Error getting workspaces: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return None

        return response.json()

    def get_workspace_metric(self, workspace_id, metric="temperature"):
        url = self.SPARK_API + "workspaceMetrics"
        if metric not in ("soundLevel", "ambientNoise", "temperature", "humidity", "tvoc", "peopleCount"):
            raise Exception("Unsupported metric: %s" % metric)

        try:
            details = Sparker._get_items_pages(
                "GET", url, headers=self._headers, params={"workspaceId": workspace_id, "metricName": metric}
            )
        except Exception as e:
            msg = "Error getting workspace metrics: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(msg)
            else:
                print(msg)
            return None

        return details

    def post_to_spark_with_attach(self, team, room, msg, attach, fname, ftype, mtype=MessageType.NEUTRAL):
        if not self.check_token():
            return False

        mt = None

        try:
            mt = MessageType(mtype)
        except Exception as e:
            emsg = "Invalid message type: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(emsg)
            else:
                print(emsg)
            return False

        team_id = None

        if team is not None:
            team_id = self.get_team_id(team)
        if team_id is None:
            return False

        room_id = self.get_room_id(team_id, room)
        if room_id is None:
            return False

        url = self.SPARK_API + "messages"

        bio = BytesIO(attach)

        payload = {
            "roomId": room_id,
            "markdown": mt.value + ((msg[: Sparker.MAX_MSG_LEN] + "...") if len(msg) > Sparker.MAX_MSG_LEN else msg),
            "files": (fname, bio, ftype),
        }
        m = MultipartEncoder(fields=payload)

        headers = self._headers
        headers["content-type"] = m.content_type

        try:
            response = Sparker._request_with_retry("POST", url, data=m, headers=headers)
            response.raise_for_status()
        except Exception as e:
            emsg = "Error posting message: {}".format(getattr(e, "message", repr(e)))
            if self._logit:
                logging.exception(emsg)
            else:
                print(emsg)
            return False

        return True
