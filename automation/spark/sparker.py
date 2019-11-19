#
# Copyright (c) 2017-2019  Joe Clarke <jclarke@cisco.com>
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


class Sparker():
    SPARK_API = 'https://api.ciscospark.com/v1/'

    RETRIES = 3

    _headers = {
        'authorization': None,
        'content-type': 'application/json'
    }

    _logit = False

    def __init__(self, **kwargs):
        if 'logit' in kwargs:
            self._logit = kwargs['logit']
        if 'token' in kwargs:
            self._headers['authorization'] = 'Bearer ' + kwargs['token']
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
            except Exception as e:
                if (response.status_code != 429 and response.status_code != 503 and response.status_code != 400) or i == Sparker.RETRIES:
                    return response

                time.sleep(backoff)
                backoff *= 2
                i += 1

    def set_token(self, token):
        self._headers['authorization'] = 'Bearer ' + token

    def check_token(self):
        if self._headers['authorization'] is None:
            if self._logit:
                logging.error('Spark token is not set!')
            else:
                print('Spark token is not set!')

            return False

        return True


    def get_message(self, mid):
        if not self.check_token():
            return None

        url = self.SPARK_API + 'messages' + '/' + mid

        try:
            response = Sparker._request_with_retry(
                'GET', url, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = 'Error getting message with ID {}: {}'.format(mid, e)
            if self._logit:
                logging.error(msg)
            else:
                print(msg)
            return None

        return response.json()

    def get_team_id(self, team):
        if not self.check_token():
            return None

        if team in self._team_cache:
            return self._team_cache[team]

        url = self.SPARK_API + 'teams'

        try:
            response = Sparker._request_with_retry(
                'GET', url, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = 'Error retrieving teams: {}'.format(e)
            if self._logit:
                logging.error(msg)
            else:
                print(msg)
            return None

        team_id = None
        for t in response.json()['items']:
            if t['name'] == team:
                self._team_cache[team] = t['id']
                return t['id']

        if team_id is None:
            msg = 'Error finding team ID for {}'.format(team)
            if self._logit:
                logging.error(msg)
            else:
                print(msg)

        return None

    def get_room_id(self, team_id, room):
        if not self.check_token():
            return None

        if team_id is None:
            team_id = ''

        if '{}:{}'.format(team_id, room) in self._room_cache:
            return self._room_cache['{}:{}'.format(team_id, room)]

        url = self.SPARK_API + 'rooms'
        params = {}

        if team_id != '':
            params['teamId'] = team_id

        try:
            response = Sparker._request_with_retry(
                'GET', url, headers=self._headers, params=params)
            response.raise_for_status()
        except Exception as e:
            msg = 'Error retrieving room {}: {}'.format(room, e)
            if self._logit:
                logging.error(msg)
            else:
                print(msg)
            return None

        room_id = None
        for r in response.json()['items']:
            if r['title'] == room:
                self._room_cache['{}:{}'.format(team_id, room)] = r['id']
                return r['id']

        if room_id is None:
            msg = 'Failed to find room ID for {}'.format(room)
            if self._logit:
                logging.error(msg)
            else:
                print(msg)

        return None

    def get_members(self, team):
        if not self.check_token():
            return None

        team_id = None

        team_id = self.get_team_id(team)
        if team_id is None:
            return None

        url = self.SPARK_API + 'team/memberships'

        payload = {'teamId': team_id}

        try:
            response = Sparker._request_with_retry(
                'GET', url, params=payload, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = 'Error getting team membership: {}'.format(e)
            if self._logit:
                logging.error(msg)
            else:
                print(msg)
            return None

        return response.json()

    def post_to_spark(self, team, room, msg):
        if not self.check_token():
            return None

        team_id = None

        if team is not None:
            team_id = self.get_team_id(team)
            if team_id is None:
                return False

        room_id = self.get_room_id(team_id, room)
        if room_id is None:
            return False

        url = self.SPARK_API + 'messages'

        payload = {'roomId': room_id,
                   'markdown': msg}

        try:
            response = Sparker._request_with_retry(
                'POST', url, json=payload, headers=self._headers)
            response.raise_for_status()
        except Exception as e:
            msg = 'Error posting message: {}'.format(e)
            if self._logit:
                logging.error(msg)
            else:
                print(msg)
            return False

        return True

    def post_to_spark_with_attach(self, team, room, msg, attach, fname, ftype):
        if not self.check_token():
            return None

        team_id = None

        if team is not None:
            team_id = self.get_team_id(team)
        if team_id is None:
            return False

        room_id = self.get_room_id(team_id, room)
        if room_id is None:
            return False

        url = self.SPARK_API + 'messages'

        bio = BytesIO(attach)

        payload = {'roomId': room_id,
                   'markdown': msg,
                   'files': (fname, bio, ftype)}
        m = MultipartEncoder(fields=payload)

        headers = self._headers
        headers['content-type'] = m.content_type

        try:
            response = Sparker._request_with_retry(
                'POST', url, data=m, headers=headers)
            response.raise_for_status()
        except Exception as e:
            msg = 'Error posting message: {}'.format(e)
            if self._logit:
                logging.error(msg)
            else:
                print(msg)
            return False

        return True
