#!/usr/bin/env python
#
# Copyright (c) 2017-2018  Joe Clarke <jclarke@cisco.com>
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


from flask import Flask
from flask import jsonify
from flask import request
import sys
import json
from hashlib import sha1
import hmac
import time
import cgi
from sparker import Sparker
import CLEUCreds

SPARK_TEAM = 'CL18-Infra_team'
SPARK_ROOM = 'proTACtive Alerts'

MAX_DEVS = 10

MSG_FORMAT = '''### {}\n
**Severity:** {}\n
**Details:** {}\n
**Affects:** [{}]{}'''

app = Flask('Diagnostic Bridge Spark Gateway')


@app.route('/callback/dbridge', methods=['POST'])
def dbridge():
    global SPARK_TEAM, SPARK_ROOM, MAX_DEVS, MSG_FORMAT, spark

    phash = None
    j = None

    try:
        phash = request.headers.get('X-DB-Hash')
        if phash is None:
            raise Exception('Unable to get hash')
    except Exception as e:
        resp = jsonify({'error': 'Unable to get payload hash'})
        resp.status_code = 403
        sys.stderr.write('Unable to get payload hash\n')

        return resp

    req = request.get_data()

    hashed = hmac.new(CLEUCreds.PROTACTIVE_KEY, req, sha1)
    if hashed.digest().encode('hex').lower() != phash.lower():
        resp = jsonify({'error': 'Unauthorized payload'})
        resp.status_code = 403
        sys.stderr.write('Unauthorized payload\n')

        return resp

    content_type = request.headers.get('Content-Type')
    mimetype, ctoptions = cgi.parse_header(content_type)

    if mimetype != 'application/json':
        resp = jsonify({'error': 'Content-Type must be application/json'})
        resp.status_code = 400
        sys.stderr.write(
            'Content-Type was not application/json (was {})\n'.format(content_type))

        return resp

    sys.stderr.write('Got "{}"\n'.format(req))

    try:
        j = json.loads(req)
    except Exception as e:
        resp = jsonify({'error': 'Failed to decode JSON: {}'.format(e)})
        resp.status_code = 400
        sys.stderr.write('Failed to decode JSON: {}\n'.format(e))

        return resp

    for problem in j:
        title = problem['summary']
        desc = problem['details']

        num_devs = len(problem['instances']) if 'instances' in problem else 0
        if num_devs == 0:
            continue

        extra_msg = ''
        devs = []

        for i in range(0, num_devs):
            devs.append(problem['instances'][i]['hostname'])
            if i == MAX_DEVS:
                break

        if num_devs > MAX_DEVS:
            extra_msg = ' and {} other device(s)'.format(
                str(num_devs - MAX_DEVS))

        sres = spark.post_to_spark(SPARK_TEAM, SPARK_ROOM, MSG_FORMAT.format(
            title, problem['severity'], desc, ', '.join(devs), extra_msg))

        if not sres:
            resp = jsonify({'error': 'Error posting to Spark; see log'})
            resp.status_code = 500

            return resp

        time.sleep(1)

    resp = jsonify({'success': 'Posted to Spark successfully'})
    resp.status_code = 200

    return resp


if __name__ == '__main__':

    spark = Sparker()

    app.run(host='10.100.253.13', port=8080, threaded=True)
