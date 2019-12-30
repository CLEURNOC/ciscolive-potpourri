#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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


import sparker
import sys
import logging
import re
import argparse

GOOD = '✅'
BAD = '🚨🚨'

if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s : %(message)s',
                        filename='/var/log/spark.log', level=logging.DEBUG)

    parser = argparse.ArgumentParser(
        prog=sys.argv[0], description='Send notifications to a Spark room')
    parser.add_argument('--team', '-t', metavar='<TEAM NAME>',
                        help='Webex Teams Team name to use')
    parser.add_argument('--room', '-r', metavar='<ROOM NAME>',
                        help='Webex Teams Room name to use', required=True)
    parser.add_argument('--token', '-T', metavar='<TOKEN>',
                        help='Spark Token to use to post', required=True)
    parser.add_argument('--good', '-g', action='store_true',
                        help='Is this a good message')
    parser.add_argument('--bad', '-b', action='store_true',
                        help='Is this a bad message')

    parser.set_defaults(team=None)
    args = parser.parse_args()

    spark = sparker.Sparker(logit=True, token=args.token)

    if not args.team and re.search(r':', args.room):
        team, room = args.room.split(':')
        args.team = team
        args.room = room

    msg = ''

    for c in sys.stdin.read():
        msg += c

    if args.good and not args.bad:
        msg = GOOD + ' ' + msg
    elif args.bad and not args.good:
        msg = BAD + ' ' + msg

    spark.post_to_spark(args.team, args.room, msg)
