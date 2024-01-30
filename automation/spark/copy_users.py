#!/usr/bin/env python3
#
# Copyright (c) 2017-2020  Joe Clarke <jclarke@cisco.com>
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

from __future__ import print_function
import sys
from argparse import ArgumentParser
from sparker import Sparker, ResourceType


def main():
    parser = ArgumentParser(description="Usage: ")

    parser.add_argument("-S", "--source-team", type=str, help="Name of the source Team of the Room")
    parser.add_argument("-s", "--source-room", type=str, help="Name of the source Room")
    parser.add_argument("-D", "--dest-team", type=str, help="Name of the destination Team of the Room")
    parser.add_argument("-d", "--dest-room", type=str, help="Name of the destination Room")
    parser.add_argument("-t", "--token", type=str, help="Webex Teams Token", required=True)
    parser.add_argument("-f", "--source-file", type=str, help="Path to file containing list of emails")
    args = parser.parse_args()

    spark = Sparker(token=args.token)

    resource = None
    if args.source_team:
        resource = args.source_team
        type = ResourceType.TEAM
    elif args.source_room:
        resource = args.source_room
        type = ResourceType.ROOM
    elif not args.source_file:
        print("ERROR: Either a source Room, source Team, or source file must be specified")
        sys.exit(1)

    if not args.source_file:
        members = spark.get_members(resource, type)
        if not members:
            print("ERROR: Failed to get members")
            sys.exit(1)
    else:
        with open(args.source_file, "rb") as fd:
            contents = fd.read().decode("utf-8")
            members = [x.strip() for x in contents.split("\n")]

    if args.dest_team:
        resource = args.dest_team
        type = ResourceType.TEAM
    elif args.dest_room:
        resource = args.dest_room
        type = ResourceType.ROOM
    else:
        print("ERROR: Either a destination Room or destination Team must be specified")
        sys.exit(1)

    if not spark.add_members(members, resource, type):
        print("ERROR: Failed to add one or more members")
        sys.exit(1)


if __name__ == "__main__":
    main()
