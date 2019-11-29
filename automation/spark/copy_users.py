#!/usr/bin/env python3

import sys
import json
from argparse import ArgumentParser
from sparker import Sparker, ResourceType


def main():
    parser = ArgumentParser(description='Usage: ')

    parser.add_argument('-S', '--source-team', type=str,
                        help='Name of the source Team of the Room')
    parser.add_argument('-s', '--source-room', type=str,
                        help='Name of the source Room')
    parser.add_argument('-D', '--dest-team', type=str,
                        help='Name of the destination Team of the Room')
    parser.add_argument('-d', '--dest-room', type=str,
                        help='Name of the destination Room')
    parser.add_argument('-t', '--token', type=str,
                        help='Webex Teams Token', required=True)
    args = parser.parse_args()

    spark = Sparker(token=args.token)

    resource = None
    if args.source_team:
        resource = args.source_team
        type = ResourceType.TEAM
    elif args.source_room:
        resource = args.source_room
        type = ResourceType.ROOM
    else:
        print('ERROR: Either a source Room or source Team must be specified')
        sys.exit(1)

    members = spark.get_members(resource, type)
    if not members:
        print('ERROR: Failed to get members')
        sys.exit(1)

    if args.dest_team:
        resource = args.dest_team
        type = ResourceType.TEAM
    elif args.dest_room:
        resource = args.dest_room
        type = ResourceType.ROOM
    else:
        print('ERROR: Either a destination Room or destination Team must be specified')
        sys.exit(1)

    if not spark.add_members(members, resource, type):
        print('ERROR: Failed to add one or more members')
        sys.exit(1)


if __name__ == '__main__':
    main()
