#!/usr/bin/env python3

from automation.spark.sparker_old import Sparker
from argparse import ArgumentParser
from pprint import pprint


def main():
    parser = ArgumentParser(description="Usage: ")

    parser.add_argument("-t", "--token", type=str, help="Webex Teams Token", required=True)
    args = parser.parse_args()

    spark = Sparker(token=args.token)

    members = spark.get_members("All CX PPD Team Chatter")
    pprint(members)
    print(len(members))


if __name__ == "__main__":
    main()
