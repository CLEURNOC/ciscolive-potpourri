#!/usr/bin/env python
#
# Copyright (c) 2017-2024  Joe Clarke <jclarke@cisco.com>
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

from sparker import Sparker, MessageType  # type: ignore
from argparse import ArgumentParser
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

SPARK_ROOM = "DHCP Scope Alarms"


def main(spark, args):
    global SPARK_ROOM

    if args.threshold == "high":
        spark.post_to_spark(
            C.WEBEX_TEAM,
            SPARK_ROOM,
            "Scope **{0}** is now **{1:.2f}%** utilized ({2} free addresses remain); suppressing future alerts until resolved or utilization increases".format(
                args.scope, args.percent, args.addresses
            ),
            MessageType.WARNING,
        )
    else:
        spark.post_to_spark(
            C.WEBEX_TEAM,
            SPARK_ROOM,
            "Scope **{0}** is now at or below **{1:.2f}%** utilized ({2} free addresses)".format(args.scope, args.percent, args.addresses),
            MessageType.GOOD,
        )


if __name__ == "__main__":
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)
    parser = ArgumentParser(description="Usage:")

    # script arguments
    parser.add_argument("-t", "--threshold", type=str, help="Threshold type", required=True)
    parser.add_argument("-p", "--percent", type=int, help="Percent of free addresses", required=True)
    parser.add_argument("-a", "--addresses", type=int, help="Number of free addresses", required=True)
    parser.add_argument("-s", "--scope", type=str, help="Scope name", required=True)
    args = parser.parse_args()

    main(spark, args)
