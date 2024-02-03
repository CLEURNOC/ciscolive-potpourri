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

import sys
from sparker import Sparker  # type: ignore
from argparse import ArgumentParser
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore


def main(spark, args):
    subject = ""
    msg = ""
    reading_body = False

    for line in sys.stdin:
        line = line.rstrip()
        if not reading_body and line.startswith("Subject:"):
            (_, subject) = line.split(":")
            continue

        if line == "":
            reading_body = True
            continue

        if not reading_body:
            continue

        msg += line + "\n"

    spark.post_to_spark(C.WEBEX_TEAM, args.room, f"**{subject.strip()}**\n\n```text\n{msg}```")


if __name__ == "__main__":
    spark = Sparker(token=CLEUCreds.SPARK_TOKEN)
    parser = ArgumentParser(description="Usage:")

    # script arguments
    parser.add_argument("-r", "--room", type=str, help="Webex room name", required=True)
    args = parser.parse_args()

    main(spark, args)
