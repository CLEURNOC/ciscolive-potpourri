#!/usr/bin/env python3

import argparse
import sys
import re
import subprocess
import os
import json


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Configure a switch port")
    parser.add_argument(
        "--switch",
        "-s",
        metavar="<SWITCH NAME(s)>",
        help="Switch name or names (comma-separated) on which to run commands (defaults to all) ",
    )
    parser.add_argument(
        "--commands", "-c", metavar="<COMMAND(s)>", help="Pipe-separated list of commands to run",
    )
    parser.add_argument(
        "--parents", "-p", metavar="<PARENT(s)>", help="Pipe-separated list of parents for all commands",
    )
    parser.add_argument(
        "--input", "-i", metavar="<INPUT_FILE>", help="Path to an input file with commands formated like config",
    )
    parser.add_argument(
        "--username", "-u", metavar="<USERNAME>", help="Username to use to connect to the N9Ks", required=True,
    )
    args = parser.parse_args()

    if not args.commands and not args.input:
        print("ERROR: Either --commands or --input is required.")
        sys.exit(1)

    if args.commands and args.input:
        print("ERROR: Only one of --commands or --input can be specified.")
        sys.exit(1)

    plist = []
    clist = []

    if args.input:
        contents = None
        try:
            with open(args.input, "r") as fd:
                contents = fd.read()

            lines = contents.split("\n")
            m = re.findall(r"^(\s+)", contents, re.M)
            if len(m) > 0:
                for line in lines:
                    if re.search(r"^\s", line):
                        clist.append(line)
                    else:
                        plist.append(line)
            else:
                clist = lines
        except Exception as e:
            print("ERROR: Failed to process input file: %s" % e)
            sys.exit(1)
    else:
        clist = args.commands.split("|")

        if args.parents:
            plist = args.parents.split("|")

    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "300"

    command = [
        "ansible-playbook",
        "-i",
        "inventory/hosts",
        "-u",
        args.username,
        "-k",
        "-e",
        '{{"cli_commands": {}}}'.format(json.dumps(clist)),
        "-e",
        '{{"cli_parents": {}}}'.format(json.dumps(plist)),
        "-e",
        "ansible_python_interpreter={}".format(sys.executable),
        "run-cli-playbook.yml",
    ]

    if args.switch:
        command += ["--limit", "{}".format(args.switch)]

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for c in iter(lambda: p.stdout.read(1), b""):
        sys.stdout.write(c.decode("utf-8"))
        sys.stdout.flush()

    p.poll()


if __name__ == "__main__":
    main()
