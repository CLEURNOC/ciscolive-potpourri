#!/usr/bin/env python3

import argparse
import sys
import re
import subprocess
import os


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Add our hosts to LibreNMS")
    parser.add_argument(
        "--cred-file", "-c", metavar="<CREDENTIAL_FILE_PATH>", help="Path to the credential file that has vault passwords", required=True
    )
    parser.add_argument("--limit", metavar="<LIMIT_STRING>", help="Comma-separated list of devices or groups to add")
    args = parser.parse_args()

    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "300"

    command = [
        "ansible-playbook",
        "-i",
        "inventory/hosts",
        "--ask-vault-pass" "-e",
        "@{}".format(args.cred_file),
        "-e",
        "ansible_python_interpreter={}".format(sys.executable),
        "add-to-librenms-playbook.yml",
    ]

    if args.limit:
        command += ["--limit", "{}".format(args.limit)]

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for c in iter(lambda: p.stdout.read(1), b""):
        sys.stdout.write(c.decode("utf-8"))
        sys.stdout.flush()

    p.poll()


if __name__ == "__main__":
    main()
