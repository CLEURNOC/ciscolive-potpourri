#!/usr/bin/env python

import argparse
import sys
import subprocess
import os
import json
import CLEUCreds  # type: ignore

CRITICAL_VMS = [
    "DC1-AD",
    "CL-VCENTER",
    "DC1-UMBRELLA",
    "DC1-DNS",
    "DC1-DHCP",
    "DC1-ISE",
]


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="vMotion critical VMs to a given host")
    parser.add_argument(
        "--host",
        "-H",
        metavar="<HOST>",
        help="vSphere host to which to migrate VMs",
    )
    args = parser.parse_args()

    os.environ["VMWARE_USER"] = CLEUCreds.VMWARE_USER
    os.environ["VMWARE_PASSWORD"] = CLEUCreds.VMWARE_PASSWORD

    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "300"

    command = [
        "ansible-playbook",
        "-i",
        "inventory/hosts",
        "-e",
        f"vmware_host={args.host}",
        "-e",
        f'{{"vms": {json.dumps(CRITICAL_VMS)}}}',
        "-e",
        "ansible_python_interpreter={}".format(sys.executable),
        "--tags",
        "vmotion",
        "vmotion-vms-playbook.yml",
    ]

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for c in iter(lambda: p.stdout.read(1), b""):
        sys.stdout.write(c.decode("utf-8"))
        sys.stdout.flush()

    p.poll()


if __name__ == "__main__":
    main()
