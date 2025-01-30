#!/usr/bin/env python

import sys
import subprocess
import os


def main():
    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "300"

    command = [
        "ansible-playbook",
        "-i",
        "inventory/hosts",
        "-e",
        "ansible_python_interpreter={}".format(sys.executable),
        "--tags",
        "ollama",
        "update-ollama-playbook.yml",
    ]

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output = ""
    for c in iter(lambda: p.stdout.read(1), ""):
        output += c

    p.wait()
    rc = p.returncode

    if rc != 0:
        print(f"\n\n***ERROR: Failed to update ollama\n{output}!")
    else:
        print(output)


if __name__ == "__main__":
    main()
