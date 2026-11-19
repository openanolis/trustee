#!/usr/bin/env python3
"""Read the public Trustee CA from the authenticated ECS boot console."""

import argparse
import base64
import json
import re
import subprocess
import sys


def extract(console):
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    lines = None
    certs = set()
    for line in console.splitlines():
        if line.rstrip().endswith(begin):
            lines = [begin]
        elif lines and line.rstrip().endswith(end):
            certs.add("\n".join(lines + [end, ""]).encode("ascii"))
            lines = None
        elif lines:
            # Console lines can include a kernel timestamp and a journal prefix.
            tail = line.rsplit(None, 1)[-1:]
            if tail and re.fullmatch(r"[A-Za-z0-9+/]{1,64}={0,2}", tail[0]):
                lines.append(tail[0])
    if len(certs) != 1:
        raise ValueError("expected one distinct instance CA in the ECS console")
    pem = certs.pop()
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"],
        input=pem, stdout=subprocess.PIPE, check=True,
    )
    if result.stdout.strip() != b"subject=CN=Trustee TDVM instance root":
        raise ValueError("unexpected certificate subject")
    return pem


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("region")
    parser.add_argument("instance_id")
    args = parser.parse_args()
    try:
        result = subprocess.check_output([
            "aliyun", "ecs", "GetInstanceConsoleOutput", "--RegionId", args.region,
            "--InstanceId", args.instance_id, "--RemoveSymbols", "true",
        ])
        encoded = json.loads(result.decode("utf-8"))["ConsoleOutput"]
        sys.stdout.buffer.write(extract(base64.b64decode(encoded).decode("utf-8", "replace")))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit("Could not read the Trustee CA from the ECS boot console: " + str(error))
