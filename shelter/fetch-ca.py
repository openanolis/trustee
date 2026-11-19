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
    pending = {}
    certs = set()
    console = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", console)
    for line in console.splitlines():
        # journald can interleave other processes between lines of the same PEM.
        record = re.search(r"(?:^|\s)([\w./@+-]+\[\d+\]):\s*(.*)$", line.strip())
        if record:
            source, message = record.groups()
        else:
            source = ""
            message = re.sub(r"^\[\s*\d+(?:\.\d+)?\]\s*", "", line.strip())
        if message == begin:
            pending[source] = [begin]
        elif source in pending and message == end:
            certs.add("\n".join(pending.pop(source) + [end, ""]).encode("ascii"))
        elif source in pending and re.fullmatch(r"[A-Za-z0-9+/]{1,64}={0,2}", message):
            pending[source].append(message)
    if not certs:
        raise ValueError("the ECS boot console has no complete CA yet. Retry after the instance starts")
    if len(certs) > 1:
        raise ValueError("the ECS console contains multiple distinct certificates")
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
            "--InstanceId", args.instance_id,
        ])
        encoded = json.loads(result.decode("utf-8"))["ConsoleOutput"]
        sys.stdout.buffer.write(extract(base64.b64decode(encoded).decode("utf-8", "replace")))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit("Could not read the Trustee CA from the ECS boot console: " + str(error))
