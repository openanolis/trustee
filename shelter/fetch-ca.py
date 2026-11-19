#!/usr/bin/env python3
"""Read the public Trustee CA from the authenticated ECS boot console."""

import argparse
import base64
import json
import re
import subprocess
import sys
import tempfile


class NoCertificate(ValueError):
    pass


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
        raise NoCertificate("the ECS boot console has no complete CA yet. Retry after the instance starts")
    if len(certs) > 1:
        raise ValueError("the ECS console contains multiple distinct certificates")
    pem = certs.pop()
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"],
        input=pem, stdout=subprocess.PIPE, check=True,
    )
    if result.stdout.strip() != b"subject=CN=Trustee TDVM instance root":
        raise ValueError("unexpected certificate subject")
    with tempfile.NamedTemporaryFile() as ca:
        ca.write(pem)
        ca.flush()
        verification = subprocess.run(
            ["openssl", "verify", "-check_ss_sig", "-CAfile", ca.name, ca.name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    if verification.returncode:
        raise ValueError("instance CA failed signature or validity checks. Verify the ECS and local clocks")
    return pem


def fetch(region, instance):
    command = ["aliyun", "ecs", "GetInstanceConsoleOutput", "--RegionId", region,
               "--InstanceId", instance]

    def console(args):
        result = subprocess.check_output(args)
        encoded = json.loads(result.decode("utf-8"))["ConsoleOutput"]
        return base64.b64decode(encoded).decode("utf-8", "replace")

    try:
        return extract(console(command))
    except NoCertificate:
        # Depending on the boot, ECS may populate only one of these representations.
        return extract(console(command + ["--RemoveSymbols", "true"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("region")
    parser.add_argument("instance_id")
    args = parser.parse_args()
    try:
        sys.stdout.buffer.write(fetch(args.region, args.instance_id))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit("Could not read the Trustee CA from the ECS boot console: " + str(error))
