#!/usr/bin/env python3
"""Run acceptance.py on the Trustee ECS with a second TDX ECS as its resource client."""

import argparse
import base64
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import ssl
import subprocess
import sys


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def guest_path(value):
    if not PurePosixPath(value).is_absolute() or not value.isprintable():
        raise argparse.ArgumentTypeError("use an absolute guest path without control characters")
    return value


def public_ca(path):
    pem = path.read_bytes().strip()
    require(len(pem) < 16384 and re.fullmatch(
        rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?\s+-----END CERTIFICATE-----", pem
    ), "expected a single public PEM certificate")
    # Re-encode only the decoded certificate. No extra bytes from the input file leave this host.
    cert = subprocess.run(["openssl", "x509", "-outform", "DER"], input=pem,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(cert.returncode == 0 and cert.stdout == ssl.PEM_cert_to_DER_cert(pem.decode("ascii")),
            "invalid public certificate")
    constraints = subprocess.run(["openssl", "x509", "-noout", "-ext", "basicConstraints"],
                                 input=pem, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(constraints.returncode == 0 and b"CA:TRUE" in constraints.stdout, "expected a CA")
    return ssl.DER_cert_to_PEM_cert(cert.stdout), hashlib.sha256(cert.stdout).hexdigest()


class CloudAssistant:
    def __init__(self, region):
        self.region = region

    def api(self, action, args, timeout=45):
        proc = subprocess.run(["aliyun", "ecs", action, "--RegionId", self.region, *args],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if proc.returncode:
            code = re.search(rb"(?m)^ErrorCode:\s*([\w.-]+)", proc.stderr)
            raise Failure(f"{action} failed ({code[1].decode() if code else proc.returncode})")
        return json.loads(proc.stdout)

    def start(self, instance, script, timeout):
        # The expected KBS denial is a command result. Preserve its exit code separately
        # so the Cloud Assistant waiter can use the same completion condition for both reads.
        script = ("#!/bin/bash\numask 077\nbash -euo pipefail 2>/dev/null <<'SHELTER_E2E'\n"
                  + script + "\nSHELTER_E2E\nprintf '\\nE2E_RC=%d\\n' \"$?\"\n")
        result = self.api("RunCommand", [
            "--InstanceId.1", instance, "--Name", "trustee-tdx-private-acceptance",
            "--Type", "RunShellScript", "--Timeout", str(timeout), "--KeepCommand", "false",
            "--ContentEncoding", "PlainText", "--CommandContent", script,
        ])
        return result["InvokeId"]

    def finish(self, instance, invocation, timeout):
        response = self.api("DescribeInvocationResults", [
            "--InstanceId", instance, "--InvokeId", invocation, "--waiter",
            "expr=Invocation.InvocationResults.InvocationResult[0].InvocationStatus || 'Pending'",
            "to=Success", "interval=2", f"timeout={timeout}",
        ], timeout + 15)
        rows = response["Invocation"]["InvocationResults"]["InvocationResult"]
        require(len(rows) == 1 and rows[0]["InstanceId"] == instance, "unexpected command target")
        output = base64.b64decode(rows[0]["Output"], validate=True).decode("utf-8")
        match = re.fullmatch(r"(.*?)\nE2E_RC=(\d+)\n?", output, re.S)
        require(match, "invalid Cloud Assistant command result")
        return int(match[2]), match[1].strip()

    def run(self, instance, script, timeout=40):
        return self.finish(instance, self.start(instance, script, timeout), timeout + 30)


def accept(args):
    server, client = args.server, args.client
    require(server != client and all(re.fullmatch(r"i-[A-Za-z0-9]+", i) for i in (server, client)),
            "provide two distinct ECS instance IDs")
    ip = ipaddress.IPv4Address(args.server_ip)
    private_networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    require(any(ip in ipaddress.ip_network(n) for n in private_networks), "expected a private server IPv4")
    pem, fingerprint = public_ca(args.ca)
    work = "/run/trustee-e2e-" + secrets.token_hex(12)
    cli = CloudAssistant(args.region)
    # The browser's --client callback exchanges one path and result per TDX session.
    # No cloud credentials, administrator key or admin token are needed by the native client.
    relay = f"""#!/bin/bash
set -euo pipefail
[[ $# == 1 && $1 =~ ^shelter-e2e/secret/e2e[0-9a-f]{{24}}$ ]]
printf '%s\\n' "$1" > {work}/request
IFS= read -r reply < {work}/reply
[[ $reply =~ ^[0-9a-f]{{64}}$ ]]
printf '%s\\n' "$reply"
"""
    check_ca = 'openssl x509 -outform DER -in "$ca" | sha256sum | cut -d" " -f1'
    callback = None
    try:
        rc, _ = cli.run(server, f"""ca={shlex.quote(args.server_ca)}
test "$({check_ca})" = {fingerprint}
ip -4 -o addr show | grep -Fq ' {ip}/'
mkdir -m 700 {work}
mkfifo -m 600 {work}/request {work}/reply
cat > {work}/client <<'CALLBACK'
{relay}CALLBACK
chmod 700 {work}/client""")
        require(rc == 0, "server private address, public CA or relay setup failed")
        native_client = shlex.quote(str(PurePosixPath(args.client_tests) / "tdx-client.sh"))
        rc, source = cli.run(client, f"""mkdir -m 700 {work}
ca={work}/ca.crt
cat > "$ca" <<'CERTIFICATE'
{pem}CERTIFICATE
openssl verify -check_ss_sig -CAfile "$ca" "$ca" >/dev/null
test "$({check_ca})" = {fingerprint}
printf '%s\\n' '{ip} trustee.internal' > {work}/hosts
awk '$0 !~ /(^|[[:space:]])trustee[.]internal([[:space:]]|$)/' /etc/hosts >> {work}/hosts
test -x {native_client}
test -x {shlex.quote(args.client_attester)}
ln -s -- {shlex.quote(args.client_attester)} {work}/trustee-attester
ip -4 route get {ip} | awk 'NR == 1 {{for (i=1; i<NF; i++) if ($i == "src") print $(i+1)}}'""")
        require(rc == 0, "client CA validity, executables or route check failed")
        source = ipaddress.IPv4Address(source)
        require(source != ip, "client and server share an address")
        browser_argv = [
            args.server_python, str(PurePosixPath(args.server_tests) / "acceptance.py"),
            "--admin-key", args.admin_key, "--ca-file", args.server_ca, "--instance-id", server,
            "--chromium", args.chromium, "--client", work + "/client",
        ]
        browser = " ".join(shlex.quote(word) for word in browser_argv)
        # The browser locally checks the decrypted hash, same-session EARs, UI and cleanup.
        # Keep its output on the server. Its exit code is sufficient for the controller.
        callback = cli.start(server, f"flock -n /run/trustee-e2e.lock {browser} >/dev/null", 720)
        path = None
        for expected in ("deny", "release"):
            rc, requested = cli.run(server, f"timeout 160 cat {work}/request", 170)
            require(rc == 0 and re.fullmatch(r"shelter-e2e/secret/e2e[0-9a-f]{24}", requested),
                    "server did not request a test resource")
            require(path is None or path == requested, "test resource changed between sessions")
            path = requested
            rc, digest = cli.run(client, f"""export PATH={work}:"$PATH"
export NO_PROXY=trustee.internal no_proxy=trustee.internal
export TRUSTEE_URL=https://trustee.internal:8082 TRUSTEE_CA_FILE={work}/ca.crt
unshare --mount --propagation private bash -euo pipefail -s -- {native_client} {path} <<'TDX'
mount --bind {work}/hosts /etc/hosts
test "$(getent ahostsv4 trustee.internal | cut -d ' ' -f1 | sort -u)" = {ip}
exec "$1" "$2"
TDX""", 115)
            require(rc != 0 or re.fullmatch(r"[0-9a-f]{64}", digest), "invalid client SHA-256")
            reply = "DENIED" if rc else digest
            delivered, _ = cli.run(server, f"timeout 10 tee {work}/reply >/dev/null <<< {reply}", 15)
            require(delivered == 0 and (rc != 0) == (expected == "deny"),
                    f"unexpected native client result at {expected} phase")
        rc, _ = cli.finish(server, callback, 240)
        callback = None
        require(rc == 0, "server browser, digest or same-session TDX audit verification failed")
        rc, _ = cli.run(server, f"""awk -v ip='{source}' -v path='/kbs/v0/resource/{path}' '
            $1 == ip && $7 == path {{ if ($9 == 200) ok++; if ($9 == 403) denied++ }}
            END {{exit !(ok && denied)}}
        ' {shlex.quote(args.access_log)}""")
        require(rc == 0, "nginx did not record the client IP for both 403 and 200")
        print("PASS two TDX ECS: private HTTPS, audited 403/200, matching secret digest and frontend")
    finally:
        if callback:
            # Let acceptance.py execute its policy restoration before removing the FIFOs.
            try:
                cli.run(server, f"timeout 2 tee {work}/reply >/dev/null <<< DENIED || true", 8)
                cli.finish(server, callback, 240)
            except Exception:
                print("Check the server's test policy and resource cleanup", file=sys.stderr)
        for instance in (server, client):
            try:
                cli.run(instance, f"if test -d {work}; then rm -r -- {work}; fi")
            except Exception:
                print(f"Check temporary directory {work} on {instance}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", required=True)
    parser.add_argument("--server", required=True, help="Trustee ECS ID")
    parser.add_argument("--client", required=True, help="independent TDX client ECS ID")
    parser.add_argument("--server-ip", required=True, help="Trustee private IPv4 in the VPC")
    parser.add_argument("--ca", type=Path, required=True, help="verified public CA from fetch-ca.py")
    parser.add_argument("--server-tests", type=guest_path, required=True)
    parser.add_argument("--client-tests", type=guest_path, required=True)
    parser.add_argument("--server-python", type=guest_path, required=True)
    parser.add_argument("--chromium", type=guest_path, required=True, help="server Chromium binary")
    parser.add_argument("--client-attester", type=guest_path, required=True)
    parser.add_argument("--admin-key", type=guest_path, default="/var/lib/trustee-shelter/identity/admin.key")
    parser.add_argument("--server-ca", type=guest_path, default="/var/lib/trustee-shelter/identity/ca.crt")
    parser.add_argument("--access-log", type=guest_path, default="/var/log/nginx/access.log")
    try:
        accept(parser.parse_args())
    except Failure as error:
        sys.exit(str(error))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(f"Two-ECS acceptance failed ({type(error).__name__})")
