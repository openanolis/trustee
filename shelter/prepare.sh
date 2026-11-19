#!/bin/bash
set -euo pipefail
exec python3 - "$(dirname "$(realpath "$0")")" "$@" <<'PY'
import argparse
import base64
import hashlib
import ipaddress
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

import yaml

source = Path(sys.argv.pop(1))
parser = argparse.ArgumentParser(prog="prepare.sh", description="Prepare a Trustee Shelter build context.")
parser.add_argument("context", type=Path, help="new or empty build context directory")
parser.add_argument("admin_public_key", help="Ed25519 public PEM, or - for a guest-local interop key")
for name in ("admin_cidr", "client_cidr", "deployer_cidr"):
    parser.add_argument(name, type=ipaddress.IPv4Network)
parser.add_argument("--external-attestation", action="store_true",
                    help="use the isolated TDX interoperability target without Shelter launch appraisal")
parser.add_argument("--rpm-dir", type=Path, required=True, help="directory containing the locked AL3 x86_64 RPMs")
parser.add_argument("--release-lock", type=Path, default=source / "trustee-release.json",
                    help="Trustee release tag, RPM version-release and SHA-256 digests")
parser.add_argument("--region")
parser.add_argument("--pccs-url", help="HTTPS PCCS origin or full SGX certification v4 URL (default: regional Alibaba Cloud VPC PCCS)")
parser.add_argument("--zone", dest="zone_id")
parser.add_argument("--instance-type")
parser.add_argument("--vpc-id")
parser.add_argument("--vswitch-id")
args = parser.parse_args()

networks = (args.admin_cidr, args.client_cidr, args.deployer_cidr)
if any(network.prefixlen == 0 for network in networks):
    parser.error("use a bounded CIDR for each role")
if bool(args.vpc_id) != bool(args.vswitch_id):
    parser.error("supply both --vpc-id and --vswitch-id for an existing network")
if args.admin_public_key == "-" and not args.external_attestation:
    parser.error("a guest-local admin key requires explicit --external-attestation")
context = args.context.resolve()
if context == source or source in context.parents:
    parser.error("use a build context outside the recipe source directory")
if context.exists() and (not context.is_dir() or any(context.iterdir())):
    parser.error("build context already exists and is not empty")

packages = ("trustee", "trustee-frontend")
try:
    release = json.loads(args.release_lock.read_text())
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", release["tag"]):
        raise ValueError("invalid release tag")
    version_release = release["rpm_version_release"]
    if not re.fullmatch(r"[0-9][A-Za-z0-9._+~^]*-[A-Za-z0-9._+~^]+", version_release):
        raise ValueError("invalid RPM version-release")
    checksums = release["sha256"]
    if set(checksums) != set(packages) or any(
        not re.fullmatch(r"[0-9a-f]{64}", checksums[package]) for package in packages
    ):
        raise ValueError("expected one SHA-256 for each of trustee and trustee-frontend")
except (OSError, KeyError, TypeError, ValueError) as err:
    parser.error(f"invalid release lock {args.release_lock}: {err}")
rpm_version_arch = f"{version_release}.x86_64"

def public_key():
    pem = Path(args.admin_public_key).read_bytes().strip()
    match = re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END PUBLIC KEY-----", pem)
    if match:
        der = base64.b64decode(b"".join(match[1].split()), validate=True)
        # RFC 8410 SubjectPublicKeyInfo for Ed25519, followed by the 32-byte public key.
        if len(der) == 44 and der.startswith(bytes.fromhex("302a300506032b6570032100")):
            return b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der) + b"\n-----END PUBLIC KEY-----\n"
    parser.error("expected one PEM-encoded Ed25519 public key")

def write_acl(path, network):
    cidrs = dict.fromkeys(("127.0.0.1", str(network)))
    path.write_text("".join(f"allow {cidr};\n" for cidr in cidrs) + "deny all;\n")

config = yaml.safe_load((source / "shelter.yml").read_text())
target = config["targets"]["production"]
provider = target["provider_options"]
for key in ("region", "zone_id", "instance_type", "vpc_id", "vswitch_id"):
    if getattr(args, key):
        provider[key] = getattr(args, key)
pccs = args.pccs_url or f"https://sgx-dcap-server-vpc.{provider['region']}.aliyuncs.com"
origin = r"https://(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]+)?"
certification = r"(?:(?:/[A-Za-z0-9._~-]+)*/sgx/certification/v4)?/?"
if not re.fullmatch(origin + certification, pccs):
    parser.error("--pccs-url must be an HTTPS origin or a URL ending in /sgx/certification/v4/")
pccs = pccs.rstrip("/")
if not pccs.endswith("/sgx/certification/v4"):
    pccs += "/sgx/certification/v4"
if args.external_attestation:
    config["default_target"] = "tdx-interop"
    config["targets"] = {"tdx-interop": target}
    target.update(trust="verified", attestation="disabled")
    provider.update(cc_mode="tdx", attestation_authority="external")
rules = provider["security_group"]["rules"]
for rule, network in zip(rules, networks):
    rule["cidr"] = str(network)
if args.admin_cidr == args.client_cidr:
    rules.pop(1)

context.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir=context.parent) as tmp:
    output = Path(tmp) / "context"
    guest = output / "guest"
    shutil.copytree(source / "guest", guest)
    shutil.copy2(source / "configure-image.sh", output)
    (guest / "pccs-url").write_text(pccs + "/\n")
    if args.admin_public_key == "-":
        (guest / "interop-local-admin").touch()
    else:
        (guest / "admin.pub").write_bytes(public_key())
    write_acl(guest / "trustee-admin.acl", args.admin_cidr)
    write_acl(guest / "trustee-client.acl", args.client_cidr)
    rpms = guest / "rpms"
    rpms.mkdir()
    for package in packages:
        name = f"{package}-{rpm_version_arch}.rpm"
        path = rpms / name
        try:
            shutil.copyfile(args.rpm_dir / name, path)
        except OSError as err:
            parser.error(f"cannot stage locked RPM {name}: {err}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != checksums[package]:
            parser.error(f"unexpected SHA256 for {name}")
    (guest / "rpm-version-arch").write_text(rpm_version_arch + "\n")
    (output / "shelter.yml").write_text(yaml.safe_dump(config, default_flow_style=False))
    output.rename(context)
print(f"{context / 'shelter.yml'} (target {config['default_target']})")
PY
