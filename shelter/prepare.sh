#!/bin/bash
set -euo pipefail
exec python3 - "$(dirname "$(realpath "$0")")" "$@" <<'PY'
import argparse
import base64
import hashlib
import ipaddress
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
parser.add_argument("--rpm-dir", type=Path, required=True, help="directory containing the two official v1.10.2 AL3 RPMs")
parser.add_argument("--region")
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
    if args.admin_public_key == "-":
        (guest / "interop-local-admin").touch()
    else:
        (guest / "admin.pub").write_bytes(public_key())
    write_acl(guest / "trustee-admin.acl", args.admin_cidr)
    write_acl(guest / "trustee-client.acl", args.client_cidr)
    rpms = guest / "rpms"
    rpms.mkdir()
    for package, checksum in {
        "trustee": "4bc263009d847f179ae27dc68b8070de119b42d439bad7ec42fd19591539761c",
        "trustee-frontend": "c3afd6849b8312db156835287a2c34ce160344b22a9461be23a2cbd7578f92ba",
    }.items():
        name = f"{package}-1.10.2-1.al8.x86_64.rpm"
        path = Path(shutil.copyfile(args.rpm_dir / name, rpms / name))
        if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
            parser.error(f"unexpected SHA256 for {name}")
    (output / "shelter.yml").write_text(yaml.safe_dump(config, default_flow_style=False))
    output.rename(context)
print(f"{context / 'shelter.yml'} (target {config['default_target']})")
PY
