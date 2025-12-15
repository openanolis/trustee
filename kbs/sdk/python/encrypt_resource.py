#!/usr/bin/env python3
"""
Helper to encrypt a resource for KBS EncryptedLocalFs.

Output JSON envelope (Base64 fields):
{
  "alg": "RSA-OAEP-256",
  "enc_key": "<base64>",
  "iv": "<base64>",
  "ciphertext": "<base64>",
  "tag": "<base64>"
}

Usage:
  ./encrypt_resource.py --pubkey /path/to/pub.pem --in secret.bin --out encrypted.json \
      --alg RSA-OAEP-256

Dependencies: cryptography (pip install cryptography)
"""

import argparse
import base64
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGS = ("RSA-OAEP-256", "RSA1_5")


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def load_rsa_public_key(path):
    if not os.path.isfile(path):
        raise FileNotFoundError("public key not found: {}".format(path))

    raw = open(path, "rb").read()
    pub = serialization.load_pem_public_key(raw)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("public key must be RSA")
    return pub


def encrypt_resource(pub, plaintext, alg):
    if alg not in ALGS:
        raise ValueError("unsupported alg: {}".format(alg))

    cek = os.urandom(32)  # AES-256-GCM key
    iv = os.urandom(12)   # 12-byte nonce

    aesgcm = AESGCM(cek)
    ct_tag = aesgcm.encrypt(iv, plaintext, None)
    ciphertext, tag = ct_tag[:-16], ct_tag[-16:]

    if alg == "RSA1_5":
        enc_key = pub.encrypt(cek, padding.PKCS1v15())
    else:
        enc_key = pub.encrypt(
            cek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    return {
        "alg": alg,
        "enc_key": _b64(enc_key),
        "iv": _b64(iv),
        "ciphertext": _b64(ciphertext),
        "tag": _b64(tag),
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Encrypt a resource for KBS EncryptedLocalFs (Base64 JSON envelope)."
    )
    parser.add_argument("--pubkey", required=True, help="Path to RSA public key (PEM)")
    parser.add_argument("--in", dest="input_path", required=True, help="Plaintext file")
    parser.add_argument("--out", dest="output_path", required=True, help="Output JSON file")
    parser.add_argument(
        "--alg",
        choices=ALGS,
        default="RSA-OAEP-256",
        help="RSA algorithm for CEK encryption (default: RSA-OAEP-256)",
    )
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    try:
        pub = load_rsa_public_key(args.pubkey)
        plaintext = open(args.input_path, "rb").read()
        envelope = encrypt_resource(pub, plaintext, args.alg)
        with open(args.output_path, "w") as f:
            json.dump(envelope, f, ensure_ascii=False, indent=2)
        print("written: {}".format(args.output_path))
    except Exception as e:
        print("error: {}".format(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
