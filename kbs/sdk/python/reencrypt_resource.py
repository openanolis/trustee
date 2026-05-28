#!/usr/bin/env python3
"""
Re-encrypt a KBS EncryptedLocalFs resource from an old key to a new key.

This is the migration step of a key rotation: after the new private key has
been added to the KBS key ring (`private_key_path` / `private_key_paths`), use
this tool to rewrite each existing resource envelope so it is encrypted with the
new public key. Once every resource has been migrated, the old private key can
be removed from the KBS configuration.

The resource content (the decrypted plaintext) is never changed; only the
envelope's encryption keys are rotated.

Usage:
  ./reencrypt_resource.py --old-privkey old.pem --new-pubkey new_pub.pem \
      --in resource.json --out resource.json [--alg RSA-OAEP-256]

  # Decryption-only sanity check (no re-encryption, no output written):
  ./reencrypt_resource.py --old-privkey old.pem --in resource.json --check

In-place rewrite is allowed (`--in` and `--out` may be the same path); the file
is only overwritten after re-encryption succeeds.

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

# Reuse the envelope encryption logic from the sibling helper.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from encrypt_resource import ALGS, encrypt_resource  # noqa: E402


def _b64decode(name, value):
    try:
        return base64.b64decode(value)
    except Exception as exc:
        raise ValueError("invalid base64 in `{}`: {}".format(name, exc))


def load_rsa_private_key(path):
    if not os.path.isfile(path):
        raise FileNotFoundError("private key not found: {}".format(path))

    raw = open(path, "rb").read()
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("private key must be RSA")
    return key


def load_rsa_public_key(path):
    if not os.path.isfile(path):
        raise FileNotFoundError("public key not found: {}".format(path))

    raw = open(path, "rb").read()
    pub = serialization.load_pem_public_key(raw)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("public key must be RSA")
    return pub


def decrypt_envelope(priv, envelope):
    alg = envelope.get("alg")
    if alg not in ALGS:
        raise ValueError("unsupported alg: {}".format(alg))

    enc_key = _b64decode("enc_key", envelope["enc_key"])
    iv = _b64decode("iv", envelope["iv"])
    ciphertext = _b64decode("ciphertext", envelope["ciphertext"])
    tag = _b64decode("tag", envelope["tag"])

    if alg == "RSA1_5":
        cek = priv.decrypt(enc_key, padding.PKCS1v15())
    else:
        cek = priv.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    if len(cek) != 32:
        raise ValueError("unexpected CEK length {}, expect 32".format(len(cek)))

    aesgcm = AESGCM(cek)
    return aesgcm.decrypt(iv, ciphertext + tag, None)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Re-encrypt a KBS EncryptedLocalFs resource from an old key to a new key."
    )
    parser.add_argument("--old-privkey", required=True, help="Old RSA private key (PEM)")
    parser.add_argument("--new-pubkey", help="New RSA public key (PEM); required unless --check")
    parser.add_argument("--in", dest="input_path", required=True, help="Input envelope JSON")
    parser.add_argument("--out", dest="output_path", help="Output envelope JSON")
    parser.add_argument(
        "--alg",
        choices=ALGS,
        default="RSA-OAEP-256",
        help="RSA algorithm for the new envelope (default: RSA-OAEP-256)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only verify the resource decrypts with the old key; do not re-encrypt",
    )
    args = parser.parse_args(argv)
    if not args.check and (not args.new_pubkey or not args.output_path):
        parser.error("--new-pubkey and --out are required unless --check is given")
    return args


def main(argv):
    args = parse_args(argv)
    try:
        priv = load_rsa_private_key(args.old_privkey)
        with open(args.input_path) as f:
            envelope = json.load(f)

        plaintext = decrypt_envelope(priv, envelope)

        if args.check:
            print("ok: {} decrypts with the old key".format(args.input_path))
            return 0

        pub = load_rsa_public_key(args.new_pubkey)
        new_envelope = encrypt_resource(pub, plaintext, args.alg)
        with open(args.output_path, "w") as f:
            json.dump(new_envelope, f, ensure_ascii=False, indent=2)
        print("re-encrypted: {}".format(args.output_path))
    except Exception as e:
        print("error: {}".format(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
