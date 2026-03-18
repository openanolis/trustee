#!/usr/bin/env python3
"""
Audit Trustee reference value against Rekor v2 evidence.

Inputs:
  - reference id / version / value
  - provenance source protocol + uri (+ optional artifact selector)
"""

import argparse
import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key


DEFAULT_TRUSTED_ROOT_URL = (
    "https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json"
)

FETCH_PROGRESS_EVERY = 200


def log(msg: str) -> None:
    print(msg, flush=True)


def fail(msg: str, code: int = 1) -> None:
    log("[FAIL] {}".format(msg))
    raise SystemExit(code)


def normalize_ref_value(value: str) -> str:
    out = value.strip().lower()
    if out.startswith("sha256:"):
        out = out.split(":", 1)[1]
    return out


def infer_scheme(host: str) -> str:
    insecure = os.getenv("TRUSTEE_OCI_INSECURE", "").lower() in {"1", "true", "yes"}
    if host.startswith("127.0.0.1") or host.startswith("localhost") or insecure:
        return "http"
    return "https"


def http_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = 20,
) -> urllib.response.addinfourl:
    req = urllib.request.Request(url=url, method=method, data=data, headers=headers or {})
    return urllib.request.urlopen(req, timeout=timeout)


def http_get_bytes(
    url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 20, verbose: bool = False
) -> bytes:
    if verbose:
        log("[HTTP] GET {}".format(url))
    req = urllib.request.Request(url=url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def init_fetch_stats() -> Dict[str, int]:
    return {"http_fetches": 0, "cache_hits": 0}


def parse_www_authenticate(header: str) -> Dict[str, str]:
    if not header.lower().startswith("bearer "):
        return {}
    attrs = header[len("Bearer ") :]
    out = {}
    for part in re.split(r",\s*", attrs):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip().strip('"')
    return out


def oci_request_with_bearer(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = 20,
    verbose: bool = False,
) -> bytes:
    req_headers = dict(headers or {})
    try:
        if verbose:
            log("[HTTP] {} {}".format(method, url))
        with http_request(method, url, headers=req_headers, data=data, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        if e.code != 401:
            detail = e.read().decode("utf-8", "replace")
            fail("request {} failed with HTTP {}: {}".format(url, e.code, detail))

        challenge = e.headers.get("WWW-Authenticate", "")
        params = parse_www_authenticate(challenge)
        realm = params.get("realm")
        if not realm:
            fail("registry auth challenge missing realm")

        qs = {}
        if params.get("service"):
            qs["service"] = params["service"]
        if params.get("scope"):
            qs["scope"] = params["scope"]
        token_url = realm + ("?" + urllib.parse.urlencode(qs) if qs else "")
        if verbose:
            log("[HTTP] GET {} (bearer token)".format(token_url))
        with http_request("GET", token_url, timeout=timeout) as token_resp:
            token_doc = json.loads(token_resp.read().decode("utf-8"))
        token = token_doc.get("token") or token_doc.get("access_token")
        if not token:
            fail("cannot fetch bearer token from `{}`".format(token_url))

        req_headers["Authorization"] = "Bearer {}".format(token)
        if verbose:
            log("[HTTP] {} {} (authorized)".format(method, url))
        with http_request(method, url, headers=req_headers, data=data, timeout=timeout) as resp2:
            return resp2.read()


def parse_oci_uri(uri: str) -> Tuple[str, str, str]:
    if not uri.startswith("oci://"):
        fail("invalid OCI uri `{}`: must start with oci://".format(uri))
    no_scheme = uri[len("oci://") :]
    if "/" not in no_scheme:
        fail("invalid OCI uri `{}`: missing repository".format(uri))
    registry, repo_ref = no_scheme.split("/", 1)
    if not registry or not repo_ref:
        fail("invalid OCI uri `{}`".format(uri))

    if "@sha256:" in repo_ref:
        repository, reference = repo_ref.split("@", 1)
    else:
        if ":" in repo_ref.rsplit("/", 1)[-1]:
            repository, tag = repo_ref.rsplit(":", 1)
            reference = tag
        else:
            repository = repo_ref
            reference = "latest"

    if not repository or not reference:
        fail("invalid OCI uri `{}`".format(uri))
    return registry, repository, reference


def choose_descriptor(manifest: dict, artifact: str) -> dict:
    layers = manifest.get("layers") or []
    if not layers:
        fail("OCI manifest has no layers")

    artifact = artifact.lower()
    artifact_type = str(manifest.get("artifactType", "")).lower()

    def score(layer: dict) -> int:
        mt = str(layer.get("mediaType", "")).lower()
        s = 0
        if artifact == "bundle":
            if "bundle" in mt:
                s += 5
            if "bundle" in artifact_type:
                s += 2
            if "json" in mt:
                s += 1
        else:
            if "provenance" in mt:
                s += 5
            if "in-toto" in mt:
                s += 2
            if "json" in mt:
                s += 1
        return s

    ranked = sorted(layers, key=score, reverse=True)
    return ranked[0]


def fetch_provenance_from_oci(uri: str, artifact: str, verbose: bool) -> bytes:
    registry, repository, reference = parse_oci_uri(uri)
    scheme = infer_scheme(registry)
    base = "{}://{}".format(scheme, registry)

    accept_manifest = (
        "application/vnd.oci.artifact.manifest.v1+json, "
        "application/vnd.oci.image.manifest.v1+json, "
        "application/vnd.docker.distribution.manifest.v2+json"
    )
    manifest_url = "{}/v2/{}/manifests/{}".format(base, repository, reference)
    manifest_raw = oci_request_with_bearer(
        "GET", manifest_url, headers={"Accept": accept_manifest}, verbose=verbose
    )
    manifest = json.loads(manifest_raw.decode("utf-8"))
    desc = choose_descriptor(manifest, artifact)

    digest = desc.get("digest")
    if not digest:
        fail("chosen OCI descriptor has no digest")
    blob_url = "{}/v2/{}/blobs/{}".format(base, repository, digest)
    blob = oci_request_with_bearer("GET", blob_url, verbose=verbose)
    if verbose:
        log("[INFO] OCI manifest artifactType={}".format(manifest.get("artifactType", "")))
        log("[INFO] OCI selected layer mediaType={}".format(desc.get("mediaType", "")))
        log("[INFO] OCI selected layer digest={}".format(digest))
    return blob


def extract_material_docs(material: bytes) -> Tuple[dict, dict, dict]:
    try:
        doc = json.loads(material.decode("utf-8"))
    except Exception as e:
        fail("provenance material is not valid JSON: {}".format(e))

    statement = None
    dsse = None
    rekor_v2 = None
    source_bundle = None

    if isinstance(doc, dict):
        source_bundle = doc.get("sourceBundle")
        statement = doc.get("statement")
        dsse = doc.get("dsseEnvelope") or (doc.get("content") or {}).get("dsseEnvelope")
        rekor_v2 = doc.get("rekorEntryV2") or (doc.get("verificationMaterial") or {}).get(
            "tlogEntries", [{}]
        )[0]

        if isinstance(source_bundle, dict):
            if dsse is None:
                dsse = source_bundle.get("dsseEnvelope") or (
                    source_bundle.get("content") or {}
                ).get("dsseEnvelope")
            if rekor_v2 is None or not rekor_v2:
                rekor_v2 = (source_bundle.get("verificationMaterial") or {}).get(
                    "tlogEntries", [{}]
                )[0]

        if statement is None and "_type" in doc and "predicateType" in doc:
            statement = doc

        if dsse is None and "payloadType" in doc and "payload" in doc and "signatures" in doc:
            dsse = doc

    if not isinstance(dsse, dict):
        fail("cannot find dsseEnvelope in provenance material")
    if not isinstance(rekor_v2, dict) or not rekor_v2:
        fail("cannot find rekorEntryV2/tlog entry in provenance material")

    if statement is None:
        payload_b64 = dsse.get("payload")
        if not isinstance(payload_b64, str):
            fail("dsseEnvelope.payload missing")
        try:
            statement = json.loads(base64.b64decode(payload_b64))
        except Exception as e:
            fail("cannot decode statement from dsse payload: {}".format(e))

    if not isinstance(statement, dict):
        fail("invalid statement document")
    return statement, dsse, rekor_v2


def verify_reference_value(statement: dict, ref_id: str, ref_ver: str, ref_value: str) -> str:
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        fail("statement.subject missing or invalid")

    matched = None
    for item in subjects:
        if isinstance(item, dict) and item.get("name") == ref_id:
            matched = item
            break
    if not matched:
        names = [s.get("name") for s in subjects if isinstance(s, dict)]
        fail("reference id `{}` not found in statement subjects: {}".format(ref_id, names))

    digest = (matched.get("digest") or {}).get("sha256")
    if not isinstance(digest, str):
        fail("statement subject digest.sha256 missing")

    expected = normalize_ref_value(ref_value)
    actual = digest.strip().lower()
    if expected != actual:
        fail(
            "reference value mismatch: input={}, statement(subject={}).sha256={}".format(
                expected, ref_id, actual
            )
        )

    actual_ver = (
        ((statement.get("predicate") or {}).get("invocation") or {})
        .get("environment", {})
        .get("artifactVersion")
    )
    if actual_ver is not None and str(actual_ver) != ref_ver:
        fail("reference version mismatch: input={}, statement={}".format(ref_ver, actual_ver))
    return actual


def tile_path_for_index(tile_index: int) -> str:
    chunks = []
    s = str(tile_index)
    while s:
        chunks.append(s[-3:].zfill(3))
        s = s[:-3]
    chunks.reverse()
    if len(chunks) == 1:
        return chunks[0]
    return "/".join(["x" + c for c in chunks[:-1]] + [chunks[-1]])


def fetch_tile_hash(
    rekor_base: str,
    level: int,
    node_index: int,
    tree_size: int,
    tile_cache: Dict[str, bytes],
    fetch_stats: Dict[str, int],
    verbose: bool,
) -> bytes:
    tile_index = node_index // 256
    pos = node_index % 256
    path = tile_path_for_index(tile_index)
    full_url = "{}/tile/{}/{}".format(rekor_base, level, path)
    raw = tile_cache.get(full_url)
    if raw is None:
        try:
            raw = http_get_bytes(full_url, verbose=verbose)
            tile_cache[full_url] = raw
            fetch_stats["http_fetches"] += 1
            if (
                not verbose
                and fetch_stats["http_fetches"] > 0
                and fetch_stats["http_fetches"] % FETCH_PROGRESS_EVERY == 0
            ):
                log(
                    "[PROGRESS] tile HTTP fetches={}, cache_hits={}".format(
                        fetch_stats["http_fetches"], fetch_stats["cache_hits"]
                    )
                )
        except urllib.error.HTTPError as e:
            if e.code != 404:
                detail = e.read().decode("utf-8", "replace")
                fail("fetch tile failed: {}, HTTP {}, {}".format(full_url, e.code, detail))
            denom = 256 ** level
            width = (tree_size // denom) % 256
            if width == 0:
                fail("tile not found and not partial: {}".format(full_url))
            partial_url = "{}/tile/{}/{}.p/{}".format(rekor_base, level, path, width)
            try:
                raw = http_get_bytes(partial_url, verbose=verbose)
                tile_cache[partial_url] = raw
                fetch_stats["http_fetches"] += 1
                if (
                    not verbose
                    and fetch_stats["http_fetches"] > 0
                    and fetch_stats["http_fetches"] % FETCH_PROGRESS_EVERY == 0
                ):
                    log(
                        "[PROGRESS] tile HTTP fetches={}, cache_hits={}".format(
                            fetch_stats["http_fetches"], fetch_stats["cache_hits"]
                        )
                    )
            except urllib.error.HTTPError as e2:
                detail = e2.read().decode("utf-8", "replace")
                fail(
                    "fetch partial tile failed: {}, HTTP {}, {}".format(
                        partial_url, e2.code, detail
                    )
                )

    else:
        fetch_stats["cache_hits"] += 1

    if len(raw) % 32 != 0:
        fail("invalid tile payload length at level {}: {}".format(level, len(raw)))
    count = len(raw) // 32
    if pos >= count:
        fail("tile position out of range: level={}, pos={}, count={}".format(level, pos, count))
    return raw[pos * 32 : (pos + 1) * 32]


def fetch_level0_leaf_hash(
    rekor_base: str,
    log_index: int,
    tree_size: int,
    tile_cache: Dict[str, bytes],
    fetch_stats: Dict[str, int],
    verbose: bool,
) -> bytes:
    return fetch_tile_hash(
        rekor_base=rekor_base,
        level=0,
        node_index=log_index,
        tree_size=tree_size,
        tile_cache=tile_cache,
        fetch_stats=fetch_stats,
        verbose=verbose,
    )


def verify_inclusion_root(
    leaf_hash: bytes, log_index: int, tree_size: int, audit_hashes_b64: List[str]
) -> bytes:
    def h_children(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + left + right).digest()

    node = leaf_hash
    idx = log_index
    last = tree_size - 1
    for item in audit_hashes_b64:
        sibling = base64.b64decode(item)
        if idx % 2 == 1 or idx == last:
            node = h_children(sibling, node)
            while idx % 2 == 0 and idx != 0:
                idx //= 2
                last //= 2
        else:
            node = h_children(node, sibling)
        idx //= 2
        last //= 2
    if last != 0:
        fail("invalid inclusion proof: tree reduction did not end at root")
    return node


def parse_checkpoint_note(envelope: str) -> dict:
    if "\n\n" not in envelope:
        fail("invalid checkpoint envelope: missing separator blank line")
    text_part, sig_part = envelope.split("\n\n", 1)
    text_lines = text_part.splitlines()
    if len(text_lines) < 3:
        fail("invalid checkpoint note text lines")
    origin = text_lines[0].strip()
    try:
        tree_size = int(text_lines[1].strip())
    except Exception:
        fail("invalid checkpoint tree size")
    root_hash = text_lines[2].strip()

    sigs = []
    for line in sig_part.splitlines():
        if not line.strip():
            continue
        if not line.startswith("— "):
            continue
        rest = line[2:]
        if " " not in rest:
            continue
        key_name, sig_b64 = rest.split(" ", 1)
        sigs.append((key_name.strip(), sig_b64.strip()))

    return {
        "origin": origin,
        "tree_size": tree_size,
        "root_hash": root_hash,
        "note_text": text_part + "\n",
        "signatures": sigs,
        "envelope": envelope,
    }


def fetch_latest_checkpoint_note(rekor_base: str, verbose: bool) -> dict:
    url = "{}/checkpoint".format(rekor_base)
    raw = http_get_bytes(url, verbose=verbose).decode("utf-8", "replace")
    return parse_checkpoint_note(raw)


def find_tlog_key(trusted_root: dict, rekor_base: str) -> dict:
    tlogs = trusted_root.get("tlogs") or []
    base = rekor_base.rstrip("/")
    for item in tlogs:
        if str(item.get("baseUrl", "")).rstrip("/") == base:
            return item
    fail("cannot find tlog key for `{}` in trusted root".format(rekor_base))
    return {}


def key_id_for_note(key_name: str, sig_type: int, pub_material: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(key_name.encode("utf-8"))
    h.update(b"\n")
    h.update(bytes([sig_type]))
    h.update(pub_material)
    return h.digest()[:4]


def run_ed25519_verify(pubkey_der: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        key = load_der_public_key(pubkey_der)
    except Exception:
        return False
    try:
        key.verify(sig, msg)  # type: ignore[attr-defined]
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def verify_checkpoint_signature(
    checkpoint_note: dict, trusted_root_url: str, rekor_base: str, verbose: bool
) -> None:
    log("[AUDIT] checkpoint 签名校验: trusted_root={}".format(trusted_root_url))
    trusted_root = json.loads(http_get_bytes(trusted_root_url, verbose=verbose).decode("utf-8"))
    tlog_key = find_tlog_key(trusted_root, rekor_base)
    key_details = ((tlog_key.get("publicKey") or {}).get("keyDetails") or "").upper()
    key_raw_b64 = (tlog_key.get("publicKey") or {}).get("rawBytes")
    if not isinstance(key_raw_b64, str):
        fail("trusted root tlog publicKey.rawBytes missing")
    key_der = base64.b64decode(key_raw_b64)
    key_name = checkpoint_note["origin"]

    if key_details != "PKIX_ED25519":
        fail(
            "unsupported checkpoint signature keyDetails `{}` (current script supports PKIX_ED25519)".format(
                key_details
            )
        )

    # Ed25519 SPKI DER; public key is the trailing 32 bytes.
    if len(key_der) < 32:
        fail("invalid Ed25519 DER key")
    pub_material = key_der[-32:]
    expect_key_id = key_id_for_note(key_name, 0x01, pub_material)
    expect_key_id_hex = expect_key_id.hex()
    log("[AUDIT] checkpoint verifier keyDetails={}".format(key_details))
    log("[AUDIT] checkpoint verifier keyId(prefix4)={}".format(expect_key_id_hex))

    ok = False
    for sign_name, sig_b64 in checkpoint_note.get("signatures", []):
        if sign_name != key_name:
            continue
        raw = base64.b64decode(sig_b64)
        if len(raw) < 5:
            continue
        got_key_id = raw[:4]
        sig = raw[4:]
        log(
            "[AUDIT] checkpoint signature candidate: signer={}, keyId(prefix4)={}".format(
                sign_name, got_key_id.hex()
            )
        )
        if got_key_id != expect_key_id:
            continue
        if run_ed25519_verify(key_der, checkpoint_note["note_text"].encode("utf-8"), sig):
            ok = True
            break
    if not ok:
        fail("checkpoint signature verification failed")
    log("[OK] checkpoint signature verified")


def largest_power_of_two_less_than(n: int) -> int:
    if n < 2:
        return 0
    p = 1 << (n.bit_length() - 1)
    if p == n:
        p >>= 1
    return p


def power256_level(size: int) -> int:
    if size < 1:
        return -1
    lvl = 0
    s = size
    while s > 1 and s % 256 == 0:
        s //= 256
        lvl += 1
    return lvl if s == 1 else -1


def range_hash_from_tiles(
    start: int,
    size: int,
    tree_size: int,
    rekor_base: str,
    tile_cache: Dict[str, bytes],
    fetch_stats: Dict[str, int],
    memo: Dict[Tuple[int, int, int], bytes],
    verbose: bool,
) -> bytes:
    key = (start, size, tree_size)
    if key in memo:
        return memo[key]
    if size <= 0:
        fail("invalid range size for Merkle hash reconstruction")
    if size == 1:
        out = fetch_tile_hash(
            rekor_base=rekor_base,
            level=0,
            node_index=start,
            tree_size=tree_size,
            tile_cache=tile_cache,
            fetch_stats=fetch_stats,
            verbose=verbose,
        )
        memo[key] = out
        return out

    lvl = power256_level(size)
    if lvl >= 0 and start % size == 0:
        out = fetch_tile_hash(
            rekor_base=rekor_base,
            level=lvl,
            node_index=start // size,
            tree_size=tree_size,
            tile_cache=tile_cache,
            fetch_stats=fetch_stats,
            verbose=verbose,
        )
        memo[key] = out
        return out

    split = largest_power_of_two_less_than(size)
    if split <= 0 or split >= size:
        fail("cannot split Merkle range")
    left = range_hash_from_tiles(
        start,
        split,
        tree_size,
        rekor_base,
        tile_cache,
        fetch_stats,
        memo,
        verbose=verbose,
    )
    right = range_hash_from_tiles(
        start + split,
        size - split,
        tree_size,
        rekor_base,
        tile_cache,
        fetch_stats,
        memo,
        verbose=verbose,
    )
    out = hashlib.sha256(b"\x01" + left + right).digest()
    memo[key] = out
    return out


def reconstruct_root_from_tiles(
    tree_size: int,
    rekor_base: str,
    tile_cache: Dict[str, bytes],
    fetch_stats: Dict[str, int],
    verbose: bool,
) -> str:
    memo = {}
    root = range_hash_from_tiles(
        start=0,
        size=tree_size,
        tree_size=tree_size,
        rekor_base=rekor_base,
        tile_cache=tile_cache,
        fetch_stats=fetch_stats,
        memo=memo,
        verbose=verbose,
    )
    return base64.b64encode(root).decode("utf-8")


def load_state(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def save_state(path: Path, checkpoint_note: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "origin": checkpoint_note["origin"],
        "tree_size": checkpoint_note["tree_size"],
        "root_hash": checkpoint_note["root_hash"],
        "checkpoint_envelope": checkpoint_note["envelope"],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit Trustee reference value with Rekor v2 evidence (OCI provenance source)."
    )
    parser.add_argument("--reference-id", required=True, help="Reference value id")
    parser.add_argument("--reference-version", required=True, help="Reference value version")
    parser.add_argument("--reference-value", required=True, help="Reference value digest (sha256 hex)")
    parser.add_argument("--provenance-source-protocol", required=True, help="Provenance source protocol")
    parser.add_argument("--provenance-source-uri", required=True, help="Provenance source uri")
    parser.add_argument(
        "--provenance-source-artifact",
        default="bundle",
        choices=["bundle", "provenance"],
        help="Provenance source artifact kind",
    )
    parser.add_argument(
        "--rekor-url",
        default="",
        help="Optional Rekor base URL override, otherwise derived from checkpoint origin",
    )
    parser.add_argument(
        "--trusted-root-url",
        default=DEFAULT_TRUSTED_ROOT_URL,
        help="Trusted root JSON URL for checkpoint signature verification",
    )
    parser.add_argument(
        "--state-file",
        default="",
        help="Optional checkpoint state file for append-only continuity checks",
    )
    parser.add_argument(
        "--verbose-http",
        action="store_true",
        help="Print HTTP access details",
    )
    args = parser.parse_args()

    log("== Trustee Rekor v2 审计脚本 ==")
    log("[INPUT] id={}, version={}".format(args.reference_id, args.reference_version))
    log("[INPUT] value={}".format(normalize_ref_value(args.reference_value)))
    log(
        "[INPUT] provenance_source=({}) {} [{}]".format(
            args.provenance_source_protocol, args.provenance_source_uri, args.provenance_source_artifact
        )
    )

    if args.provenance_source_protocol.lower() != "oci":
        fail("currently only `oci` provenance source protocol is supported")

    log("\n[STEP 1/7] 从 OCI provenance source 拉取审计材料...")
    material = fetch_provenance_from_oci(
        args.provenance_source_uri,
        artifact=args.provenance_source_artifact,
        verbose=args.verbose_http,
    )
    log("[OK] 已获取 provenance 材料，bytes={}".format(len(material)))

    log("\n[STEP 2/7] 解析 statement / dsse / rekorEntryV2 ...")
    statement, dsse, rekor_entry = extract_material_docs(material)
    log("[OK] 解析成功")

    log("\n[STEP 3/7] 校验参考值（id/version/value）与 statement 一致...")
    matched_digest = verify_reference_value(
        statement, args.reference_id, args.reference_version, args.reference_value
    )
    log("[OK] 参考值匹配，subject.digest.sha256={}".format(matched_digest))

    log("\n[STEP 4/7] 校验 DSSE 与 Rekor canonicalizedBody 摘要一致...")
    payload_b64 = dsse.get("payload")
    if not isinstance(payload_b64, str):
        fail("dsseEnvelope.payload missing")
    payload = base64.b64decode(payload_b64)
    payload_sha256_b64 = base64.b64encode(hashlib.sha256(payload).digest()).decode()

    canonicalized_body_b64 = rekor_entry.get("canonicalizedBody") or rekor_entry.get(
        "canonicalized_body"
    )
    if not isinstance(canonicalized_body_b64, str):
        fail("rekor entry missing canonicalizedBody")
    canonicalized_body = base64.b64decode(canonicalized_body_b64)
    canonicalized_json = json.loads(canonicalized_body.decode("utf-8"))
    kind = str(canonicalized_json.get("kind", "")).lower()
    if kind != "dsse":
        fail("unexpected Rekor entry kind `{}` (expect dsse)".format(kind))
    rekor_payload_digest = (
        ((canonicalized_json.get("spec") or {}).get("dsseV002") or {})
        .get("payloadHash", {})
        .get("digest")
    ) or (
        ((canonicalized_json.get("spec") or {}).get("dsseV002") or {}).get("data", {}).get("digest")
    )
    if payload_sha256_b64 != rekor_payload_digest:
        fail(
            "dsse payload digest mismatch: local={}, rekor={}".format(
                payload_sha256_b64, rekor_payload_digest
            )
        )
    log("[OK] payload digest match: {}".format(payload_sha256_b64))

    inclusion = rekor_entry.get("inclusionProof") or {}
    try:
        log_index = int(rekor_entry.get("logIndex"))
        tree_size = int(inclusion.get("treeSize"))
    except Exception:
        fail("invalid rekor logIndex/treeSize")
    root_hash_b64 = inclusion.get("rootHash")
    audit_hashes = inclusion.get("hashes") or []
    cp_env = (inclusion.get("checkpoint") or {}).get("envelope", "")
    if not isinstance(root_hash_b64, str) or not isinstance(audit_hashes, list):
        fail("invalid inclusion proof fields")
    if not isinstance(cp_env, str) or not cp_env.strip():
        fail("inclusion proof checkpoint envelope missing")
    proof_cp = parse_checkpoint_note(cp_env)

    rekor_base = args.rekor_url.strip().rstrip("/")
    if not rekor_base:
        rekor_base = "{}://{}".format(infer_scheme(proof_cp["origin"]), proof_cp["origin"])
    log("[INFO] Rekor base URL: {}".format(rekor_base))
    log("[INFO] Rekor logIndex={}, proof.treeSize={}".format(log_index, tree_size))
    log("[INFO] Rekor proof.rootHash={}".format(root_hash_b64))

    log("\n[STEP 5/7] 校验 checkpoint 签名（proof checkpoint + latest checkpoint）...")
    if proof_cp["tree_size"] != tree_size or proof_cp["root_hash"] != root_hash_b64:
        fail("proof checkpoint text does not match inclusionProof fields")
    verify_checkpoint_signature(
        checkpoint_note=proof_cp,
        trusted_root_url=args.trusted_root_url,
        rekor_base=rekor_base,
        verbose=args.verbose_http,
    )
    latest_cp = fetch_latest_checkpoint_note(rekor_base, verbose=args.verbose_http)
    verify_checkpoint_signature(
        checkpoint_note=latest_cp,
        trusted_root_url=args.trusted_root_url,
        rekor_base=rekor_base,
        verbose=args.verbose_http,
    )
    if latest_cp["origin"] != proof_cp["origin"]:
        fail(
            "latest checkpoint origin mismatch: latest={}, proof={}".format(
                latest_cp["origin"], proof_cp["origin"]
            )
        )
    if latest_cp["tree_size"] < proof_cp["tree_size"]:
        fail(
            "latest checkpoint older than proof checkpoint: latest_size={}, proof_size={}".format(
                latest_cp["tree_size"], proof_cp["tree_size"]
            )
        )
    log(
        "[OK] checkpoint continuity: proof(size={}) -> latest(size={})".format(
            proof_cp["tree_size"], latest_cp["tree_size"]
        )
    )

    log("\n[STEP 6/7] 校验 entry 存在性与包含性证明（访问 Rekor v2 tile）...")
    tile_cache = {}
    fetch_stats = init_fetch_stats()
    leaf_hash = hashlib.sha256(b"\x00" + canonicalized_body).digest()
    server_leaf = fetch_level0_leaf_hash(
        rekor_base=rekor_base,
        log_index=log_index,
        tree_size=tree_size,
        tile_cache=tile_cache,
        fetch_stats=fetch_stats,
        verbose=args.verbose_http,
    )
    if server_leaf != leaf_hash:
        fail("entry existence check failed: tile leaf hash != local leaf hash")
    calc_root = verify_inclusion_root(leaf_hash, log_index, tree_size, audit_hashes)
    calc_root_b64 = base64.b64encode(calc_root).decode("utf-8")
    if calc_root_b64 != root_hash_b64:
        fail(
            "inclusion proof verification failed: calculated_root={}, proof_root={}".format(
                calc_root_b64, root_hash_b64
            )
        )
    log("[OK] entry exists at logIndex={}, and inclusion proof is valid".format(log_index))

    log("\n[STEP 7/7] append-only 严格校验（重构两棵树根）...")
    if args.state_file:
        state_file = Path(args.state_file)
    else:
        safe_origin = latest_cp["origin"].replace("/", "_")
        state_file = Path.home() / ".cache" / "trustee-rekor-audit" / "{}.json".format(safe_origin)

    prev_state = load_state(state_file)
    if prev_state is None:
        log(
            "[WARN] 未发现历史 checkpoint 状态；已建立基线。下一次运行将执行严格 append-only 重构校验。"
        )
        strict_append_only_done = False
    else:
        prev_env = prev_state.get("checkpoint_envelope")
        if not isinstance(prev_env, str) or not prev_env.strip():
            fail("previous state missing checkpoint_envelope; cannot run strict append-only check")
        prev_cp = parse_checkpoint_note(prev_env)
        verify_checkpoint_signature(
            checkpoint_note=prev_cp,
            trusted_root_url=args.trusted_root_url,
            rekor_base=rekor_base,
            verbose=args.verbose_http,
        )
        if prev_cp["origin"] != latest_cp["origin"]:
            fail(
                "previous checkpoint origin mismatch: previous={}, latest={}".format(
                    prev_cp["origin"], latest_cp["origin"]
                )
            )
        if latest_cp["tree_size"] < prev_cp["tree_size"]:
            fail(
                "append-only failed: latest tree size {} < previous {}".format(
                    latest_cp["tree_size"], prev_cp["tree_size"]
                )
            )

        log(
            "[AUDIT] reconstruct previous root from Rekor tiles: size={}".format(
                prev_cp["tree_size"]
            )
        )
        prev_rebuilt = reconstruct_root_from_tiles(
            tree_size=prev_cp["tree_size"],
            rekor_base=rekor_base,
            tile_cache=tile_cache,
            fetch_stats=fetch_stats,
            verbose=args.verbose_http,
        )
        log(
            "[AUDIT] previous root expected={}, rebuilt={}".format(
                prev_cp["root_hash"], prev_rebuilt
            )
        )
        if prev_rebuilt != prev_cp["root_hash"]:
            fail("previous checkpoint root reconstruction mismatch")

        log(
            "[AUDIT] reconstruct latest root from Rekor tiles: size={}".format(
                latest_cp["tree_size"]
            )
        )
        latest_rebuilt = reconstruct_root_from_tiles(
            tree_size=latest_cp["tree_size"],
            rekor_base=rekor_base,
            tile_cache=tile_cache,
            fetch_stats=fetch_stats,
            verbose=args.verbose_http,
        )
        log(
            "[AUDIT] latest root expected={}, rebuilt={}".format(
                latest_cp["root_hash"], latest_rebuilt
            )
        )
        if latest_rebuilt != latest_cp["root_hash"]:
            fail("latest checkpoint root reconstruction mismatch")

        strict_append_only_done = True
        log("[OK] strict append-only verification passed (previous root -> latest root)")
        log(
            "[AUDIT] tile fetch summary: http_fetches={}, cache_hits={}".format(
                fetch_stats["http_fetches"], fetch_stats["cache_hits"]
            )
        )

    save_state(state_file, latest_cp)
    log("[OK] checkpoint state saved: {}".format(state_file))

    log("\n================ AUDIT RESULT ================")
    log("[PASS] 1) 参考值与 statement/rekor 中内容一致")
    log("[PASS] 2) entry 在 Rekor v2 上存在且包含性证明通过")
    log("[PASS] 3) checkpoint 签名校验通过（proof + latest）")
    if strict_append_only_done:
        log("[PASS] 4) append-only 严格校验通过（两次 checkpoint 树根重构一致）")
    else:
        log("[PASS] 4) append-only：已建立基线，下一次运行将执行严格校验")
    log("=============================================")


if __name__ == "__main__":
    main()
