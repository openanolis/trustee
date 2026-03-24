#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Parse UKI reference-value JSON and print "<alg> <digest>" for slsa-generator.

Expected file content: a single JSON object with one key
``measurement.uki.<algorithm>`` and a one-element array of hex digest string.
Supported algorithms: sha256, sha384 (case and hyphen variants accepted).
"""

import json
import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("用法: parse_uki_digest.py <uki.json>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    if not path.is_file():
        print(f"UKI JSON 文件不存在: {path}", file=sys.stderr)
        return 1

    try:
        raw = path.read_text(encoding="utf-8")
        obj = json.loads(raw)
    except Exception as e:
        print(f"UKI JSON 解析失败: {e}", file=sys.stderr)
        return 1

    if not isinstance(obj, dict) or len(obj) != 1:
        print("UKI JSON 必须是仅包含一个键值对的对象", file=sys.stderr)
        return 1

    key, value = next(iter(obj.items()))
    m = re.fullmatch(r"measurement\.uki\.([A-Za-z0-9_-]+)", key)
    if not m:
        print("UKI JSON 键必须是 measurement.uki.<algorithm>", file=sys.stderr)
        return 1

    alg_raw = m.group(1).strip().lower().replace("-", "").replace("_", "")
    if alg_raw == "sha256":
        alg = "sha256"
    elif alg_raw == "sha384":
        alg = "sha384"
    else:
        print(
            f"不支持的 UKI 摘要算法: {m.group(1)} (仅支持 sha256/sha384)",
            file=sys.stderr,
        )
        return 1

    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], str):
        print("UKI JSON 值必须是仅包含一个摘要字符串的数组", file=sys.stderr)
        return 1

    digest = value[0].strip().lower()
    if not digest:
        print("UKI 摘要不能为空", file=sys.stderr)
        return 1

    if alg == "sha256" and not re.fullmatch(r"[0-9a-f]{64}", digest):
        print("UKI sha256 摘要格式非法（应为 64 位十六进制）", file=sys.stderr)
        return 1
    if alg == "sha384" and not re.fullmatch(r"[0-9a-f]{96}", digest):
        print("UKI sha384 摘要格式非法（应为 96 位十六进制）", file=sys.stderr)
        return 1

    print(f"{alg} {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
