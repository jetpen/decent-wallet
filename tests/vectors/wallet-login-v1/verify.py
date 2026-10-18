#!/usr/bin/env python3
"""Verify wallet-login v1 vector JSON and the file digests in manifest.json."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("protocol") != "decent-wallet-login-v1":
        raise SystemExit("unexpected wallet-login protocol profile")

    digests = manifest.get("sha256")
    if not isinstance(digests, dict) or not digests:
        raise SystemExit("manifest is missing vector digests")

    declared = set(manifest.get("positive_vectors", [])) | set(manifest.get("negative_vectors", []))
    if declared != set(digests):
        raise SystemExit("manifest vector paths and digest paths differ")

    for relative_path, expected_digest in digests.items():
        path = (ROOT / relative_path).resolve()
        if ROOT.resolve() not in path.parents:
            raise SystemExit(f"vector path escapes package: {relative_path}")
        actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_digest != expected_digest:
            raise SystemExit(f"SHA-256 mismatch for {relative_path}: {actual_digest}")
        json.loads(path.read_text(encoding="utf-8"))

    positive = json.loads((ROOT / manifest["positive_vectors"][0]).read_text(encoding="utf-8"))
    if positive.get("expected") != "accept" or positive.get("profile") != manifest["protocol"]:
        raise SystemExit("positive vector profile/expected result mismatch")
    proof = positive.get("proof")
    if not isinstance(proof, dict) or set(proof) != {"profile", "challenge", "identity_id", "signature"}:
        raise SystemExit("positive vector proof schema mismatch")

    negative = json.loads((ROOT / manifest["negative_vectors"][0]).read_text(encoding="utf-8"))
    cases = negative.get("vectors")
    if not isinstance(cases, list) or not cases:
        raise SystemExit("negative vector list is empty")
    ids = [case.get("id") for case in cases]
    if len(ids) != len(set(ids)) or any(not item for item in ids):
        raise SystemExit("negative vector IDs must be present and unique")

    print(f"wallet-login v1 vectors verified: 1 positive, {len(cases)} negative")


if __name__ == "__main__":
    main()
