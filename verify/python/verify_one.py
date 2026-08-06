#!/usr/bin/env python3
"""Re-verify the committed Phase 2 evidence trail offline with the Python SDK.

Consumes the SAME committed bytes as scripts/verify-one.ts (TypeScript) and
verify/go/verify_one.go (Go). For each claim it decodes the ProofBundle and its
VerificationReceipt, then checks:

  (1) bundle  -> identity_status reproduces the recorded decision
  (2) receipt -> signature verifies
  (3) receipt -> bundle_hash binding matches bundle_hash(bundle)
  (4) receipt -> prev_hash chain link is intact (genesis = 32 zero bytes)

Usage (from verify/python/, with the local SDK installed — see VERIFY.md):

    python3 verify_one.py            # verify every claim in manifest order
    python3 verify_one.py commit-1   # verify a single claim by label

Exits non-zero if any check fails. Offline; no network.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ratify_protocol import (
    SCOPE_FILES_WRITE,
    VerifierContext,
    VerifyOptions,
    bundle_hash,
    decode_proof_bundle,
    decode_verification_receipt,
    receipt_hash,
    verify_bundle,
    verify_verification_receipt,
)

# evidence/ sits two levels up from verify/python/.
EVIDENCE_DIR = Path(__file__).resolve().parent.parent.parent / "evidence"


class SetRevocationProvider:
    """In-memory revocation set (SPEC §17.1); Python analogue of the harness provider."""

    def __init__(self, revoked: set[str]) -> None:
        self._revoked = revoked

    def is_revoked(self, cert_id: str):
        return (cert_id in self._revoked, None)


def _okmiss(ok: bool, yes: str, no: str) -> str:
    return yes if ok else no


def main() -> int:
    manifest = json.loads((EVIDENCE_DIR / "manifest.json").read_text())
    target_resource_id = manifest["target_resource_id"]
    revocation = SetRevocationProvider(set(manifest["revoked_certs"]))

    only_label = sys.argv[1] if len(sys.argv) > 1 else ""

    prev_receipt_hash: bytes | None = None
    zero32 = bytes(32)
    failures = 0
    reported = 0

    for entry in manifest["claims"]:
        label = entry["label"]
        bundle = decode_proof_bundle((EVIDENCE_DIR / "bundles" / f"{label}.json").read_text())
        receipt = decode_verification_receipt((EVIDENCE_DIR / "receipts" / f"{label}.json").read_text())

        # (1) Re-verify the bundle; identity_status must reproduce the recorded decision.
        opts = VerifyOptions(
            required_scope=SCOPE_FILES_WRITE,
            now=entry["verified_at"],
            context=VerifierContext(
                requested_resource_id=target_resource_id,
                requested_path=entry["requested_path"],
                has_resource=True,
            ),
            revocation=revocation if entry["revoked"] else None,
        )
        res = verify_bundle(bundle, opts)
        bundle_ok = res.identity_status == entry["expected_decision"]

        # (2) Receipt signature.
        sig_err = verify_verification_receipt(receipt)

        # (3) bundle_hash binding.
        hash_ok = receipt.bundle_hash == bundle_hash(bundle)

        # (4) prev_hash chain link.
        expected_prev = prev_receipt_hash if prev_receipt_hash is not None else zero32
        chain_ok = receipt.prev_hash == expected_prev

        # Advance the chain regardless of the label filter so links stay honest.
        prev_receipt_hash = receipt_hash(receipt)

        if only_label and label != only_label:
            continue
        reported += 1

        receipt_ok = sig_err is None and hash_ok and chain_ok
        claim_ok = bundle_ok and receipt_ok
        if not claim_ok:
            failures += 1

        sig = "ok" if sig_err is None else f"BAD ({sig_err})"
        print(f"{label}: identity_status={res.identity_status} "
              f"(recorded {entry['expected_decision']}) {_okmiss(bundle_ok, 'OK', 'MISMATCH')}")
        print(f"{label}: receipt signature={sig} "
              f"bundle_hash_binding={_okmiss(hash_ok, 'ok', 'BAD')} "
              f"prev_hash_chain={_okmiss(chain_ok, 'ok', 'BROKEN')} "
              f"{_okmiss(receipt_ok, 'OK', 'FAIL')}")

    if only_label and reported == 0:
        print(f"verify_one: no claim labelled {only_label!r} in manifest", file=sys.stderr)
        return 2
    if failures:
        print(f"verify_one: {failures} claim(s) FAILED", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
