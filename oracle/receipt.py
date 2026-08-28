"""Ed25519 signed, hash-chained receipts.

This is lesson 18's receipt construction (`18-securing-ai-agents/code_samples/
18-signed-receipts.ipynb`) lifted out of the notebook and into an importable
module. The wire format is unchanged on purpose: a receipt produced here
verifies with the notebook's `verify_receipt`, and vice versa.

Why the oracle needs this at all: a drift report is a claim about the world
("as of 2026-08-27, lesson 04 pins a model that no longer exists"). A buyer who
pays for that claim has no reason to trust the seller's word for it. Signing the
report over its canonical bytes lets the buyer check two things offline, with
nothing but a public key:

  * attribution - this report came from the key that claims to publish it
  * integrity   - not one byte has changed since it was signed

It deliberately does NOT prove the report is *correct*. That boundary is the
same one lesson 18 draws, and it matters for pricing: you are selling a
verifiable, timestamped observation, not an oracle of truth.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import Any

from jcs import canonicalize
from nacl import signing
from nacl.exceptions import BadSignatureError

RECEIPT_TYPE = "course.drift_report.v1"


def b64url_nopad(data: bytes) -> str:
    """Base64url-encode bytes without padding (RFC 4648 Section 5)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    """Decode a base64url string that may be missing padding."""
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)


def sha256_canonical(obj: Any) -> str:
    """SHA-256 over the JCS (RFC 8785) canonical JSON form of `obj`."""
    return f"sha256:{hashlib.sha256(canonicalize(obj)).hexdigest()}"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sign_receipt(payload: dict, signing_key: signing.SigningKey) -> dict:
    """Attach an Ed25519 signature over the canonical bytes of `payload`.

    The `signature` object is not itself part of the signed bytes - that is what
    makes verification reconstructible from the receipt alone.
    """
    message_hash = hashlib.sha256(canonicalize(payload)).digest()
    signature_bytes = signing_key.sign(message_hash).signature
    return {
        **payload,
        "signature": {
            "alg": "EdDSA",
            "sig": b64url_nopad(signature_bytes),
            "public_key": b64url_nopad(bytes(signing_key.verify_key)),
        },
    }


def verify_receipt(receipt: dict) -> bool:
    """Verify a receipt's signature using only the key embedded in it.

    Note what this does and does not establish. It proves the receipt was signed
    by the holder of that private key and has not been altered. It does not
    establish that the key belongs to anyone you trust - that binding has to
    come from somewhere else (a published key, a DNS record, a key you were
    handed out of band).
    """
    sig_obj = receipt.get("signature")
    if not isinstance(sig_obj, dict) or sig_obj.get("alg") != "EdDSA":
        return False

    payload = {k: v for k, v in receipt.items() if k != "signature"}
    message_hash = hashlib.sha256(canonicalize(payload)).digest()

    try:
        verify_key = signing.VerifyKey(b64url_decode(sig_obj["public_key"]))
        verify_key.verify(message_hash, b64url_decode(sig_obj["sig"]))
        return True
    except (BadSignatureError, KeyError, ValueError, TypeError):
        return False


def receipt_hash(receipt: dict) -> str:
    """Chain hash of a complete receipt, signature included.

    This becomes the next receipt's `previous_receipt_hash`. Chaining is what
    turns a pile of independently-valid receipts into a sequence: drop one, or
    reorder two, and every later link stops matching.
    """
    return sha256_canonical(receipt)


def build_report_receipt(
    findings: list[dict],
    scan_meta: dict,
    sequence: int,
    previous_receipt_hash: str | None,
    signing_key: signing.SigningKey,
    publisher: str = "course-drift-oracle",
) -> dict:
    """Build and sign one drift-report receipt.

    The full findings list is hashed rather than embedded. That is not an
    accident of size - it is the commercial hinge. The receipt is free to hand
    out and proves a specific findings blob existed at a specific time; the blob
    it commits to is what the paid tool actually returns. A buyer can verify
    after paying that they received the exact thing that was promised.
    """
    payload = {
        "type": RECEIPT_TYPE,
        "publisher": publisher,
        "repo": scan_meta.get("repo"),
        "commit": scan_meta.get("commit"),
        "scanned_files": scan_meta.get("scanned_files"),
        "findings_hash": sha256_canonical(findings),
        "findings_count": len(findings),
        "severity_counts": _severity_counts(findings),
        "timestamp": utc_now(),
        "sequence": sequence,
        "previous_receipt_hash": previous_receipt_hash,
    }
    return sign_receipt(payload, signing_key)


def verify_chain(receipts: list[dict]) -> tuple[bool, str]:
    """Verify signatures and linkage across an ordered list of receipts.

    Returns (ok, human-readable reason).
    """
    previous: str | None = None
    for index, receipt in enumerate(receipts):
        if not verify_receipt(receipt):
            return False, f"receipt {index} has an invalid signature"
        if receipt.get("sequence") != index:
            return False, (
                f"receipt {index} claims sequence {receipt.get('sequence')}"
            )
        if receipt.get("previous_receipt_hash") != previous:
            return False, f"receipt {index} does not link to its predecessor"
        previous = receipt_hash(receipt)
    return True, f"{len(receipts)} receipt(s) verified and correctly chained"


def _severity_counts(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.get("severity", "unknown")
        counts[severity] = counts.get(severity, 0) + 1
    return dict(sorted(counts.items()))
