"""Sign a published skill file with the oracle's Ed25519 identity.

The skill-market experiment (one free, signed, hash-verifiable SKILL.md;
give it away, watch for pull) needs exactly one new capability: a receipt
that commits to a file's raw bytes rather than to a findings array. The
signature machinery is receipt.py's, unchanged - the same key that signs
drift reports signs skills, so a stranger who has verified one report
receipt already trusts (or distrusts) this key for skills too.

Idempotent on purpose: re-running against an unchanged skill file leaves
an existing valid receipt untouched, so a weekly deploy does not churn a
new signature (and a new timestamp) over identical bytes. The receipt
only changes when the skill changes.

Verification path for a stranger, no code from us required:
  1. sha256 the SKILL.md bytes; compare to receipt payload's skill_sha256.
  2. Verify the Ed25519 signature over the payload's RFC 8785 canonical
     JSON (the free verify_report MCP tool does this, or receipt.py's
     verify_receipt, or the worker's TypeScript verifyReceipt).

Like every receipt here: proves attribution and integrity, not
correctness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from publish import load_or_create_key
from receipt import sign_receipt, utc_now, verify_receipt

SKILL_RECEIPT_TYPE = "course.skill.v1"


def sha256_file(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def build_skill_payload(skill_path: Path, repo_root: Path) -> dict:
    return {
        "type": SKILL_RECEIPT_TYPE,
        "publisher": "course-drift-oracle",
        "skill": skill_path.relative_to(repo_root).as_posix(),
        "skill_sha256": sha256_file(skill_path),
        "skill_bytes": skill_path.stat().st_size,
        "timestamp": utc_now(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill", required=True, help="path to the SKILL.md to sign")
    parser.add_argument(
        "--repo-root",
        default=".",
        help="repo root the receipt's skill path is expressed relative to",
    )
    parser.add_argument(
        "--key-file",
        default=str(Path(__file__).parent / ".signing-key"),
        help="dev-key fallback path (production uses the ORACLE_SIGNING_KEY env var)",
    )
    args = parser.parse_args()

    skill_path = Path(args.skill).resolve()
    repo_root = Path(args.repo_root).resolve()
    receipt_path = skill_path.parent / "receipt.json"

    payload = build_skill_payload(skill_path, repo_root)

    if receipt_path.exists():
        existing = json.loads(receipt_path.read_text())
        if (
            existing.get("skill_sha256") == payload["skill_sha256"]
            and verify_receipt(existing)
        ):
            print(f"receipt current: {receipt_path} already signs {payload['skill_sha256']}")
            return 0

    key = load_or_create_key(Path(args.key_file))
    receipt = sign_receipt(payload, key)

    if not verify_receipt(receipt):
        print("self-check failed: freshly signed receipt does not verify", file=sys.stderr)
        return 1

    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(f"signed {payload['skill']} ({payload['skill_sha256']}) -> {receipt_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
