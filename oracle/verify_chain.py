"""Verify `chain.jsonl`: the append-only log of every report ever published.

`receipt.build_report_receipt` and `publish.py` already prove the chain is
correct *as they build it*. This is the independent check a buyer (or CI) runs
afterward: read the file as it sits on disk, verify every signature, verify
every link (`sequence` increments by one, `previous_receipt_hash` points at
the prior entry's hash), and verify the last entry's `findings_hash` actually
matches what `worker/data/paid.json` currently serves - a chain can be
internally perfect and still describe a report the storefront quietly
replaced.

Exits nonzero on the first break, naming the exact line in `chain.jsonl` that
failed and why. Exits 0 and prints the chain length on a clean run.

Kept as its own script rather than folded into the cross-language signature
test: that test's whole point is proving Python and TypeScript agree on one
receipt, and this check is Python-only, walking the full chain on disk. A
standalone script keeps both scripts single-purpose.

Run:
    python verify_chain.py
    python verify_chain.py --chain chain.jsonl --paid ../worker/data/paid.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from receipt import receipt_hash, sha256_canonical, verify_receipt


def load_chain(path: Path) -> list[tuple[int, dict]]:
    """Every non-blank line, paired with its 1-indexed line number."""
    entries: list[tuple[int, dict]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entries.append((line_number, json.loads(raw)))
            except json.JSONDecodeError as exc:
                sys.exit(f"{path}:{line_number}: invalid JSON - {exc}")
    return entries


def verify(chain_path: Path, paid_path: Path | None) -> tuple[bool, str]:
    if not chain_path.exists():
        return False, f"{chain_path}: not found"

    entries = load_chain(chain_path)
    if not entries:
        return False, f"{chain_path}: empty chain"

    previous_hash: str | None = None
    for expected_sequence, (line_number, receipt) in enumerate(entries):
        if not verify_receipt(receipt):
            return False, f"{chain_path}:{line_number}: invalid signature"
        if receipt.get("sequence") != expected_sequence:
            return False, (
                f"{chain_path}:{line_number}: claims sequence "
                f"{receipt.get('sequence')!r}, expected {expected_sequence}"
            )
        if receipt.get("previous_receipt_hash") != previous_hash:
            return False, (
                f"{chain_path}:{line_number}: previous_receipt_hash does not "
                "link to the prior entry"
            )
        previous_hash = receipt_hash(receipt)

    last_line, last_receipt = entries[-1]

    if paid_path is not None and paid_path.exists():
        paid = json.loads(paid_path.read_text(encoding="utf-8"))
        if last_receipt.get("findings_hash") != paid.get("findings_hash"):
            return False, (
                f"{chain_path}:{last_line}: last entry's findings_hash does "
                f"not match {paid_path}'s findings_hash - the chain and the "
                "published report have diverged"
            )
        published_hash = sha256_canonical(paid.get("findings", []))
        if published_hash != last_receipt.get("findings_hash"):
            return False, (
                f"{paid_path}: findings array does not hash to the chain's "
                "last committed findings_hash - the seller is serving "
                "something other than what was signed"
            )

    return True, f"{chain_path}: {len(entries)} receipt(s) verified and correctly chained"


def main() -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain", type=Path, default=here / "chain.jsonl")
    parser.add_argument(
        "--paid", type=Path, default=here.parent / "worker" / "data" / "paid.json",
        help="the currently published paid tier, checked against the chain's "
             "last entry (pass a nonexistent path to skip this check)",
    )
    args = parser.parse_args()

    ok, reason = verify(args.chain, args.paid)
    print(reason if ok else reason, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
