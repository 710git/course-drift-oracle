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

Wired as a step in `.github/workflows/oracle.yml` rather than into
`cross-language-verify.mjs`: that script's own required output is the fixed
string `ok: 5/5 checks passed` (`SPRINT.md` operating rule 4 checks for it
literally), and its whole point is proving Python and TypeScript agree - this
check is Python-only, so folding it in would either break that fixed check
count or, if spawned as a subprocess from Node, address a problem that
doesn't exist here (nothing here needs to be verified against a second
language). A standalone script keeps both scripts single-purpose.

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


def verify(chain_path: Path, paid_path: Path | None,
           catalog_path: Path | None = None) -> tuple[bool, str]:
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

    # Since the deprecation feed shipped, each publish appends a PAIR of
    # receipts: the drift report's, then the catalog snapshot's. When a
    # published catalog.json exists, the chain's last entry is therefore the
    # catalog receipt and the report receipt sits one before it. Without a
    # catalog.json (older layouts, partial data dirs) the last entry is the
    # report receipt, as before.
    catalog_receipt: tuple[int, dict] | None = None
    report_receipt = entries[-1]

    if catalog_path is not None and catalog_path.exists():
        if len(entries) < 2:
            return False, (
                f"{chain_path}: a published catalog exists but the chain has "
                "no room for a report+catalog receipt pair"
            )
        catalog_receipt = entries[-1]
        report_receipt = entries[-2]

        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        cat_line, cat_entry = catalog_receipt
        if cat_entry.get("findings_hash") != catalog.get("receipt", {}).get("findings_hash"):
            return False, (
                f"{chain_path}:{cat_line}: last entry's findings_hash does "
                f"not match {catalog_path}'s receipt - the chain and the "
                "published catalog have diverged"
            )
        if sha256_canonical(catalog.get("models", [])) != cat_entry.get("findings_hash"):
            return False, (
                f"{catalog_path}: models array does not hash to the chain's "
                "committed catalog findings_hash - the seller is serving a "
                "catalog other than what was signed"
            )

    last_line, last_receipt = report_receipt

    if paid_path is not None and paid_path.exists():
        paid = json.loads(paid_path.read_text(encoding="utf-8"))
        if last_receipt.get("findings_hash") != paid.get("findings_hash"):
            return False, (
                f"{chain_path}:{last_line}: report receipt's findings_hash "
                f"does not match {paid_path}'s findings_hash - the chain and "
                "the published report have diverged"
            )
        published_hash = sha256_canonical(paid.get("findings", []))
        if published_hash != last_receipt.get("findings_hash"):
            return False, (
                f"{paid_path}: findings array does not hash to the chain's "
                "committed findings_hash - the seller is serving "
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
    parser.add_argument(
        "--catalog", type=Path,
        default=here.parent / "worker" / "data" / "catalog.json",
        help="the currently published catalog snapshot; when present the "
             "chain's last entry must be its receipt (pass a nonexistent "
             "path to skip)",
    )
    args = parser.parse_args()

    ok, reason = verify(args.chain, args.paid, args.catalog)
    print(reason if ok else reason, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
