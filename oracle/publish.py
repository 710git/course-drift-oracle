"""Turn a raw scan into the artifacts the Worker serves.

The split between free.json and paid.json IS the business model, so it is
worth being explicit about where the line falls and why.

  free.json  - counts, severity histogram, affected lesson names, the findings
               hash, and the signature. Enough for an agent to decide whether
               it cares. Costs nothing, and it is the thing that makes the paid
               tier legible: you can verify the seller is describing something
               real before you pay.

  paid.json  - the findings themselves: file, line, what is wrong, what to
               change it to. This is the part that saves the buyer the work.

Both commit to the same `findings_hash`. That is the honesty mechanism: after
paying, the buyer recomputes the hash over what they received and checks it
against the signed receipt they read for free. A seller who quietly serves a
thinner report than advertised gets caught by arithmetic rather than by trust.

  catalog.json - a signed snapshot of `model_catalog.json` itself, for the
               deprecation feed (`model_status` / `model_status_batch` in the
               Worker). Same signing
               machinery, same chain, a different payload: the catalog's own
               curated entries instead of a scan's findings. Published every
               run regardless of whether the catalog changed, since it is
               cheap and keeps the freshness claim mechanically true.

Run:
    python publish.py --findings findings.json --out-dir ../worker/data
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from nacl import signing

from receipt import (
    b64url_nopad,
    build_report_receipt,
    receipt_hash,
    sha256_canonical,
    verify_chain,
    verify_receipt,
)

KEY_ENV = "ORACLE_SIGNING_KEY"


def load_or_create_key(key_path: Path) -> signing.SigningKey:
    """Resolve the signing key: env var first, then a local dev key file.

    The env var is the path that matters in production - a scheduled cloud run
    injects the secret and never writes it down. The file fallback exists so
    that cloning this repo and running it once actually works; it generates a
    throwaway identity rather than failing with a setup error.
    """
    from_env = os.environ.get(KEY_ENV)
    if from_env:
        from receipt import b64url_decode
        return signing.SigningKey(b64url_decode(from_env))

    if key_path.exists():
        from receipt import b64url_decode
        return signing.SigningKey(b64url_decode(key_path.read_text().strip()))

    key = signing.SigningKey.generate()
    key_path.write_text(b64url_nopad(bytes(key)) + "\n", encoding="utf-8")
    key_path.chmod(0o600)
    print(
        f"note: generated a development signing key at {key_path}.\n"
        f"      For anything real, set {KEY_ENV} instead and keep this file out "
        f"of git.",
        file=sys.stderr,
    )
    return key


def lesson_of(path: str) -> str:
    """Map a repo-relative path to the lesson directory that owns it."""
    head = path.split("/", 1)[0]
    return head if head and head[0].isdigit() else "(course root)"


def build_free_tier(findings: list[dict], meta: dict, receipt: dict) -> dict:
    """The public summary. Says how bad it is, never says where."""
    by_lesson: dict[str, dict[str, int]] = {}
    for finding in findings:
        bucket = by_lesson.setdefault(lesson_of(finding["file"]), {})
        bucket[finding["severity"]] = bucket.get(finding["severity"], 0) + 1

    # Name the subjects but not their locations. An agent needs the subject to
    # decide relevance ("do I care about openai?"); the locations are the work.
    subjects = sorted({f["subject"] for f in findings if f["severity"] == "critical"})

    return {
        "report": "course-drift-oracle/free",
        "repo": meta.get("repo"),
        "commit": meta.get("commit"),
        "generated": receipt["timestamp"],
        "catalog_version": meta.get("catalog_version"),
        "findings_count": receipt["findings_count"],
        "severity_counts": receipt["severity_counts"],
        "critical_subjects": subjects,
        "affected_lessons": dict(sorted(by_lesson.items())),
        "findings_hash": receipt["findings_hash"],
        "receipt": receipt,
        "paid_tier": {
            "returns": "every finding with file, line, diagnosis, and suggested fix",
            "verify": (
                "recompute the RFC 8785 canonical SHA-256 over the returned "
                "findings array and compare it to findings_hash above"
            ),
        },
    }


def build_paid_tier(findings: list[dict], meta: dict, receipt: dict) -> dict:
    return {
        "report": "course-drift-oracle/full",
        "repo": meta.get("repo"),
        "commit": meta.get("commit"),
        "generated": receipt["timestamp"],
        "findings_hash": receipt["findings_hash"],
        "receipt": receipt,
        "findings": findings,
    }


def catalog_entries(catalog: dict) -> list[dict]:
    """Flatten the catalog's {model_id: entry} map into a list sorted by id.

    `build_report_receipt` hashes and signs a list (it was built for
    `findings`), so the catalog snapshot needs the same shape. Sorting by id
    makes the hash reproducible regardless of the source file's key order.
    """
    models = catalog.get("models", {})
    return [{"id": model_id, **entry} for model_id, entry in sorted(models.items())]


def build_catalog_tier(entries: list[dict], catalog: dict, meta: dict, receipt: dict) -> dict:
    """Signed snapshot of the full model catalog.

    Same `build_report_receipt` call as the drift-report tiers, over a
    different payload: the catalog's model entries instead of scan findings.
    `receipt.py` is unchanged, so the receipt's own field names are still
    `findings_hash` / `findings_count` even though what they commit to here is
    the catalog, not a scan - see the module docstring above.
    """
    return {
        "report": "course-drift-oracle/catalog",
        "repo": meta.get("repo"),
        "commit": meta.get("commit"),
        "generated": receipt["timestamp"],
        "catalog_version": catalog.get("version"),
        "models_count": receipt["findings_count"],
        "receipt": receipt,
        "models": entries,
    }


def main() -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, default=here / "findings.json")
    parser.add_argument("--catalog", type=Path, default=here / "model_catalog.json")
    parser.add_argument("--out-dir", type=Path, default=here.parent / "worker" / "data")
    parser.add_argument("--chain", type=Path, default=here / "chain.jsonl",
                        help="append-only log of every report ever published")
    parser.add_argument("--key-file", type=Path, default=here / ".signing-key")
    args = parser.parse_args()

    scan = json.loads(args.findings.read_text(encoding="utf-8"))
    findings, meta = scan["findings"], scan["meta"]
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))

    key = load_or_create_key(args.key_file)

    # Continue the existing chain rather than starting a new one, so the full
    # publication history stays verifiable as a single sequence.
    history: list[dict] = []
    if args.chain.exists():
        history = [
            json.loads(line)
            for line in args.chain.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    receipt = build_report_receipt(
        findings=findings,
        scan_meta=meta,
        sequence=len(history),
        previous_receipt_hash=receipt_hash(history[-1]) if history else None,
        signing_key=key,
    )

    # Catalog snapshot: same chain, next sequence number, linked to the report
    # receipt just built above. One shared publication history for both
    # products signed by the same key (see the design memo, §3.2).
    entries = catalog_entries(catalog)
    catalog_receipt = build_report_receipt(
        findings=entries,
        scan_meta={
            "repo": meta.get("repo"),
            "commit": meta.get("commit"),
            "scanned_files": len(entries),
        },
        sequence=len(history) + 1,
        previous_receipt_hash=receipt_hash(receipt),
        signing_key=key,
    )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    free = build_free_tier(findings, meta, receipt)
    paid = build_paid_tier(findings, meta, receipt)
    catalog_snapshot = build_catalog_tier(entries, catalog, meta, catalog_receipt)
    (args.out_dir / "free.json").write_text(
        json.dumps(free, indent=2) + "\n", encoding="utf-8")
    (args.out_dir / "paid.json").write_text(
        json.dumps(paid, indent=2) + "\n", encoding="utf-8")
    (args.out_dir / "catalog.json").write_text(
        json.dumps(catalog_snapshot, indent=2) + "\n", encoding="utf-8")

    with args.chain.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(receipt) + "\n")
        handle.write(json.dumps(catalog_receipt) + "\n")

    # Prove the invariants here rather than asserting them in a README.
    history.append(receipt)
    history.append(catalog_receipt)
    chain_ok, chain_reason = verify_chain(history)
    hash_ok = sha256_canonical(paid["findings"]) == receipt["findings_hash"]
    catalog_hash_ok = sha256_canonical(catalog_snapshot["models"]) == catalog_receipt["findings_hash"]

    print(f"signed report  sequence={receipt['sequence']} "
          f"findings={receipt['findings_count']}")
    print(f"  public key   {receipt['signature']['public_key']}")
    print(f"  signature    {'valid' if verify_receipt(receipt) else 'INVALID'}")
    print(f"signed catalog sequence={catalog_receipt['sequence']} "
          f"models={catalog_receipt['findings_count']}")
    print(f"  signature    {'valid' if verify_receipt(catalog_receipt) else 'INVALID'}")
    print(f"  chain        {chain_reason}")
    print(f"  paid tier    {'matches' if hash_ok else 'DOES NOT MATCH'} findings_hash")
    print(f"  catalog      {'matches' if catalog_hash_ok else 'DOES NOT MATCH'} findings_hash")
    print(f"  wrote        {args.out_dir}/free.json, {args.out_dir}/paid.json, "
          f"{args.out_dir}/catalog.json")

    return 0 if (chain_ok and hash_ok and catalog_hash_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
