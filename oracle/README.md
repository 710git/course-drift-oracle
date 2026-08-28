# oracle/

The part of the Course Drift Oracle that does the work: scans a course
repo, checks what it finds against upstream reality, and signs the result.

```
drift_scan.py       scanner: model pins + live PyPI checks
model_catalog.json  the curated asset: first-party retirement data, by hand
receipt.py          Ed25519 + RFC 8785 canonical JSON signing and verification
publish.py          turns a raw scan into the free and paid tiers the Worker serves
verify_chain.py      independently verifies the whole publication history
chain.jsonl          the live, append-only log of every report published
chain.v1.jsonl        an archived earlier chain; see chain.v1.NOTE.md
```

## What it checks

- **Model pins**, matched against `model_catalog.json`. Each entry names a
  model, its lifecycle state on the platform the course actually targets,
  and its retirement date where one has been announced, with a first-party
  source URL for every claim. This file is the asset a machine cannot
  maintain by itself; keeping it true is the actual job.
- **Package version floors**, matched against the live PyPI JSON API. An
  open floor (`>=` or `>` with no upper bound) whose currently resolving
  version has crossed a major version boundary is flagged as critical:
  a fresh install today gets something the course was never tested
  against.

## How to run it yourself

```bash
pip install jcs pynacl

git clone https://github.com/microsoft/ai-agents-for-beginners ../ai-agents-for-beginners
export DRIFT_TARGET_REPO=$(pwd)/../ai-agents-for-beginners

python drift_scan.py --summary          # add --offline to skip PyPI, or pass --repo-root
python publish.py                       # signs, writes ../worker/data/{free,paid}.json
python verify_chain.py                  # checks the whole chain independently
```

`publish.py` signs with a development key generated locally if you have not
set `ORACLE_SIGNING_KEY`. Regenerating locally produces a report signed by
a different key than the live service; use it to audit the methodology, not
to reproduce the live service's exact signature.

## How to verify the chain yourself

`chain.jsonl` is the append-only record of every report this service has
ever published, each entry naming the sequence number, the previous entry's
hash, and its own Ed25519 signature. Run:

```bash
python verify_chain.py --chain chain.jsonl
```

This checks, independently of the code that wrote the chain, that every
signature is valid and every entry correctly links to the one before it.
It is the same kind of check a buyer or an outside auditor would want to
run against the full record, not just a single receipt.

## A signing-key rotation, before anything shipped

The chain visible here is not the very first one this service ever
produced. An earlier development signing key was generated inside a
temporary environment during the pre-launch build and was lost when that
environment was torn down, before any report had been sold and before any
buyer had ever seen or pinned a public key. Rather than pretend that
history did not happen, it is kept as `chain.v1.jsonl` with an explanation
in `chain.v1.NOTE.md`. The live chain (`chain.jsonl`) started fresh under a
new key, and every report this service has actually sold was signed under
that key. The lesson is public because the discipline it produced - the
signing key never touches a repo, ever, at any stage - is part of what you
are trusting when you rely on a signature from this service.

## What is not here

`findings.json` and `../worker/data/{free,paid}.json` are the manufactured
report output. They are not checked into this repository, here or in the
private working repository this mirror is drawn from: they are regenerated
by `drift_scan.py` and `publish.py` on every run, and the live service
serves the current version from Cloudflare KV. The signing key itself has
never been committed anywhere, in any repository, at any point.
