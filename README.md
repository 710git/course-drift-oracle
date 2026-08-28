# Course Drift Oracle

A signed drift report for Microsoft's [ai-agents-for-beginners](https://github.com/microsoft/ai-agents-for-beginners)
course. It scans the course for two things that go wrong quietly:

- **model pins** that name a deployment which is deprecated or scheduled to
  retire
- **package version floors** whose open `>=` requirement now resolves to a
  newer major version than the course was written against

Both are invisible in a diff. Nothing in a course repo tells you a pinned
model is about to stop serving, or that `pip install` today pulls a package
two majors ahead of what the lessons assume. Answering that question takes
someone actually checking each pin against the platform's own retirement
calendar and the package's real release history. This repo is that checking,
done once and kept current, sold as a report.

## Why trust it

Every report is signed, not just asserted:

- **Ed25519 signatures over RFC 8785 canonical JSON.** The exact bytes that
  were signed can be reconstructed and re-hashed by anyone, in any language.
  A Python-signed receipt verifies against the TypeScript verifier with no
  shared trust between them - see `oracle/receipt.py` (signs) and
  `worker/src/logic.ts` (verifies).
- **Append-only publication chain.** Every report ever published is a link
  in `oracle/chain.jsonl`, each entry pointing at the hash of the one before
  it. Drop an entry, edit one, or reorder two and every later link stops
  matching. `oracle/verify_chain.py` checks this independently of the code
  that writes it.
- **`verify_report` is free.** Call it before paying to confirm the free
  summary's claims are backed by a real signature, and after paying to
  confirm the paid report matches the hash the free summary already
  committed to. A seller who serves fewer findings than promised gets
  caught by arithmetic, not by trust.
- **This repository is the source.** Nothing here is a description of the
  product; it is the product's actual scanner, signing code, and server,
  in the same form that runs the live service.

## Use it in five minutes

The service is an MCP server over streamable HTTP:

```
https://course-drift-oracle.zachary-ferose.workers.dev/mcp
```

Four tools:

| Tool | Price | Returns |
|---|---|---|
| `drift_summary` | free | finding counts by severity and lesson, plus a signed receipt |
| `verify_report` | free | checks a receipt's signature and, optionally, that a findings array matches it |
| `drift_report` | $0.25 | every finding: file, line, diagnosis, fix. Paid via MPP (Tempo testnet) |
| `drift_report_x402` | $0.25 | the same report, paid via x402/USDC |

A typical run:

1. Call `drift_summary`. It costs nothing and returns a signed receipt
   describing how many findings exist, their severity, and which lessons
   are affected. Decide from that whether the full report is worth buying.
2. Call `verify_report` with the receipt from step 1. Confirm the signature
   is valid before you pay anything.
3. Pay $0.25 and call `drift_report` (or `drift_report_x402` if you are
   paying with USDC). You get every finding with a file, a line number,
   what is wrong, and the fix.
4. Call `verify_report` again, this time passing the findings array you
   just received alongside the same receipt. Confirm the hash matches -
   this is what proves you got everything you paid for, not a trimmed
   version of it.

## Verifying a receipt yourself

Every response carries a `receipt` object: a signed statement of what was
found, when, and by which key, chained to every report published before it.
`verify_report` does the check for you over MCP, but nothing about it is a
black box - the two files that do the actual work are short and readable:

- `oracle/receipt.py` builds and signs a receipt: canonicalize the payload
  (RFC 8785), hash it (SHA-256), sign the hash (Ed25519).
- `worker/src/logic.ts` does the same steps in TypeScript to check a
  signature. Read both side by side and there is nothing left to take on
  faith.

`oracle/verify_chain.py` walks the full publication history in
`oracle/chain.jsonl` and confirms every signature is valid and every entry
links correctly to the one before it - the check a buyer or an outside
auditor would run against the whole record, not just one receipt.

## Payments

Two rails carry identical goods:

- **MPP** (Machine Payments Protocol) is designed to settle by card or
  stablecoin; this deployment currently charges on the Tempo testnet.
- **x402** settles in USDC and exists mainly for discovery: agents that
  search for services through the x402 Bazaar only find ones that settle
  through an x402 facilitator.

**Both rails currently run on testnets** - MPP against the Tempo testnet,
x402 against Base Sepolia. Nothing here has taken a real payment yet. That
is stated plainly rather than glossed over: verify the mechanics work
before relying on either rail for anything that matters to you.

## What this repository contains

```
oracle/     the scanner and the signing code
worker/     the MCP server: two free tools, two paid tools, HTTP 402
web/        the storefront pages served alongside the endpoint
clients/    an independent buyer client - run it yourself before you pay
```

`Project-Office`, the private repository this mirror is drawn from, holds
the day-to-day working process, deploy automation, and credentials. None of
that is needed to use or verify this service, so none of it is here.

## Honest limits

- Payments settle on testnets, not mainnet, as of this writing.
- The model and package catalog this scanner checks against is maintained
  by hand and covers a limited set of models today. It grows over time; it
  is not exhaustive now.
- Signature verification proves a report was produced by this service and
  has not been altered. It does not prove the report is correct - that
  claim rests on the sources cited inside each finding, which you are free
  to check yourself.

## License

No license file is included. Absent one, all rights are reserved by
default; this is a decision for the repository owner to make explicitly,
not an oversight.

## Contact

pm.agent.svc@gmail.com
