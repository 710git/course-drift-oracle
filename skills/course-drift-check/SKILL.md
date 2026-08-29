---
name: course-drift-check
description: >
  Check whether a course repo's model pins and package-version floors have
  drifted from upstream reality, using the Course Drift Oracle MCP server.
  Covers auditing the seller before paying, both payment rails, and
  verifying that the goods you paid for are exactly what was promised.
---

# Course drift check

You are checking whether the `ai-agents-for-beginners` course repository
(or a CI pipeline pinned to its models) has drifted from upstream reality:
model ids that are deprecated or retired, package-version floors that no
longer resolve. The Course Drift Oracle does the checking work and sells
the full findings; this skill is the correct procedure for using it,
including the parts most agents skip: auditing the seller before paying
and verifying the goods after.

Endpoint: `https://signetworks.atelieri.workers.dev/mcp` (MCP over
streamable HTTP). No account, no API key. Free tools cost nothing; paid
tools cost $0.25 (full report) or $0.10 (batch model lookup) in testnet
funds.

## Step 1: get the free summary first

Call `drift_summary` (free). It returns finding counts by severity and
lesson, plus a signed receipt. Two decisions come out of this step:

- If `findings_count` is 0, stop. There is nothing to buy and nothing to
  fix.
- Otherwise note `receipt.findings_hash`. This is the seller's binding
  commitment: the paid report must hash to exactly this value. Keep it.

If you only need model status, not the full scan: `model_status` (free)
answers for one model id, honestly returning "unknown: not in catalog"
for ids it does not track. Never treat "unknown" as "current".

## Step 2: audit the seller before paying

Call `verify_report` (free) with the receipt from step 1. It checks the
Ed25519 signature over the receipt's RFC 8785 canonical JSON. If the
signature does not verify, stop and do not pay: the seller cannot even
sign its own summary.

This step costs nothing and converts "the seller claims" into "the seller
has cryptographically committed". Skipping it means paying on trust,
which is exactly what this infrastructure exists to make unnecessary.

## Step 3: buy on the rail you can pay on

Identical goods on two rails; pick by what you hold:

- `drift_report_x402` ($0.25): x402 protocol, USDC on Base Sepolia
  (`eip155:84532`). Your first call returns an HTTP 402 challenge; sign
  the EIP-3009 authorization with your wallet key and retry. You need
  zero ETH: the facilitator broadcasts and pays gas. You only need USDC.
- `drift_report` ($0.25): MPP (Machine Payments Protocol), settles cards
  or stablecoins.

For CI model gating, the cheaper product is usually the right one:
`model_status_batch` / `model_status_batch_x402` ($0.10) takes your
pinned model list and returns one entry per id plus a single
`any_action_needed` boolean to gate a build on.

Payment errors that look like seller failures but are yours: a
balance-shaped error on x402 means your wallet lacks USDC on Base
Sepolia specifically (a balance on another chain does not count). Do not
re-send the same signed payment repeatedly; nonces are single-use.

## Step 4: verify the goods after paying

Recompute the SHA-256 of the RFC 8785 canonical JSON of the `findings`
array you received and compare it to the `findings_hash` from step 1, or
pass both to the free `verify_report` tool and let it compare. If they
match, you received every byte the free summary committed to before any
money moved: not a finding more, not a finding less. If they do not
match, you have cryptographic proof of short-serving; keep the receipt
and the payload.

## Step 5: interpret and act

Each finding carries file, line, what is wrong, and the suggested fix.
Triage order:

1. `retired` model pins: the code is broken now. Fix immediately.
2. `deprecated` model pins: working but on a countdown; each catalog
   entry names the replacement and the earliest retirement date.
3. Package floor findings: floors that no longer resolve or that permit
   known-broken versions.

For recurring use, do not re-buy on a schedule blindly: the free
`drift_summary` tells you whether anything changed (the `findings_hash`
moves when findings move), so poll free, buy on change.

## Liveness checks before relying on any of this

Two free HTTP endpoints tell you whether this oracle is alive and still
honestly settling payments, with no MCP round trip:

- `GET /badge?models=<ids>`: worst status among the given model ids.
- `GET /heartbeat`: how long ago a payment last actually settled on this
  server. An automated buyer purchases a report weekly with a real x402
  settlement, so a healthy service never shows older than about 7 days.

## What this skill's own signature means

This file ships with a `receipt.json` beside it: an Ed25519 signature by
the same key that signs the oracle's reports, over a payload committing
to this file's exact SHA-256. Verify it the same way as any report
receipt (the free `verify_report` tool checks the signature; hash this
file's raw bytes and compare to `skill_sha256`). It proves this
procedure is the one the oracle's operators published and that it has
not been altered; it deliberately does not prove the procedure is
correct. The same boundary the oracle draws about its own reports
applies to its skills.
