# Course Drift Oracle - buyer client

Run this yourself to audit the Course Drift Oracle before you pay it
anything.

This is an independent buyer for the Course Drift Oracle MCP server. It is
not part of the oracle: it does not import any of the oracle's code, it
re-implements RFC 8785 canonicalization and the SHA-256 hash check itself,
and it treats the server strictly as an untrusted counterparty whose
receipts have to be checked, not taken on faith. If you do not want to
trust this repository's own description of how verification works, this
client is the alternative: read it, and see for yourself what it actually
checks.

It runs the full buyer journey against the server over streamable HTTP MCP,
using the official `@modelcontextprotocol/sdk` client, and prints a
pass/fail/skip line for each step:

1. connect and list tools - expects `drift_summary`, `verify_report`,
   `drift_report`, `drift_report_x402`
2. call `drift_summary` (free) and confirm the receipt it returns carries an
   Ed25519 signature
3. call `verify_report` on that receipt and expect `signature: true`
4. call `drift_report` and confirm the payment path: in local test mode,
   expect the full report; otherwise expect the MPP 402 challenge and print
   its shape
5. call `drift_report_x402` and expect an x402 payment-required response,
   printing the payment requirements it lists (this does not pay - see
   "Wiring a real x402 payer" below)
6. recompute `findings_hash` locally (RFC 8785 canonical JSON + SHA-256,
   reimplemented in `src/canonical.mjs`) over whatever findings the run did
   obtain, and compare against the receipt's committed hash

Step 6 only runs when findings were actually obtained unpaid (local test
mode, or a wired x402 payer). Otherwise it reports skipped rather than
faking a result.

## Install

```bash
cd clients/buyer
npm install
```

## Remote mode

Point the client at the live service:

```bash
node src/index.mjs remote https://signetworks.atlierx.workers.dev/mcp
```

This client never deploys anything and never touches the service's
infrastructure or credentials - it only calls the MCP tools any buyer can
call.

## Local mode

Local mode talks to a `wrangler dev` instance of the worker in `../../worker`,
for anyone who wants to run the server itself locally rather than only
calling the deployed one. See `wrangler.jsonc` and `package.json` in that
directory for how to run it locally (`npm install`, then `npx wrangler dev`).
With payments disabled in local dev, step 4 returns the full report unpaid
and step 6 gets findings to check.

## The x402 facilitator

Step 5 calls `drift_report_x402`. The worker's x402 support needs to reach
its configured x402 facilitator just to build the payment requirements it
returns, even for the "no payment yet" response. Some sandboxed or
restricted networks block outbound access to third-party facilitator hosts;
if step 5 fails with a message about no supported payment kinds being
loaded, that is very likely a network restriction in your environment, not
a problem with the service.

`test/stub-x402-facilitator.mjs` is a minimal facilitator that runs on
localhost and answers the same way a real one would, for testing step 5's
shape without needing outbound access to a real facilitator. It never
verifies or settles a payment - this client never pays, so nothing else is
needed to prove the payment-required path works end to end.

## Wiring a real x402 payer

This client deliberately does not pay. It is a verifier, not a wallet. The
code is structured so a payer can be added in one place:
`src/x402-handler.mjs` exports `payX402(requirements)`, called nowhere yet,
with a comment describing the steps to wire it up. Nothing else in this
client needs to change when that lands.

## Layout

```
src/
  canonical.mjs     RFC 8785 canonicalization + SHA-256, independent of oracle/
  x402-handler.mjs  the one seam where a real x402 payer plugs in later
  index.mjs         the six-step buyer journey and the CLI entry point
test/
  stub-x402-facilitator.mjs   minimal localhost facilitator, for step 5 when
                               outbound access to a real facilitator is blocked
```

## Why this exists

A signed receipt is only worth as much as the verification code you trust.
Rather than ask you to trust this repository's claims about what
`verify_report` checks, this client checks the same things itself, from
scratch, in a separate implementation, and shows you the result. Read
`src/canonical.mjs` and `src/index.mjs` before you run either, if you want
to know exactly what "verified" means here.
