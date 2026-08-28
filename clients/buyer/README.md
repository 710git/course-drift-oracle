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
   printing the payment requirements it lists. If `BUYER_PRIVATE_KEY` is
   set (see "Wiring a real x402 payer" below), step 5b then signs a real
   USDC payment for one of those requirements, retries the call with it
   attached, and expects the worker to report a settled payment
   (transaction hash, payer address). Without a key set, the run stops at
   the payment-required response.
6. recompute `findings_hash` locally (RFC 8785 canonical JSON + SHA-256,
   reimplemented in `src/canonical.mjs`) over whatever findings the run did
   obtain, and compare against the receipt's committed hash

Step 6 only runs when findings were actually obtained (local test mode, or
a real x402 payment settled in step 5b). Otherwise it reports skipped
rather than faking a result.

## Install

Node 22 or newer.

```bash
cd clients/buyer
npm install
```

## Remote mode

Point the client at the live service:

```bash
node src/index.mjs remote https://signetworks.atelieri.workers.dev/mcp
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

## Wiring a real x402 payer

Generate a throwaway Base Sepolia testnet wallet:

```bash
node scripts/generate-wallet.mjs
```

It prints an address and a private key. The key is a testnet throwaway:
never send it real funds, never commit it, never put it in a file. Fund
the address with Base Sepolia ETH (for gas) and Base Sepolia USDC (to pay
with) from any public faucet, then:

```bash
BUYER_PRIVATE_KEY="<the-key>" node src/index.mjs remote https://signetworks.atelieri.workers.dev/mcp
```

Step 5b then signs and submits a real x402 payment: it builds an EVM
signer from the key with viem's `privateKeyToAccount`, feeds the worker's
payment requirements into `@x402/core`'s client-side payment payload
builder with the "exact" EVM scheme registered against that signer
(`@x402/evm/exact/client`), and retries `drift_report_x402` with the
resulting token attached to `_meta["x402/payment"]`. The worker's x402
wrapper submits the signed payload to the configured facilitator for
verification and settlement; this client only ever signs. The seam is
`src/x402-handler.mjs`'s `payX402(requirements, challenge)` - it returns
the payment token, or `null` when `BUYER_PRIVATE_KEY` is not set, in which
case the unpaid journey runs exactly as before.

## The x402 facilitator

Step 5 calls `drift_report_x402`. The worker's x402 support needs to reach
its configured x402 facilitator just to build the payment requirements it
returns, even for the "no payment yet" response. Some sandboxed or
restricted networks block outbound access to third-party facilitator hosts;
if step 5 fails with a message about no supported payment kinds being
loaded, that is very likely a network restriction in your environment, not
a problem with the service.

`test/stub-x402-facilitator.mjs` is a minimal facilitator that runs on
localhost. It answers `GET /supported` the way `@x402/core` expects, and
also `POST /verify` and `POST /settle` with a plausibility check rather
than a real chain call - enough to exercise the payer path end to end in a
restricted environment without a real facilitator or a real testnet.
`test/x402-handler.test.mjs` (`npm test`) covers `payX402()` against that
stub with a throwaway key generated fresh per run.

## Layout

```
src/
  canonical.mjs     RFC 8785 canonicalization + SHA-256, independent of oracle/
  x402-handler.mjs  the x402 payer: signs a real payment when BUYER_PRIVATE_KEY is set
  index.mjs         the buyer journey (steps 1-6, plus 5b when a payer is wired) and the CLI entry point
scripts/
  generate-wallet.mjs         prints a fresh throwaway Base Sepolia keypair
  check-kv-source.mjs         confirms the deployed worker serves KV-backed data
test/
  stub-x402-facilitator.mjs   minimal localhost facilitator (no chain calls),
                               for exercising steps 5/5b in restricted networks
  x402-handler.test.mjs       node --test coverage of payX402() against the stub
```

## Why this exists

A signed receipt is only worth as much as the verification code you trust.
Rather than ask you to trust this repository's claims about what
`verify_report` checks, this client checks the same things itself, from
scratch, in a separate implementation, and shows you the result. Read
`src/canonical.mjs` and `src/index.mjs` before you run either, if you want
to know exactly what "verified" means here.
