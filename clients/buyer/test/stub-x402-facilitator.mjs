#!/usr/bin/env node
// A minimal x402 facilitator stub, reachable on localhost.
//
// The real default (x402.org/facilitator) is not reachable from every
// sandbox this client runs in - some outbound network policies allow only
// an explicit host allowlist, and x402.org is not on it. That is an
// environment limitation, not something to route around by disabling
// checks. This stub exists instead: it is a real, minimal facilitator that
// answers the three routes @x402/core's HTTPFacilitatorClient calls:
//
//   GET  /supported   lets a resource server (the worker's `withX402`, or
//                      this test's own x402ResourceServer) initialize and
//                      hand back genuine payment requirements.
//   POST /verify       checks a signed payment payload against plausibility
//                      rules (right asset, right amount, right recipient, a
//                      signature-shaped string) and reports isValid.
//   POST /settle       same plausibility check, then reports success with a
//                      stub transaction hash.
//
// /verify and /settle do NOT touch a chain - no RPC call, no signature
// cryptographic verification, no real USDC transfer. They exist so the full
// buyer-pays / worker-verifies / worker-settles round trip can be exercised
// end to end in a sandbox that cannot reach a real facilitator or a real
// testnet. A green result here proves the x402 payload the buyer builds and
// signs is well-formed and reaches the same code path the worker uses in
// production (see src/x402-handler.mjs and test/x402-handler.test.mjs) - it
// does not prove a real Base Sepolia transaction cleared. See
// the README ("Wiring a real x402 payer") for how to prove that against the real
// facilitator and chain.
//
// Usage:
//   node test/stub-x402-facilitator.mjs [port]     (default port 4402)
//
// Then point the worker at it for local testing:
//   X402_FACILITATOR_URL = "http://127.0.0.1:4402"
// in the worker's local dev secrets file (see README.md).

import { createServer } from "node:http";
import { randomBytes } from "node:crypto";

// Matches @x402/core's supportedResponseSchema: { kinds, extensions, signers }.
// One kind per (x402Version, network, scheme) the worker asks for - the
// worker's default is X402_NETWORK=eip155:84532 (Base Sepolia) with the
// "exact" scheme registered via registerExactEvmScheme.
const SUPPORTED = {
  kinds: [
    { x402Version: 2, scheme: "exact", network: "eip155:84532" },
    { x402Version: 2, scheme: "exact", network: "eip155:8453" },
  ],
  extensions: [],
  signers: {},
};

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

/**
 * Plausibility-checks a payment payload against the requirements it claims
 * to satisfy. Not a chain check - see file header.
 *
 * @returns {{ok: true, from: string} | {ok: false, reason: string}}
 */
function checkPayload(paymentPayload, paymentRequirements) {
  const auth = paymentPayload?.payload?.authorization;
  const signature = paymentPayload?.payload?.signature;
  if (!auth || typeof auth.from !== "string" || typeof auth.to !== "string") {
    return { ok: false, reason: "missing or malformed authorization" };
  }
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/.test(signature)) {
    return { ok: false, reason: "missing or malformed signature" };
  }
  if (paymentRequirements?.payTo && auth.to.toLowerCase() !== paymentRequirements.payTo.toLowerCase()) {
    return { ok: false, reason: "authorization.to does not match payTo" };
  }
  if (paymentRequirements?.amount && String(auth.value) !== String(paymentRequirements.amount)) {
    return { ok: false, reason: "authorization.value does not match required amount" };
  }
  return { ok: true, from: auth.from };
}

function stubTransactionHash() {
  return `0x${randomBytes(32).toString("hex")}`;
}

/**
 * Build (but do not start) the stub facilitator's http.Server. Exported so
 * tests can run it on an ephemeral port without shelling out to the CLI.
 */
export function createStubFacilitator() {
  return createServer((req, res) => {
    if (req.method === "GET" && req.url === "/supported") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(SUPPORTED));
      return;
    }

    if (req.method === "POST" && req.url === "/verify") {
      readJsonBody(req)
        .then(({ paymentPayload, paymentRequirements }) => {
          const check = checkPayload(paymentPayload, paymentRequirements);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            check.ok
              ? JSON.stringify({ isValid: true, payer: check.from })
              : JSON.stringify({ isValid: false, invalidReason: check.reason }),
          );
        })
        .catch((err) => {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ isValid: false, invalidReason: `bad request: ${err.message}` }));
        });
      return;
    }

    if (req.method === "POST" && req.url === "/settle") {
      readJsonBody(req)
        .then(({ paymentPayload, paymentRequirements }) => {
          const check = checkPayload(paymentPayload, paymentRequirements);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            check.ok
              ? JSON.stringify({
                  success: true,
                  transaction: stubTransactionHash(),
                  network: paymentRequirements?.network ?? "eip155:84532",
                  payer: check.from,
                })
              : JSON.stringify({ success: false, errorReason: check.reason, network: paymentRequirements?.network }),
          );
        })
        .catch((err) => {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, errorReason: `bad request: ${err.message}` }));
        });
      return;
    }

    res.writeHead(501, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: `stub facilitator does not implement ${req.method} ${req.url}` }));
  });
}

// CLI entry point: `node test/stub-x402-facilitator.mjs [port]`.
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.argv[2] ?? 4402);
  const server = createStubFacilitator();
  server.listen(port, "127.0.0.1", () => {
    console.log(`stub x402 facilitator listening on http://127.0.0.1:${port}`);
    console.log(`serves GET /supported, POST /verify, POST /settle - no chain calls, see file header`);
  });
}
