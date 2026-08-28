#!/usr/bin/env node
// A minimal x402 facilitator stub, reachable on localhost.
//
// The real default (x402.org/facilitator) is not reachable from every
// sandbox this client runs in - some outbound network policies allow only
// an explicit host allowlist, and x402.org is not on it. That is an
// environment limitation, not something to route around by disabling
// checks. This stub exists instead: it is a real, minimal facilitator that
// answers GET /supported the way @x402/core expects, so the worker's
// `withX402` wrapper can initialize and hand back a genuine
// payment-required response with real payment requirements. It never
// verifies or settles a payment - drift_report_x402 is only exercised up to
// "payment required" in this client (see src/x402-handler.mjs), so nothing
// else is needed.
//
// Usage:
//   node test/stub-x402-facilitator.mjs [port]     (default port 4402)
//
// Then point the worker at it for local testing:
//   X402_FACILITATOR_URL = "http://127.0.0.1:4402"
// in worker/.dev.vars (see ../../clients/buyer/README.md).

import { createServer } from "node:http";

const port = Number(process.argv[2] ?? 4402);

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

const server = createServer((req, res) => {
  if (req.method === "GET" && req.url === "/supported") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(SUPPORTED));
    return;
  }
  res.writeHead(501, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: `stub facilitator does not implement ${req.method} ${req.url}` }));
});

server.listen(port, "127.0.0.1", () => {
  console.log(`stub x402 facilitator listening on http://127.0.0.1:${port}`);
  console.log(`serves GET /supported only - enough to get past resourceServer.initialize()`);
});
