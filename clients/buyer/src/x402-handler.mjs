// Single seam for wiring an x402 payment handler into the buyer client.
//
// By default this client still does not pay: signing a real x402 payment
// needs a funded testnet wallet, and most runs (CI, a laptop with no wallet)
// should not attempt it. The payer below activates only when
// BUYER_PRIVATE_KEY is set in the environment - it is never read from a
// file, never logged, and never written anywhere. Everything before this
// file (transport, tool calls, verification) stays the same either way; the
// rest of the client only ever calls payX402() and hasPayer().
//
// How it works, matching the same shape `agents/x402`'s own
// `withX402Client` uses server-side-compatible payloads:
//   1. Build an EVM signer from BUYER_PRIVATE_KEY (viem's privateKeyToAccount).
//   2. Feed the `accepts` array from the 402 response into @x402/core's
//      client-side payment payload builder (`x402Client`), with the "exact"
//      EVM scheme registered against the signer (`@x402/evm/exact/client`).
//      This signs the USDC payment authorization per the x402 spec - the
//      buyer never touches the facilitator directly, it only signs.
//   3. JSON-encode the resulting payload, base64-encode it, and hand it back
//      so the caller can retry the tool call with it attached to
//      `_meta["x402/payment"]`. The worker's `withX402` wrapper is what
//      actually submits the signed payload to the facilitator for
//      verification and settlement.

import { x402Client } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const X402_VERSION = 2;

/** True when a BUYER_PRIVATE_KEY is present and a real payer will be used. */
export function hasPayer() {
  return typeof process.env.BUYER_PRIVATE_KEY === "string" && process.env.BUYER_PRIVATE_KEY.trim().length > 0;
}

function loadAccount() {
  const raw = process.env.BUYER_PRIVATE_KEY;
  if (!raw) return null;
  const key = raw.startsWith("0x") ? raw : `0x${raw}`;
  return privateKeyToAccount(/** @type {`0x${string}`} */ (key));
}

// One client per process is fine - it holds no per-payment state, only the
// registered signer and scheme.
let cachedClient = null;

function getPaymentClient() {
  if (cachedClient) return cachedClient;
  const account = loadAccount();
  if (!account) return null;
  const client = new x402Client();
  registerExactEvmScheme(client, { signer: account });
  cachedClient = client;
  return client;
}

/**
 * Sign an x402 payment for one of the offered requirements and return the
 * base64 token ready to attach to a retried tool call's
 * `_meta["x402/payment"]`. Returns null when no payer is configured
 * (BUYER_PRIVATE_KEY unset) - callers should treat that as "cannot pay",
 * not as an error.
 *
 * @param {object[]} requirements - the `accepts` array from an x402
 *   PAYMENT_REQUIRED response (PaymentRequirements[]).
 * @param {object} [challenge] - the full x402/error payload the 402 response
 *   carried, so x402Version/resource/extensions can be echoed back verbatim.
 * @returns {Promise<string|null>} base64-encoded signed payment payload, or
 *   null if no payer is wired.
 */
export async function payX402(requirements, challenge = {}) {
  const paymentClient = getPaymentClient();
  if (!paymentClient) return null;
  if (!Array.isArray(requirements) || requirements.length === 0) {
    throw new Error("payX402: no payment requirements offered");
  }

  const paymentRequiredResponse = {
    x402Version: challenge.x402Version ?? X402_VERSION,
    resource: challenge.resource ?? { url: "", description: "", mimeType: "application/json" },
    accepts: requirements,
    extensions: challenge.extensions,
  };

  const paymentPayload = await paymentClient.createPaymentPayload(paymentRequiredResponse);
  return Buffer.from(JSON.stringify(paymentPayload), "utf8").toString("base64");
}

/** Pretty-print x402 payment requirements for the smoke-test log. */
export function describeRequirements(requirements) {
  if (!Array.isArray(requirements) || requirements.length === 0) return "(no requirements listed)";
  return requirements
    .map((req, i) => {
      const lines = [
        `  [${i}] scheme=${req.scheme} network=${req.network}`,
        `      payTo=${req.payTo} asset=${req.asset}`,
        `      amount=${req.amount ?? req.maxAmountRequired}`,
      ];
      if (req.resource) lines.push(`      resource=${req.resource}`);
      return lines.join("\n");
    })
    .join("\n");
}
