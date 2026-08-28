// Single seam for wiring an x402 payment handler into the buyer client.
//
// This pass deliberately does not pay: signing a real x402 payment payload
// needs a funded testnet wallet, and wiring one is out of scope. What matters
// architecturally is that the rest of the client never has to change when
// that wallet shows up - it only ever calls payX402(), and everything before
// this file (transport, tool calls, verification) stays the same.
//
// To wire a real payer later:
//   1. npm install @x402/core @x402/evm viem
//   2. Build an EVM signer from a private key (viem's privateKeyToAccount).
//   3. Replace the body of payX402 below with a call into @x402/core's
//      client-side payment payload builder, using `requirements` (the
//      `accepts` array from the 402 response) to pick a network/asset the
//      signer can pay with, then retry the tool call with the resulting
//      payment token attached (see how agents/x402's withX402Client does
//      this: it JSON-encodes the payment payload, base64-encodes it, and
//      sends it back as `_meta["x402/payment"]` on the retried call).

/**
 * @param {object[]} requirements - the `accepts` array from an x402
 *   PAYMENT_REQUIRED response (PaymentRequirements[]).
 * @returns {Promise<null>} always null in this pass - no wallet is wired.
 */
export async function payX402(requirements) {
  void requirements;
  return null;
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
