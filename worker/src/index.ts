/**
 * Course Drift Oracle - a remote MCP server with a free tier and a paid tier.
 *
 * This is the experiment the whole exercise exists to run: can you put
 * genuinely useful information behind a paywall that an *agent* - not a human
 * with a credit card - can clear on its own, in one round trip, with no
 * account and no API key?
 *
 * Three tools, and the split between them is the argument:
 *
 *   drift_summary   free.  How bad is it, which lessons, which subjects.
 *                   Enough to decide whether to buy. Costs the caller nothing.
 *   drift_report    paid.  Every finding with file, line, and the fix. This is
 *                   the part that replaces work, which is why it is the part
 *                   that costs money.
 *   verify_report   free.  Checks the Ed25519 signature and the findings hash.
 *                   Free on purpose - a buyer who cannot audit the goods before
 *                   and after paying has no reason to pay a second time.
 *
 * On protocol choice: this serves BOTH payment rails on the same HTTP 402
 * foundation. MPP (Machine Payments Protocol) settles cards via Stripe as well
 * as stablecoins, so buyers are not forced into crypto. x402 exists here for
 * one reason MPP cannot cover: discovery. Coinbase's x402 Bazaar indexes only
 * services that settle through an x402 facilitator, and it is currently the
 * one catalog agents with budgets actually query. The x402 tool is the
 * storefront window; MPP is the wider checkout lane.
 *
 * Deploy: see README.md in this directory.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { withX402, type X402Config } from "agents/x402";
import { Mppx, tempo, Transport } from "mppx/server";
import { z } from "zod";

import bundledFree from "../data/free.json";
import bundledPaid from "../data/paid.json";
import { getReport, json, payoutGuardReason, verifyReceipt } from "./logic";

type PaymentEnv = {
  MPP_SECRET_KEY: string;
  PAYOUT_ADDRESS: string;
  /** CAIP-2 chain id for x402. Default is Base Sepolia (testnet). */
  X402_NETWORK?: string;
  /**
   * x402 facilitator URL. Default is the x402.org testnet facilitator. To be
   * indexed by the x402 Bazaar, settle through Coinbase's CDP facilitator on
   * mainnet instead - that requires a CDP account and swaps this URL.
   */
  X402_FACILITATOR_URL?: string;
  /** Workers KV, written by the nightly publish. See getReport() in logic.ts. */
  REPORTS: KVNamespace;
  /** "1" keeps the paid tool open - for local testing only. */
  DISABLE_PAYMENTS?: string;
};

/**
 * Price per report.
 *
 * Worth being deliberate rather than defaulting to the $0.01 everyone reaches
 * for. A penny a call is the price of a byte, and this is not selling bytes -
 * it is selling the migration triage a maintainer would otherwise do by hand.
 * The floor is set by what the buyer avoids, not by what the response costs to
 * serve. Still cheap enough that an agent spends it without escalating to a
 * human, which is the actual design constraint on agent-facing pricing.
 */
const REPORT_PRICE_USD = "0.25";

/** USDC on Tempo testnet. Swap for your production asset before charging. */
const CURRENCY = "0x20c0000000000000000000000000000000000000";

// ---------------------------------------------------------------------------

export class DriftOracleMCP extends McpAgent<PaymentEnv> {
  server = withX402(
    new McpServer({ name: "course-drift-oracle", version: "1.0.0" }),
    {
      network: this.env.X402_NETWORK ?? "eip155:84532",
      recipient: this.env.PAYOUT_ADDRESS as `0x${string}`,
      facilitator: {
        url: this.env.X402_FACILITATOR_URL ?? "https://x402.org/facilitator",
      },
    } satisfies X402Config,
  );

  async init() {
    // See payoutGuardReason in logic.ts: a paid tool pointed at an unspendable
    // payout must refuse to sell, not collect money into a hole. When the
    // guard trips, both paid tools stay registered (so buyers see a stable
    // tool list) but return this error instead of a payment challenge.
    const payoutGuard = payoutGuardReason(this.env.PAYOUT_ADDRESS, this.env.X402_NETWORK);

    const mppx = Mppx.create({
      methods: [tempo.charge({ testnet: true })],
      secretKey: this.env.MPP_SECRET_KEY,
      transport: Transport.mcpSdk(),
    });

    // --- free: the sales pitch, and an honest one -------------------------
    this.server.tool(
      "drift_summary",
      "Free. How many pinned models and package versions in the " +
        "ai-agents-for-beginners course have drifted from upstream reality, " +
        "broken down by lesson and severity. Returns a signed receipt " +
        "committing to the full findings set. No payment required.",
      {},
      async () =>
        json(await getReport((k) => this.env.REPORTS?.get(k, "json"), "free", bundledFree)),
    );

    // --- free: let the buyer audit before and after paying ----------------
    this.server.tool(
      "verify_report",
      "Free. Verify a report receipt's Ed25519 signature, and optionally " +
        "check that a findings array matches the hash the receipt committed " +
        "to. Use this before paying to confirm the seller is describing real " +
        "work, and after paying to confirm you received all of it.",
      {
        receipt: z.record(z.string(), z.unknown()).describe("the receipt object from any report"),
        findings: z
          .array(z.record(z.string(), z.unknown()))
          .optional()
          .describe("optionally, the findings array to check against findings_hash"),
      },
      async ({ receipt, findings }) =>
        json(await verifyReceipt(receipt as Record<string, unknown>, findings)),
    );

    // --- paid: the work ---------------------------------------------------
    this.server.tool(
      "drift_report",
      `Paid ($${REPORT_PRICE_USD}). Every drift finding with file path, line ` +
        "number, what is wrong, and the suggested fix - enough to open a PR " +
        "without re-deriving anything. Verifiable against the free summary's " +
        "findings_hash.",
      {},
      async (_args, extra) => {
        const report = await getReport(
          (k) => this.env.REPORTS?.get(k, "json"),
          "paid",
          bundledPaid,
        );

        if (this.env.DISABLE_PAYMENTS === "1") {
          return json({ ...report, _note: "payments disabled (local test mode)" });
        }

        if (payoutGuard) {
          return json({ error: "payments unavailable", reason: payoutGuard });
        }

        const payment = await mppx.charge({
          amount: REPORT_PRICE_USD,
          currency: CURRENCY,
          description: "Course drift report - full findings",
          recipient: this.env.PAYOUT_ADDRESS,
        })(extra);

        // The 402 path: hand back a Challenge and let the caller retry with a
        // credential. An agent resolves this itself; no human, no signup.
        if (payment.status === 402) throw payment.challenge;

        return payment.withReceipt(json(report));
      },
    );

    // --- paid: the same work, on the x402 rail ----------------------------
    // Identical goods, second checkout lane. This tool exists because the
    // x402 Bazaar only indexes services that settle through an x402
    // facilitator, and a storefront that cannot be discovered by the agents
    // holding budgets is a demo, not a business. The report embeds its own
    // signed receipt, so the buyer's audit path (verify_report) is identical
    // on both rails.
    const x402Description =
      `Paid ($${REPORT_PRICE_USD}, x402/USDC). Same full drift report as ` +
      "drift_report: every finding with file path, line number, what is " +
      "wrong, and the suggested fix. Pay with x402 if you hold USDC; use " +
      "drift_report to pay by card or other MPP methods.";

    if (payoutGuard) {
      // Registered as an ordinary tool, not a paidTool: withX402 would build
      // challenges against the bad payout address before our handler runs.
      this.server.tool("drift_report_x402", x402Description, {}, async () =>
        json({ error: "payments unavailable", reason: payoutGuard }),
      );
    } else {
      this.server.paidTool(
        "drift_report_x402",
        x402Description,
        Number(REPORT_PRICE_USD),
        {},
        {},
        async () =>
          json(await getReport((k) => this.env.REPORTS?.get(k, "json"), "paid", bundledPaid)),
      );
    }
  }
}

export default DriftOracleMCP.serve("/mcp");
