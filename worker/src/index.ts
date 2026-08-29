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
 * Plus a second, smaller product on the same infrastructure - the model
 * deprecation feed. Same catalog, same
 * signing, a different question ("is this model id alive") instead of a scan:
 *
 *   model_status         free.  One model id in, its catalog entry (or an
 *                        honest "unknown: not in catalog") out, plus the
 *                        signed catalog receipt. The taster, same role
 *                        drift_summary plays for the drift report.
 *   model_status_batch   paid.  A list of model ids in, one entry per id plus
 *                        an any_action_needed boolean out. The buyer's actual
 *                        use case: gate a build on a caller's pinned models
 *                        without parsing an array by hand.
 *
 * And a plain HTTP route alongside the MCP tools - GET /badge - so a README
 * can wear the deprecation feed as a shields.io badge instead of calling a
 * tool. Free, unauthenticated, cached at the edge; see the route handler
 * below and buildModelBadge in logic.ts for the badge's own reasoning.
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

import bundledCatalog from "../data/catalog.json";
import bundledFree from "../data/free.json";
import bundledPaid from "../data/paid.json";
import {
  buildModelBadge,
  buildSettlementBadge,
  type CatalogSnapshot,
  buildPot,
  getReport,
  json,
  lookupModel,
  lookupModels,
  payoutGuardReason,
  SETTLEMENT_KV_KEY,
  type SettlementStamp,
  verifyReceipt,
} from "./logic";

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

/**
 * Price per batch model-status query.
 *
 * Deliberately below REPORT_PRICE_USD: this sells one fact per id (comparable
 * to reading a row on the provider's own deprecation page), not migration
 * triage. The paid case is real anyway - a CI pipeline gets one signed answer
 * across all its pinned models instead of several free single-id lookups,
 * plus the any_action_needed boolean it actually wants to gate a build on.
 * That trade-off is deliberate, not an accident of pricing.
 */
const MODEL_STATUS_BATCH_PRICE_USD = "0.10";

/** USDC on Tempo testnet. Swap for your production asset before charging. */
const CURRENCY = "0x20c0000000000000000000000000000000000000";

// ---------------------------------------------------------------------------

/**
 * Record that a payment just cleared, for GET /heartbeat. Written from every
 * paid handler's success path: an x402 paidTool handler only runs after the
 * facilitator verifies the buyer's signed payment (settlement completes in
 * the same request; a settle failure fails the buyer's own run), and the MPP
 * path stamps only after charge() returns non-402. Best-effort on purpose -
 * bookkeeping must never break a sale, so a KV write failure is swallowed
 * and the badge simply stays at its previous age.
 */
async function stampSettlement(
  env: PaymentEnv,
  tool: string,
  rail: SettlementStamp["rail"],
): Promise<void> {
  try {
    // Carry the running count forward (GET /pot renders one coin per
    // settlement). A prior stamp without a count still proves one
    // settlement; a torn read just restarts the count, never the badge.
    let prior = 0;
    try {
      const prev = (await env.REPORTS?.get(SETTLEMENT_KV_KEY, "json")) as SettlementStamp | null;
      if (prev && typeof prev.ts === "string") {
        prior =
          typeof prev.count === "number" && Number.isInteger(prev.count) && prev.count > 0
            ? prev.count
            : 1;
      }
    } catch {
      // Unreadable prior stamp: count restarts at this settlement.
    }
    const stamp: SettlementStamp = {
      ts: new Date().toISOString(),
      tool,
      rail,
      count: prior + 1,
    };
    await env.REPORTS?.put(SETTLEMENT_KV_KEY, JSON.stringify(stamp));
  } catch {
    // Losing one stamp costs badge freshness, not money or goods.
  }
}

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

        await stampSettlement(this.env, "drift_report", "mpp");
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
        async () => {
          await stampSettlement(this.env, "drift_report_x402", "x402");
          return json(await getReport((k) => this.env.REPORTS?.get(k, "json"), "paid", bundledPaid));
        },
      );
    }

    // --- free: the deprecation feed's taster -------------------------------
    this.server.tool(
      "model_status",
      "Free. Look up one model id in the signed catalog: current, " +
        "deprecated, or retired, plus replacement, earliest_retirement, " +
        "source, and retrieved. Returns an honest \"unknown: not in catalog\" " +
        "for an id this catalog does not track - never conflated with " +
        "\"current\". Includes the catalog snapshot's signed receipt.",
      {
        model_id: z.string().min(1).describe("the model id to look up, e.g. \"gpt-4o\""),
      },
      async ({ model_id }) => {
        const catalog = await getReport(
          (k) => this.env.REPORTS?.get(k, "json"),
          "catalog",
          bundledCatalog,
        );
        return json({
          ...lookupModel(catalog as unknown as CatalogSnapshot, model_id),
          receipt: catalog.receipt,
          _source: catalog._source,
        });
      },
    );

    // --- paid: the deprecation feed's actual product -----------------------
    const modelStatusBatchDescription =
      `Paid ($${MODEL_STATUS_BATCH_PRICE_USD}). Look up a list of model ids ` +
      "in the signed catalog and return one entry per id (or an honest " +
      "\"unknown: not in catalog\" per id), plus any_action_needed: true if " +
      "any input model is deprecated or retired. Built for a CI pipeline's " +
      "pinned-model set - one signed answer and one boolean to gate a build " +
      "on, instead of parsing an array of free lookups by hand.";
    const modelStatusBatchSchema = {
      model_ids: z
        .array(z.string().min(1))
        .min(1)
        .describe("the model ids to look up, e.g. a CI pipeline's pinned model set"),
    };

    this.server.tool(
      "model_status_batch",
      modelStatusBatchDescription,
      modelStatusBatchSchema,
      async ({ model_ids }, extra) => {
        const catalog = await getReport(
          (k) => this.env.REPORTS?.get(k, "json"),
          "catalog",
          bundledCatalog,
        );
        const build = () => {
          const { results, anyActionNeeded } = lookupModels(
            catalog as unknown as CatalogSnapshot,
            model_ids,
          );
          return {
            results,
            any_action_needed: anyActionNeeded,
            receipt: catalog.receipt,
            _source: catalog._source,
          };
        };

        if (this.env.DISABLE_PAYMENTS === "1") {
          return json({ ...build(), _note: "payments disabled (local test mode)" });
        }

        if (payoutGuard) {
          return json({ error: "payments unavailable", reason: payoutGuard });
        }

        const payment = await mppx.charge({
          amount: MODEL_STATUS_BATCH_PRICE_USD,
          currency: CURRENCY,
          description: "Model status batch - pinned model deprecation check",
          recipient: this.env.PAYOUT_ADDRESS,
        })(extra);

        if (payment.status === 402) throw payment.challenge;

        await stampSettlement(this.env, "model_status_batch", "mpp");
        return payment.withReceipt(json(build()));
      },
    );

    // --- paid: the same lookup, on the x402 rail ----------------------------
    const modelStatusBatchX402Description =
      `Paid ($${MODEL_STATUS_BATCH_PRICE_USD}, x402/USDC). Same batch model ` +
      "status lookup as model_status_batch: one entry per input id plus " +
      "any_action_needed. Pay with x402 if you hold USDC; use " +
      "model_status_batch to pay by card or other MPP methods.";

    if (payoutGuard) {
      this.server.tool(
        "model_status_batch_x402",
        modelStatusBatchX402Description,
        modelStatusBatchSchema,
        async () => json({ error: "payments unavailable", reason: payoutGuard }),
      );
    } else {
      this.server.paidTool(
        "model_status_batch_x402",
        modelStatusBatchX402Description,
        Number(MODEL_STATUS_BATCH_PRICE_USD),
        modelStatusBatchSchema,
        {},
        async ({ model_ids }: { model_ids: string[] }) => {
          await stampSettlement(this.env, "model_status_batch_x402", "x402");
          const catalog = await getReport(
            (k) => this.env.REPORTS?.get(k, "json"),
            "catalog",
            bundledCatalog,
          );
          const { results, anyActionNeeded } = lookupModels(
            catalog as unknown as CatalogSnapshot,
            model_ids,
          );
          return json({
            results,
            any_action_needed: anyActionNeeded,
            receipt: catalog.receipt,
            _source: catalog._source,
          });
        },
      );
    }
  }
}

const mcpHandler = DriftOracleMCP.serve("/mcp");

/**
 * GET /badge?models=<comma-separated ids>
 *
 * shields.io "endpoint" badge (https://shields.io/badges/endpoint-badge) over
 * the same catalog model_status/model_status_batch read. Free and
 * unauthenticated on purpose - a badge lives in a README that anonymous CI
 * fetches on every render, and a paid or gated badge just breaks the README.
 *
 * Signing: unlike the MCP report/catalog receipts (signed by the offline
 * publisher and merely *verified* here in verifyReceipt), no Ed25519 private
 * key is available in this worker's runtime - PaymentEnv carries only
 * MPP_SECRET_KEY (a payment credential, not a signing key), REPORTS (KV), and
 * the payout vars. Signing the badge body would mean inventing a second key
 * path outside the one the receipts already use, so the badge ships
 * unsigned; its Cache-Control and the catalog's own signed receipt (available
 * via model_status) are the integrity story instead.
 */
async function handleBadge(request: Request, env: PaymentEnv): Promise<Response> {
  const url = new URL(request.url);
  const catalog = await getReport(
    (k) => env.REPORTS?.get(k, "json"),
    "catalog",
    bundledCatalog,
  );
  const badge = buildModelBadge(catalog as unknown as CatalogSnapshot, url.searchParams.get("models"));

  return new Response(JSON.stringify(badge), {
    headers: {
      "content-type": "application/json",
      // shields.io polls this on a schedule of its own; 5 minutes is short
      // enough that a fresh deprecation shows up same-day, long enough that
      // a popular README does not hammer KV on every page load.
      "cache-control": "public, max-age=300",
      // No credentials, nothing to protect - open to any origin, same as any
      // other public badge endpoint (shields.io's own included).
      "access-control-allow-origin": "*",
    },
  });
}

/**
 * GET /heartbeat
 *
 * shields.io "endpoint" badge answering one question: when did a payment last
 * actually clear on this worker? Reads the SETTLEMENT_KV_KEY stamp written by
 * the paid handlers (see stampSettlement above) - the seller's own record,
 * refreshed by every real sale including the weekly automated heartbeat
 * purchase, which is itself an ordinary sale. Free, unauthenticated, cached
 * and CORS-open for the same reasons as /badge, and unsigned for the same
 * reason too: the on-chain settlement transactions are the independently
 * checkable record; this badge is the at-a-glance view.
 */
async function handleHeartbeat(env: PaymentEnv): Promise<Response> {
  let stamp: SettlementStamp | null = null;
  try {
    stamp = (await env.REPORTS?.get(SETTLEMENT_KV_KEY, "json")) as SettlementStamp | null;
  } catch {
    // A KV read failure serves "none recorded" rather than a 500 - the badge
    // must render in a README even when the backing store hiccups.
  }
  const badge = buildSettlementBadge(stamp, new Date());

  return new Response(JSON.stringify(badge), {
    headers: {
      "content-type": "application/json",
      "cache-control": "public, max-age=300",
      "access-control-allow-origin": "*",
    },
  });
}

/**
 * GET /pot
 *
 * The pot of gold: one coin per settlement that has ever cleared on this
 * worker, served as plain JSON for the storefront's pot rendering (and
 * anyone else who wants a lifetime count). Same trust posture as
 * /heartbeat: free, unauthenticated, cached, CORS-open, unsigned - the
 * on-chain transactions are the checkable record, this is the tally.
 */
async function handlePot(env: PaymentEnv): Promise<Response> {
  let stamp: SettlementStamp | null = null;
  try {
    stamp = (await env.REPORTS?.get(SETTLEMENT_KV_KEY, "json")) as SettlementStamp | null;
  } catch {
    // Serve the pre-stamp floor rather than a 500 on a KV hiccup.
  }
  return new Response(JSON.stringify(buildPot(stamp)), {
    headers: {
      "content-type": "application/json",
      "cache-control": "public, max-age=300",
      "access-control-allow-origin": "*",
    },
  });
}

export default {
  async fetch(request: Request, env: PaymentEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/badge") {
      return handleBadge(request, env);
    }
    if (request.method === "GET" && url.pathname === "/heartbeat") {
      return handleHeartbeat(env);
    }
    if (request.method === "GET" && url.pathname === "/pot") {
      return handlePot(env);
    }
    return mcpHandler.fetch(request, env, ctx);
  },
};
