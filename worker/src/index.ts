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
import { makeFetcher, realFetcher, runAudit, validateTargetUrl } from "./audit";
import {
  type AuditPayload,
  type AuditReceipt,
  type AuditSignature,
  buildAuditReceipt,
  buildModelBadge,
  buildSettlementBadge,
  type CatalogSnapshot,
  buildPot,
  getReport,
  importAuditSigningKey,
  json,
  lookupModel,
  lookupModels,
  payoutGuardReason,
  SETTLEMENT_KV_KEY,
  type SettlementStamp,
  signAuditPayload,
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
  /**
   * Ed25519 seed (base64url, 32 bytes) for signing site audits live at the
   * edge. Deliberately a separate key from the oracle report chain: that key
   * stays CI-only and never touches a live request. Optional on purpose -
   * absent, the audit tools serve honestly unsigned reports that say so.
   */
  AUDIT_SIGNING_KEY?: string;
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

/**
 * Price per site audit. Same reasoning as REPORT_PRICE_USD: the buyer is not
 * paying for the bytes, they are paying for a dated, third-party-signed
 * attestation they can hand to someone else.
 */
const AUDIT_PRICE_USD = "0.25";

/** Audits allowed per target hostname per window. Coarse on purpose. */
const AUDIT_RATE_LIMIT = 6;
const AUDIT_RATE_WINDOW_SECS = 600;

/**
 * Per-target rate limit: nothing may use this worker to
 * generate load against a third party's server, paid or not, so the limit is
 * keyed by the TARGET's hostname, not by the buyer. Fails closed - a broken
 * limiter refuses the audit rather than skipping the limit. KV's eventual
 * consistency makes this a coarse limit, which is all it needs to be: the
 * hard per-audit fetch cap bounds each individual call regardless.
 */
async function auditRateLimitReason(
  env: PaymentEnv,
  origin: string,
  increment: boolean,
): Promise<string | null> {
  const key = `audit-rl:${new URL(origin).hostname}`;
  try {
    const prior = (await env.REPORTS.get(key, "json")) as { count?: number } | null;
    const count =
      prior && typeof prior.count === "number" && Number.isInteger(prior.count) && prior.count > 0
        ? prior.count
        : 0;
    if (count >= AUDIT_RATE_LIMIT) {
      return (
        `rate limited: at most ${AUDIT_RATE_LIMIT} audits of one host per ` +
        `${AUDIT_RATE_WINDOW_SECS / 60} minutes; try again later`
      );
    }
    if (increment) {
      await env.REPORTS.put(key, JSON.stringify({ count: count + 1 }), {
        expirationTtl: AUDIT_RATE_WINDOW_SECS,
      });
    }
    return null;
  } catch {
    return "rate limiter unavailable; refusing the audit rather than skipping the limit";
  }
}

/**
 * One imported key per isolate, re-imported only if the secret rotates.
 * Import failure is remembered as null so a malformed secret degrades to
 * honest unsigned receipts instead of failing every audit.
 */
let auditKeyCache: { seed: string; key: Promise<CryptoKey | null> } | null = null;
function auditSigningKey(seed: string): Promise<CryptoKey | null> {
  if (!auditKeyCache || auditKeyCache.seed !== seed) {
    auditKeyCache = { seed, key: importAuditSigningKey(seed).catch(() => null) };
  }
  return auditKeyCache.key;
}

/**
 * The full audit path shared by all three site_audit tools: rate limit
 * (checked and counted here, against the target), bounded fetches via
 * audit.ts's guarded fetcher, then a live edge signature when the audit key
 * is provisioned. Target validity must be checked by the caller BEFORE any
 * payment is taken; this function re-validates as defense in depth.
 */
async function auditAndSign(
  env: PaymentEnv,
  url: string,
): Promise<Record<string, unknown>> {
  const target = validateTargetUrl(url);
  if (!target.ok) return { error: "invalid target", reason: target.reason };
  const limited = await auditRateLimitReason(env, target.origin, true);
  if (limited) return { error: "audit refused", reason: limited };
  const payload = await runAudit(target.origin, realFetcher);
  return { receipt: await buildAuditReceipt(payload, await signIfProvisioned(env, payload)) };
}

/** Sign an audit payload with the edge key when it is provisioned; an
 * absent, malformed, or failing key serves an honest unsigned receipt,
 * never a 500 and never a fabricated signature. */
async function signIfProvisioned(
  env: PaymentEnv,
  payload: AuditPayload,
): Promise<AuditSignature | null> {
  if (!env.AUDIT_SIGNING_KEY) return null;
  const key = await auditSigningKey(env.AUDIT_SIGNING_KEY);
  if (!key) return null;
  try {
    return await signAuditPayload(payload, key);
  } catch {
    return null;
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

    // --- product 3: the site audit -----------------------------------------
    // The first tools here that fetch a destination the buyer supplies, so
    // everything funnels through audit.ts's guarded fetcher and the
    // per-target rate limit above. Free summary, paid detail, both rails -
    // the same shape the drift report proved out.
    const auditSchema = {
      url: z
        .string()
        .min(1)
        .describe('the site URL to audit, e.g. "https://example.com"'),
    };

    this.server.tool(
      "site_audit_summary",
      "Free. Submit a site URL; the worker runs 12 agent-legibility checks " +
        "against it (robots.txt AI-crawler directives, llms.txt, MCP " +
        "advertisement, structured data, meta/charset/content-type sanity, " +
        "no-JS response) with bounded fetches, private addresses refused, " +
        "and a per-target rate limit. Returns how many of 12 passed, plus " +
        "target and date - enough to decide whether the paid per-check " +
        "detail is worth it.",
      auditSchema,
      async ({ url }) => {
        const result = await auditAndSign(this.env, url);
        const receipt = result.receipt as
          | { payload: { target: string; audited_at: string; summary: { pass: number; total: number } } }
          | undefined;
        if (!receipt) return json(result);
        return json({
          target: receipt.payload.target,
          audited_at: receipt.payload.audited_at,
          checks_passed: receipt.payload.summary.pass,
          checks_total: receipt.payload.summary.total,
          _note:
            "per-check status, detail, and the signed receipt are the paid " +
            `tier: site_audit ($${AUDIT_PRICE_USD}, MPP) or site_audit_x402 ` +
            `($${AUDIT_PRICE_USD}, x402/USDC)`,
        });
      },
    );

    this.server.tool(
      "site_audit",
      `Paid ($${AUDIT_PRICE_USD}). All 12 agent-legibility checks for a ` +
        "submitted site URL, each with status and detail, as a dated " +
        "receipt signed live with a dedicated Ed25519 audit key (or " +
        "explicitly unsigned while that key is unprovisioned - never a " +
        "fabricated signature). Verify with verify_report. The signature " +
        "proves what was checked and when, not that the site is good.",
      auditSchema,
      async ({ url }, extra) => {
        // Validity and rate limit are checked BEFORE charging: a buyer must
        // not pay for "invalid target". auditAndSign re-checks after.
        const target = validateTargetUrl(url);
        if (!target.ok) return json({ error: "invalid target", reason: target.reason });
        const limited = await auditRateLimitReason(this.env, target.origin, false);
        if (limited) return json({ error: "audit refused", reason: limited });

        if (this.env.DISABLE_PAYMENTS === "1") {
          return json({
            ...(await auditAndSign(this.env, url)),
            _note: "payments disabled (local test mode)",
          });
        }

        if (payoutGuard) {
          return json({ error: "payments unavailable", reason: payoutGuard });
        }

        const payment = await mppx.charge({
          amount: AUDIT_PRICE_USD,
          currency: CURRENCY,
          description: "Site audit - 12 agent-legibility checks, signed",
          recipient: this.env.PAYOUT_ADDRESS,
        })(extra);

        if (payment.status === 402) throw payment.challenge;

        await stampSettlement(this.env, "site_audit", "mpp");
        return payment.withReceipt(json(await auditAndSign(this.env, url)));
      },
    );

    const siteAuditX402Description =
      `Paid ($${AUDIT_PRICE_USD}, x402/USDC). Same full site audit as ` +
      "site_audit: all 12 checks with status and detail as a signed dated " +
      "receipt. Pay with x402 if you hold USDC; use site_audit to pay by " +
      "card or other MPP methods. Payment settles before the target is " +
      "checked, so run the free site_audit_summary first to confirm your " +
      "URL is valid and not rate limited.";

    if (payoutGuard) {
      this.server.tool("site_audit_x402", siteAuditX402Description, auditSchema, async () =>
        json({ error: "payments unavailable", reason: payoutGuard }),
      );
    } else {
      this.server.paidTool(
        "site_audit_x402",
        siteAuditX402Description,
        Number(AUDIT_PRICE_USD),
        auditSchema,
        {},
        async ({ url }: { url: string }) => {
          await stampSettlement(this.env, "site_audit_x402", "x402");
          return json(await auditAndSign(this.env, url));
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

// ---------------------------------------------------------------------------
// The worker's own agent-legible face. This service sells a
// legibility audit, so its own origin practices what it audits: a real
// homepage, robots.txt, llms.txt, and a well-known MCP advertisement, each
// served with the content type its role implies. These pages are also what
// the self-audit below examines.
// ---------------------------------------------------------------------------

const HOME_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Course Drift Oracle</title>
<meta name="description" content="MCP server selling signed drift reports, model deprecation facts, and site audits. Free tiers, paid detail, x402 and MPP rails.">
<link rel="mcp-server" href="/mcp">
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"Service","name":"Course Drift Oracle","description":"Signed, verifiable facts for agents: course drift reports, model deprecation status, site legibility audits.","serviceType":"MCP tool server"}
</script>
</head>
<body>
<h1>Course Drift Oracle</h1>
<p>An MCP server at <code>/mcp</code> (streamable HTTP). Ten tools: signed
drift reports for the ai-agents-for-beginners course, model deprecation
facts, and twelve-check site legibility audits. Free summaries and
verification, paid detail on two rails (MPP and x402/USDC, testnet).</p>
<p>Free surfaces: <a href="/badge?models=gpt-4o">/badge</a>,
<a href="/heartbeat">/heartbeat</a>, <a href="/pot">/pot</a>,
<a href="/self-audit">/self-audit</a>, <a href="/llms.txt">/llms.txt</a>.
Storefront and docs:
<a href="https://710git.github.io/course-drift-oracle/">course-drift-oracle</a>.</p>
</body>
</html>
`;

const ROBOTS_TXT = `# Course Drift Oracle - agents and their crawlers are the audience.
User-agent: GPTBot
Disallow:

User-agent: ClaudeBot
Disallow:

User-agent: Google-Extended
Disallow:

User-agent: PerplexityBot
Disallow:

User-agent: CCBot
Disallow:

User-agent: anthropic-ai
Disallow:

User-agent: *
Disallow:
`;

const LLMS_TXT = `# Course Drift Oracle

> MCP server selling signed drift reports, model deprecation facts, and
> twelve-check site legibility audits. Free tiers on every product; paid
> detail settles via MPP or x402/USDC (testnet).

## Free surfaces

- [heartbeat](/heartbeat): shields.io badge JSON, days since the last
  real settlement on this worker.
- [pot](/pot): lifetime settlement tally, one coin per cleared payment.
- [badge](/badge?models=gpt-4o): model deprecation status as a badge.
- [mcp advertisement](/.well-known/mcp.json): where the MCP endpoint
  lives and how to speak to it.

## Endpoint

MCP over streamable HTTP at /mcp. The storefront with the full catalog
lives at https://710git.github.io/course-drift-oracle/.
`;

const MCP_WELL_KNOWN = JSON.stringify({
  name: "course-drift-oracle",
  transport: "streamable-http",
  endpoint: "/mcp",
  description:
    "Signed drift reports, model deprecation facts, and site legibility audits. Free and paid tools; paid detail settles via MPP or x402/USDC (testnet).",
  catalog: "https://710git.github.io/course-drift-oracle/catalog.json",
});

function pageResponse(body: string, contentType: string): Response {
  return new Response(body, {
    headers: {
      "content-type": contentType,
      "cache-control": "public, max-age=3600",
      "access-control-allow-origin": "*",
    },
  });
}

/**
 * Free-route dispatch, shared verbatim between the public fetch handler and
 * the self-audit's in-process fetcher, so the self-audit examines exactly
 * the code paths the public gets. Returns null for anything that is not a
 * free route (the public handler then falls through to MCP). GET and HEAD
 * both match: llms.txt link checks probe with HEAD, and a HEAD that 405s on
 * a path the GET serves would be a real legibility bug.
 */
async function freeRoutes(request: Request, env: PaymentEnv): Promise<Response | null> {
  if (request.method !== "GET" && request.method !== "HEAD") return null;
  const { pathname } = new URL(request.url);
  switch (pathname) {
    case "/":
      return pageResponse(HOME_HTML, "text/html; charset=utf-8");
    case "/robots.txt":
      return pageResponse(ROBOTS_TXT, "text/plain; charset=utf-8");
    case "/llms.txt":
      return pageResponse(LLMS_TXT, "text/plain; charset=utf-8");
    case "/.well-known/mcp.json":
      return pageResponse(MCP_WELL_KNOWN, "application/json");
    case "/badge":
      return handleBadge(request, env);
    case "/heartbeat":
      return handleHeartbeat(env);
    case "/pot":
      return handlePot(env);
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// GET /self-audit: the worker runs its own paid product's
// twelve checks against its own origin and serves the signed receipt.
//
// A Cloudflare Worker cannot fetch its own hostname, so the audit runs
// in-process: runAudit gets a fetcher whose raw layer dispatches
// same-origin requests through freeRoutes above - the same handlers, the
// same bytes, just not the public network path. That distinction is stated
// in the response rather than hidden. Cached in KV for an hour so a popular
// storefront does not re-run ten route evaluations per page view.
// ---------------------------------------------------------------------------

const SELF_AUDIT_KV_KEY = "self-audit-receipt";
const SELF_AUDIT_TTL_SECS = 3600;
const SELF_AUDIT_NOTE =
  "self-audit: this worker ran its own site_audit checks against its own " +
  "origin, in-process through the same handlers that serve these routes " +
  "(a worker cannot fetch its own hostname). Refreshed hourly. Checks 3 " +
  "and 12 report facts, not verdicts, so 10/12 is the maximum score. The " +
  "signature proves what was checked and when, never that the checks are " +
  "exhaustive.";

async function handleSelfAudit(request: Request, env: PaymentEnv): Promise<Response> {
  const respond = (receipt: AuditReceipt) =>
    new Response(JSON.stringify({ ...receipt, _note: SELF_AUDIT_NOTE }), {
      headers: {
        "content-type": "application/json",
        "cache-control": "public, max-age=300",
        "access-control-allow-origin": "*",
      },
    });

  try {
    const cached = (await env.REPORTS?.get(SELF_AUDIT_KV_KEY, "json")) as AuditReceipt | null;
    const auditedAt = cached ? Date.parse(cached.payload?.audited_at ?? "") : Number.NaN;
    if (cached && !Number.isNaN(auditedAt) && Date.now() - auditedAt < SELF_AUDIT_TTL_SECS * 1000) {
      return respond(cached);
    }
  } catch {
    // An unreadable cache just means a fresh run below.
  }

  const origin = new URL(request.url).origin;
  const localFetcher = makeFetcher(async (input, init) => {
    const req = new Request(input, { method: init?.method ?? "GET" });
    return (await freeRoutes(req, env)) ?? new Response("not found", { status: 404 });
  });

  try {
    const payload = await runAudit(origin, localFetcher);
    const receipt = await buildAuditReceipt(payload, await signIfProvisioned(env, payload));
    try {
      await env.REPORTS?.put(SELF_AUDIT_KV_KEY, JSON.stringify(receipt), {
        expirationTtl: SELF_AUDIT_TTL_SECS * 2,
      });
    } catch {
      // Losing the cache costs recomputation, not correctness.
    }
    return respond(receipt);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return new Response(JSON.stringify({ error: "self-audit unavailable", reason: message }), {
      status: 503,
      headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
    });
  }
}

export default {
  async fetch(request: Request, env: PaymentEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if ((request.method === "GET" || request.method === "HEAD") && url.pathname === "/self-audit") {
      return handleSelfAudit(request, env);
    }
    const free = await freeRoutes(request, env);
    if (free) return free;
    return mcpHandler.fetch(request, env, ctx);
  },
};
