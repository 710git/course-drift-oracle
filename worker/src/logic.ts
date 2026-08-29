/**
 * Pure logic for the Course Drift Oracle worker: no `env`, no `fetch`, no MCP
 * types. Everything here takes data and returns data, which is what makes it
 * unit-testable with plain `node --test` instead of a Worker runtime.
 *
 * `index.ts` imports from this module; it does not duplicate any of it.
 */

// ---------------------------------------------------------------------------
// RFC 8785 (JCS) canonical JSON.
//
// Small enough to inline, and inlining it is the point: the buyer must be able
// to recompute the hash themselves. A verification step that depends on a
// package only the seller ships is not verification.
// ---------------------------------------------------------------------------

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    // JCS specifies ECMAScript number serialization, which is exactly what
    // JSON.stringify already does. Strings get JSON escaping, also per spec.
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  // Object keys sort by UTF-16 code unit, which is Array.prototype.sort's
  // default comparison on strings.
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const entries = keys.map(
    (key) =>
      `${JSON.stringify(key)}:${canonicalize((value as Record<string, unknown>)[key])}`,
  );
  return `{${entries.join(",")}}`;
}

export async function sha256Canonical(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalize(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}

export function b64urlDecode(input: string): Uint8Array {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * Verify a report receipt: Ed25519 signature over the canonical payload, then
 * the findings hash. Mirrors `oracle/receipt.py` exactly - a receipt signed by
 * the Python publisher verifies here, which is the only way the two halves of
 * this system can be said to agree.
 */
export async function verifyReceipt(
  receipt: Record<string, unknown>,
  findings?: unknown,
): Promise<{ signature: boolean; findingsHash: boolean | null; reason: string }> {
  const sig = receipt.signature as
    | { alg?: string; sig?: string; public_key?: string }
    | undefined;

  if (!sig || sig.alg !== "EdDSA" || !sig.sig || !sig.public_key) {
    return { signature: false, findingsHash: null, reason: "missing or non-EdDSA signature" };
  }

  const payload = { ...receipt };
  delete (payload as Record<string, unknown>).signature;

  // The signature is over the SHA-256 of the canonical bytes, not the bytes.
  const messageHash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalize(payload)),
  );

  let signatureOk = false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      b64urlDecode(sig.public_key),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    signatureOk = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      b64urlDecode(sig.sig),
      messageHash,
    );
  } catch (error) {
    return {
      signature: false,
      findingsHash: null,
      reason: `signature check failed: ${(error as Error).message}`,
    };
  }

  let findingsOk: boolean | null = null;
  if (findings !== undefined) {
    findingsOk = (await sha256Canonical(findings)) === receipt.findings_hash;
  }

  return {
    signature: signatureOk,
    findingsHash: findingsOk,
    reason: signatureOk
      ? findingsOk === false
        ? "signature valid but findings do not match the committed hash"
        : "verified"
      : "signature does not verify against the embedded public key",
  };
}

export const json = (value: unknown) => ({
  content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
});

// ---------------------------------------------------------------------------
// Model deprecation feed: a lookup, not a scan.
//
// The catalog snapshot (`catalog.json`, published by oracle/publish.py) holds
// one signed list of model entries, each carrying `id`. `lookupModel` and
// `lookupModels` are the pure functions both new tools share - looking a
// caller-supplied id up against that list, honestly, including the "we do
// not track this one" case, which by design must never be conflated with
// "current".
// ---------------------------------------------------------------------------

export type CatalogEntry = {
  id: string;
  status: string;
  [key: string]: unknown;
};

export type CatalogSnapshot = {
  models: CatalogEntry[];
  receipt: Record<string, unknown>;
  [key: string]: unknown;
};

export type ModelLookupResult =
  | { id: string; known: true; entry: CatalogEntry }
  | { id: string; known: false; reason: "unknown: not in catalog" };

/** A model is a build-time or CI-time risk once it stops being fully current. */
export const ACTION_NEEDED_STATUSES = new Set(["deprecated", "retired"]);

export function lookupModel(catalog: CatalogSnapshot, modelId: string): ModelLookupResult {
  const entry = catalog.models.find((m) => m.id === modelId);
  if (!entry) return { id: modelId, known: false, reason: "unknown: not in catalog" };
  return { id: modelId, known: true, entry };
}

export function lookupModels(
  catalog: CatalogSnapshot,
  modelIds: string[],
): { results: ModelLookupResult[]; anyActionNeeded: boolean } {
  const results = modelIds.map((id) => lookupModel(catalog, id));
  const anyActionNeeded = results.some(
    (r) => r.known && ACTION_NEEDED_STATUSES.has(r.entry.status),
  );
  return { results, anyActionNeeded };
}

/**
 * Read the current report from a KV-shaped getter, falling back to the copy
 * bundled at build time.
 *
 * The fallback is not belt-and-braces, it is what makes the two halves of this
 * system independent. Freshness is the whole asset here, and if publishing a
 * new report required redeploying the Worker, then the nightly analyst would
 * need deploy credentials and the storefront would go through a build every
 * time a retirement date moved. Putting the report in KV means the analyst
 * writes data and the storefront reads data, and neither has to know the other
 * exists.
 *
 * The bundled copy then covers the cold-start case: a freshly deployed Worker
 * serves a real report before the first scheduled run has happened, rather
 * than serving an error or an empty object.
 *
 * Takes a plain getter function rather than a KVNamespace/env so this stays
 * testable with `node --test`: a mock getter that returns null or throws
 * exercises the fallback path with no Worker runtime involved.
 */
export async function getReport<T>(
  kvGet: (key: string) => Promise<unknown | null>,
  key: string,
  bundled: T,
): Promise<T & { _source: string }> {
  try {
    const stored = await kvGet(key);
    if (stored) return { ...(stored as T), _source: "kv" };
  } catch {
    // A KV read failure should degrade to a stale-but-real report rather than
    // take the storefront down. The report carries its own timestamp, so a
    // caller can always tell how old what they got is.
  }
  return { ...bundled, _source: "bundled" };
}

// ---------------------------------------------------------------------------
// Payout sanity guard.
//
// wrangler.jsonc vars are one edit away from production, and a paid tool that
// constructs a payment challenge against an unspendable or throwaway payout
// address does not fail loudly - it collects money into a hole. ERC-20
// transfers to the zero address revert; transfers to an address nobody holds
// keys for succeed and are gone. Docs alone do not stop var flips, so the
// worker refuses to sell instead.
// ---------------------------------------------------------------------------

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

/**
 * The committed testnet placeholder in wrangler.jsonc. Generated with viem,
 * private key discarded on purpose: it can receive testnet challenge flows
 * but nobody can ever spend from it, which is exactly the property that makes
 * it safe to commit and fatal to use on mainnet.
 */
export const TESTNET_PLACEHOLDER_PAYOUT = "0xbBA79C2D92FD6fe815602e29E81Da27aB23E705D";

const MAINNET_NETWORKS = new Set(["eip155:1", "eip155:8453"]);

/**
 * Returns null when it is safe to construct payment challenges, otherwise a
 * human-readable reason for refusing. Pure so it is unit-testable.
 */
export function payoutGuardReason(
  payoutAddress: string | undefined,
  network: string | undefined,
): string | null {
  const address = (payoutAddress ?? "").toLowerCase();
  if (!address || address === ZERO_ADDRESS) {
    return "PAYOUT_ADDRESS is unset or the zero address; refusing to construct payment challenges";
  }
  const net = network ?? "eip155:84532";
  if (MAINNET_NETWORKS.has(net) && address === TESTNET_PLACEHOLDER_PAYOUT.toLowerCase()) {
    return (
      `X402_NETWORK is mainnet (${net}) but PAYOUT_ADDRESS is the committed testnet ` +
      "throwaway whose key was discarded; real funds sent there are unrecoverable. " +
      "Set a payout address you hold keys for before charging on mainnet."
    );
  }
  return null;
}

// ---------------------------------------------------------------------------
// shields.io status badge.
//
// A different shape of "taster" than model_status: no MCP round trip, no
// payment, just GET /badge?models=... returning shields.io's "endpoint"
// JSON schema (https://shields.io/badges/endpoint-badge) so a README can
// embed it directly with img.shields.io/endpoint. Built on the same
// lookupModels used by the paid batch tool - the free badge and the paid
// lookup agree on what "deprecated" and "unknown" mean because they share
// the one function that decides.
// ---------------------------------------------------------------------------

/** shields.io's endpoint schema. `isError` marks a badge that is not a real
 * status - missing/malformed input - so shields can style it distinctly
 * without the caller having to parse the message text. */
export type ShieldsBadge = {
  schemaVersion: 1;
  label: string;
  message: string;
  color: string;
  isError?: true;
};

const BADGE_LABEL = "model drift";

/** Past this, the badge is doing catalog work, not decorating a README. Keeps
 * one caller from turning a free, cacheable badge into an unbounded lookup. */
export const MAX_BADGE_MODELS = 20;

/** Comma-separated model ids, trimmed and with empty entries dropped. A
 * single id with no comma is just the one-element case of this. */
export function parseBadgeModelIds(raw: string | null | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((id) => id.trim())
    .filter((id) => id.length > 0);
}

/**
 * Pure badge builder: catalog snapshot + raw `models` query param in,
 * shields.io badge JSON out. No fetch, no KV, no Response - the route
 * handler in index.ts owns headers and status; this owns the decision.
 *
 * Color/message rules (deprecated beats unknown for color, since a
 * deprecated pin is the caller's problem and an unknown id might just be a
 * typo or a model this catalog does not track yet):
 *   - no models given / too many models  -> "no models given" / "too many
 *     models", color lightgrey, isError - a 400 in badge form, since a
 *     badge endpoint has no good way to also say "HTTP 400" to img tags.
 *   - any model deprecated or retired    -> "<n> deprecated" (+ ", <n>
 *     unknown" if applicable), color red.
 *   - no deprecated but some unknown     -> "<n> unknown", color yellow.
 *   - every model known and current      -> "current", color brightgreen.
 */
// ---------------------------------------------------------------------------
// Settlement heartbeat badge.
//
// The worker is the party that gets paid, so the worker is the honest source
// for "when did a payment last actually clear here". Every paid tool handler
// stamps SETTLEMENT_KV_KEY after its payment settles (an x402 paidTool
// handler only runs post-verification; the MPP path stamps after charge()
// returns non-402), and GET /heartbeat serves the age of that stamp as a
// shields.io badge. The weekly automated heartbeat purchase
// is itself an ordinary sale, so a healthy week never shows
// older than ~7 days - and a badge drifting past that is exactly the "does
// this paywall still settle honestly?" alarm the heartbeat exists to raise.
// ---------------------------------------------------------------------------

export const SETTLEMENT_KV_KEY = "last_settlement";

export type SettlementStamp = {
  /** ISO-8601 UTC time the payment settled (handler-side clock). */
  ts: string;
  /** Which tool was bought, e.g. "drift_report_x402". */
  tool: string;
  /** Which rail carried it. */
  rail: "x402" | "mpp";
};

const HEARTBEAT_LABEL = "last settlement";

/** One missed weekly heartbeat (7 days + a day of slack) turns the badge
 * yellow; two turn it red. Exported so tests and docs share the numbers. */
export const HEARTBEAT_YELLOW_DAYS = 8;
export const HEARTBEAT_RED_DAYS = 15;

/**
 * Pure heartbeat badge builder: last settlement stamp (or null when nothing
 * has ever settled / KV was wiped) + "now" in, shields.io badge JSON out.
 *
 * Color/message rules:
 *   - no stamp                  -> "none recorded", lightgrey. True state,
 *     not an error: a fresh deploy has no settlements yet.
 *   - unparseable/future stamp  -> "unreadable", lightgrey, isError.
 *     (A stamp from the future means a corrupt write, not time travel.)
 *   - settled < 1 day ago       -> "today", brightgreen.
 *   - 1..HEARTBEAT_YELLOW_DAYS  -> "N day(s) ago", brightgreen.
 *   - ..HEARTBEAT_RED_DAYS      -> "N days ago", yellow (missed one beat).
 *   - older                     -> "N days ago", red (the rail is stale).
 */
export function buildSettlementBadge(
  stamp: SettlementStamp | null | undefined,
  now: Date,
): ShieldsBadge {
  if (!stamp || typeof stamp.ts !== "string") {
    return {
      schemaVersion: 1,
      label: HEARTBEAT_LABEL,
      message: "none recorded",
      color: "lightgrey",
    };
  }

  const settled = Date.parse(stamp.ts);
  // 60s of forward tolerance covers ordinary clock skew between the isolate
  // that wrote the stamp and the one serving the badge.
  if (Number.isNaN(settled) || settled > now.getTime() + 60_000) {
    return {
      schemaVersion: 1,
      label: HEARTBEAT_LABEL,
      message: "unreadable",
      color: "lightgrey",
      isError: true,
    };
  }

  const days = Math.floor(Math.max(0, now.getTime() - settled) / 86_400_000);
  if (days < 1) {
    return { schemaVersion: 1, label: HEARTBEAT_LABEL, message: "today", color: "brightgreen" };
  }

  const message = days === 1 ? "1 day ago" : `${days} days ago`;
  const color =
    days <= HEARTBEAT_YELLOW_DAYS ? "brightgreen" : days <= HEARTBEAT_RED_DAYS ? "yellow" : "red";
  return { schemaVersion: 1, label: HEARTBEAT_LABEL, message, color };
}

export function buildModelBadge(
  catalog: CatalogSnapshot,
  rawModels: string | null | undefined,
): ShieldsBadge {
  const modelIds = parseBadgeModelIds(rawModels);

  if (modelIds.length === 0) {
    return {
      schemaVersion: 1,
      label: BADGE_LABEL,
      message: "no models given",
      color: "lightgrey",
      isError: true,
    };
  }
  if (modelIds.length > MAX_BADGE_MODELS) {
    return {
      schemaVersion: 1,
      label: BADGE_LABEL,
      message: "too many models",
      color: "lightgrey",
      isError: true,
    };
  }

  const { results } = lookupModels(catalog, modelIds);
  const deprecatedCount = results.filter(
    (r) => r.known && ACTION_NEEDED_STATUSES.has(r.entry.status),
  ).length;
  const unknownCount = results.filter((r) => !r.known).length;

  if (deprecatedCount === 0 && unknownCount === 0) {
    return { schemaVersion: 1, label: BADGE_LABEL, message: "current", color: "brightgreen" };
  }

  const parts: string[] = [];
  if (deprecatedCount > 0) parts.push(`${deprecatedCount} deprecated`);
  if (unknownCount > 0) parts.push(`${unknownCount} unknown`);

  return {
    schemaVersion: 1,
    label: BADGE_LABEL,
    message: parts.join(", "),
    color: deprecatedCount > 0 ? "red" : "yellow",
  };
}
