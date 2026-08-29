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
  if (receipt.type === AUDIT_RECEIPT_TYPE) {
    return verifyAuditReceiptShape(receipt as unknown as AuditReceipt);
  }

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
// Base64url encoding (the write-side complement to `b64urlDecode` above).
// ---------------------------------------------------------------------------

export function b64urlEncode(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const b of arr) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// Agent Readiness Auditor (Product 3) receipts.
//
// `AuditPayload`/`AuditCheck` are the shared audit contract: the checks
// module (audit.ts) produces one of these; this module only signs and verifies
// it, reusing `canonicalize`/`sha256Canonical`/`b64urlDecode` above rather
// than duplicating them. This is the canonical home for these two types:
// anything else that needs them should import from here, not redeclare them.
//
// Signing uses a NEW, separate Ed25519 key from the oracle's report-signing
// key (env AUDIT_SIGNING_KEY, worker-side only - never the CI-only oracle
// chain key). When that key is not provisioned, the audit still runs and
// the receipt says so honestly instead of faking a signature.
// ---------------------------------------------------------------------------

export type AuditCheckStatus = "pass" | "warn" | "info" | "fail" | "error";

export type AuditCheck = {
  id: string; // fixed ids listed in the ticket, fixed order
  title: string; // short human title
  status: AuditCheckStatus;
  detail: string; // derived facts only, hard cap 300 chars, never raw body
};

export type AuditPayload = {
  version: "audit-v1";
  target: string; // normalized origin, e.g. "https://example.com"
  audited_at: string; // ISO 8601 UTC
  fetches: number; // outbound requests actually made (hard cap 10)
  checks: AuditCheck[]; // exactly 12, in the fixed order
  summary: { pass: number; total: 12 };
};

export type AuditSignature = {
  alg: "EdDSA";
  sig: string;
  public_key: string;
};

/** Shape marker `verifyReceipt` dispatches on; distinguishes an audit
 * receipt from a `course.drift_report.v1` report receipt. */
export const AUDIT_RECEIPT_TYPE = "course.site_audit.v1";

export type AuditReceipt = {
  type: typeof AUDIT_RECEIPT_TYPE;
  payload: AuditPayload;
  payload_hash: string;
  signature: AuditSignature | null;
  /** Present only when unsigned - an honest explanation, never a fake signature. */
  note?: string;
};

const AUDIT_UNSIGNED_NOTE =
  "unsigned: AUDIT_SIGNING_KEY is not provisioned on this worker; this report " +
  "carries a payload hash but no signature.";

// The standard PKCS#8 wrapper for a raw 32-byte Ed25519 private key seed
// (RFC 8410 algorithm identifier + OCTET STRING framing). WebCrypto's
// "pkcs8" import format needs this prefix; it never needs the seed alone.
const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * Public key that goes with a signing key produced by `importAuditSigningKey`,
 * keyed by object identity. The signing key itself is deliberately
 * non-extractable (least privilege: it can sign, nothing can read its bits
 * back out) so the public key has to be captured at import time instead.
 */
const auditPublicKeyBySigningKey = new WeakMap<CryptoKey, string>();

/**
 * Decode a base64url-nopad 32-byte Ed25519 seed (as provisioned via the
 * AUDIT_SIGNING_KEY secret) and import it as a signing-only CryptoKey.
 */
export async function importAuditSigningKey(seedB64url: string): Promise<CryptoKey> {
  const seed = b64urlDecode(seedB64url);
  if (seed.length !== 32) {
    throw new Error(
      `AUDIT_SIGNING_KEY must decode to a 32-byte Ed25519 seed, got ${seed.length} bytes`,
    );
  }
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);

  const signingKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "Ed25519" },
    false,
    ["sign"],
  );

  // A second, extractable import of the same bytes exists only to read the
  // matching public key back out (buyers verify offline, so the receipt has
  // to carry it). That copy never signs anything and is not retained.
  const extractableCopy = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "Ed25519" },
    true,
    ["sign"],
  );
  const jwk = (await crypto.subtle.exportKey("jwk", extractableCopy)) as JsonWebKey;
  auditPublicKeyBySigningKey.set(signingKey, jwk.x as string);

  return signingKey;
}

/**
 * Sign an audit payload: Ed25519 over the SHA-256 of its RFC 8785 canonical
 * JSON, the exact mechanism `verifyReceipt` already uses for report
 * receipts. `key` must come from `importAuditSigningKey` - that is where the
 * matching public key was captured.
 */
export async function signAuditPayload(
  payload: AuditPayload,
  key: CryptoKey,
): Promise<AuditSignature> {
  const publicKey = auditPublicKeyBySigningKey.get(key);
  if (!publicKey) {
    throw new Error("signAuditPayload: key was not produced by importAuditSigningKey");
  }
  const messageHash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalize(payload)),
  );
  const sigBytes = await crypto.subtle.sign({ name: "Ed25519" }, key, messageHash);
  return { alg: "EdDSA", sig: b64urlEncode(sigBytes), public_key: publicKey };
}

/**
 * Build the audit receipt. When `signatureBundle` is null (no signing key
 * provisioned), the receipt is still useful - it carries the payload hash a
 * buyer can recompute themselves - but `signature` is honestly `null` with a
 * `note` explaining why. It never fabricates a hash-only pseudo-signature.
 */
export async function buildAuditReceipt(
  payload: AuditPayload,
  signatureBundle: AuditSignature | null,
): Promise<AuditReceipt> {
  const payload_hash = await sha256Canonical(payload);
  if (signatureBundle === null) {
    return {
      type: AUDIT_RECEIPT_TYPE,
      payload,
      payload_hash,
      signature: null,
      note: AUDIT_UNSIGNED_NOTE,
    };
  }
  return {
    type: AUDIT_RECEIPT_TYPE,
    payload,
    payload_hash,
    signature: signatureBundle,
  };
}

/**
 * Audit-shape half of `verifyReceipt`'s dispatch: same mechanism (Ed25519
 * over SHA-256 of RFC 8785 canonical JSON), applied to the embedded payload
 * rather than to "receipt minus signature" the way report receipts work,
 * since an audit receipt signs its payload directly rather than itself.
 */
async function verifyAuditReceiptShape(
  receipt: AuditReceipt,
): Promise<{ signature: boolean; findingsHash: boolean | null; reason: string }> {
  const sig = receipt.signature;
  if (!sig) {
    return {
      signature: false,
      findingsHash: null,
      reason: "receipt is unsigned (no signing key was provisioned when it was built)",
    };
  }
  if (sig.alg !== "EdDSA" || !sig.sig || !sig.public_key) {
    return { signature: false, findingsHash: null, reason: "missing or non-EdDSA signature" };
  }

  const messageHash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalize(receipt.payload)),
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

  const payloadHashOk = (await sha256Canonical(receipt.payload)) === receipt.payload_hash;

  return {
    signature: signatureOk,
    findingsHash: payloadHashOk,
    reason: signatureOk
      ? payloadHashOk
        ? "verified"
        : "signature valid but payload does not match the committed hash"
      : "signature does not verify against the embedded public key",
  };
}

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
  /** Running total of settlements stamped since stamping went live.
   * Absent on stamps written before the counter existed; those count as 1. */
  count?: number;
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

/** Settlements that cleared on-chain before the KV stamp existed, so the pot
 * never undercounts history: two buyer-run x402 purchases on 2026-08-28 and
 * the first fully automated self-purchase on 2026-08-29. Each is a public
 * Base Sepolia transaction; the stamp only ever adds to this floor. */
export const PRELAUNCH_SETTLEMENTS = 3;

export type PotOfGold = {
  /** Total settlements ever: the pre-stamp floor plus the stamped count. */
  settlements: number;
  /** ISO-8601 time of the most recent stamped settlement, or null. */
  last: string | null;
  network: string;
  note: string;
};

/**
 * Pure pot builder for GET /pot: one gold coin per settlement that has ever
 * cleared on this worker. A stamp with a valid positive integer count
 * contributes that count; a stamp without one (written before the counter
 * existed) still proves one settlement; no stamp contributes zero. The
 * pre-stamp floor covers history the stamp cannot know about.
 */
export function buildPot(stamp: SettlementStamp | null | undefined): PotOfGold {
  let stamped = 0;
  if (stamp && typeof stamp.ts === "string") {
    stamped =
      typeof stamp.count === "number" && Number.isInteger(stamp.count) && stamp.count > 0
        ? stamp.count
        : 1;
  }
  const last =
    stamp && typeof stamp.ts === "string" && !Number.isNaN(Date.parse(stamp.ts))
      ? stamp.ts
      : null;
  return {
    settlements: PRELAUNCH_SETTLEMENTS + stamped,
    last,
    network: "eip155:84532",
    note: "One coin per real settlement. Faucet USDC on Base Sepolia testnet, not revenue; the transactions are the checkable record.",
  };
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
