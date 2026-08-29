/**
 * Agent Readiness Auditor: SSRF-guarded fetch wrapper plus the Tier 1 twelve
 * checks, orchestrated
 * by `runAudit`.
 *
 * This module is the trust-boundary code: the buyer supplies the target, and
 * the Worker fetches it live at request time. Every check evaluator below is
 * a pure function over already-fetched documents (`FetchedDoc`), so the
 * checklist itself is unit-testable with no network - only `runAudit` and the
 * real fetcher (`realFetcher`) touch `fetch()`, and `runAudit` takes its
 * fetcher as a parameter so tests inject a stub there too.
 *
 * `index.ts` imports `runAudit` and `realFetcher` from here; it does not
 * duplicate any of this.
 *
 * Honest residual (memo section 3): a Cloudflare Worker cannot pre-resolve
 * DNS itself, so `validateTargetUrl` checks the hostname/IP-literal a buyer
 * submitted (and, in `realFetcher`, the literal destination of every
 * redirect hop), but a hostname that resolves to a public IP at validation
 * time and a private one at the moment `fetch()` actually dials out (DNS
 * rebinding) is not something this module can observe or block from inside
 * the Worker sandbox. This is mitigated by the platform's own egress shape,
 * not eliminated by anything here - stated plainly rather than assumed away.
 */

// ---------------------------------------------------------------------------
// The audit payload contract, shared with the receipt signer in logic.ts.
// ---------------------------------------------------------------------------

export type AuditCheckStatus = "pass" | "warn" | "info" | "fail" | "error";

export type AuditCheck = {
  id: string; // fixed ids listed below, fixed order
  title: string; // short human title
  status: AuditCheckStatus;
  detail: string; // derived facts only, hard cap 300 chars, never raw body
};

export type AuditPayload = {
  version: "audit-v1";
  target: string; // normalized origin, e.g. "https://example.com"
  audited_at: string; // ISO 8601 UTC
  fetches: number; // outbound requests actually made (hard cap 10)
  checks: AuditCheck[]; // exactly 12, in the order below
  summary: { pass: number; total: 12 };
};

/** Fixed check order. */
export const CHECK_IDS = [
  "robots-exists",
  "robots-ai-directives",
  "robots-not-blanket",
  "llmstxt-exists",
  "llmstxt-shape",
  "llmstxt-links",
  "mcp-advert",
  "structured-data",
  "title-meta",
  "charset",
  "content-type-sanity",
  "homepage-response",
] as const;

// ---------------------------------------------------------------------------
// Fetched document model. Every check evaluator below takes only these plain
// values - no Response object, no headers map beyond what is already
// extracted - so evaluators stay pure and network-free.
// ---------------------------------------------------------------------------

export type FetchedDoc =
  | {
      url: string;
      status: number;
      contentType: string;
      body: string;
      truncated: boolean;
      elapsedMs: number;
    }
  | { url: string; error: string };

function isOk(doc: FetchedDoc): doc is Extract<FetchedDoc, { status: number }> {
  return !("error" in doc);
}

/** Hard cap on any `detail` string. Never raw body, only derived facts. */
const DETAIL_CAP = 300;

function cap(detail: string): string {
  return detail.length > DETAIL_CAP ? `${detail.slice(0, DETAIL_CAP - 1)}…` : detail;
}

function check(id: string, title: string, status: AuditCheckStatus, detail: string): AuditCheck {
  return { id, title, status, detail: cap(detail) };
}

// ---------------------------------------------------------------------------
// SSRF guard: validateTargetUrl.
//
// Pure hostname/IP-literal validation. Called once on the buyer's submitted
// URL by runAudit, and again by realFetcher on every redirect hop's absolute
// destination - the memo is explicit that the check has to happen close to
// the actual fetch, not just once at input validation.
// ---------------------------------------------------------------------------

const RESERVED_HOSTNAME_SUFFIXES = [".local", ".internal", ".localhost"];

function parseIPv4(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const nums: number[] = [];
  for (const part of parts) {
    if (!/^[0-9]{1,3}$/.test(part)) return null;
    const n = Number.parseInt(part, 10);
    if (n > 255) return null;
    nums.push(n);
  }
  return nums;
}

/** Loopback, private (RFC 1918), link-local (incl. the cloud metadata
 * address 169.254.169.254), carrier-grade NAT, "this network", and
 * multicast/reserved space. */
function isPrivateIPv4(o: number[]): boolean {
  const [a, b] = o;
  if (a === 127) return true; // loopback
  if (a === 10) return true; // private
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 169 && b === 254) return true; // link-local, includes the metadata IP
  if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  if (a === 0) return true; // "this network"
  if (a >= 224) return true; // multicast (224-239) and reserved (240-255)
  return false;
}

/** Expand an IPv6 literal (without brackets, zone id stripped) to eight
 * 16-bit groups, handling "::" compression and an embedded IPv4 tail (e.g.
 * "::ffff:192.168.1.1"). Returns null if the literal does not parse. */
function expandIPv6(raw: string): { groups: number[]; ipv4Tail: number[] | null } | null {
  let addr = raw;
  const pct = addr.indexOf("%");
  if (pct !== -1) addr = addr.slice(0, pct); // strip zone id, e.g. %eth0

  let ipv4Tail: number[] | null = null;
  const lastColon = addr.lastIndexOf(":");
  const tail = lastColon === -1 ? addr : addr.slice(lastColon + 1);
  if (tail.includes(".")) {
    const parsed = parseIPv4(tail);
    if (!parsed) return null;
    ipv4Tail = parsed;
    const hi = ((parsed[0] << 8) | parsed[1]).toString(16);
    const lo = ((parsed[2] << 8) | parsed[3]).toString(16);
    addr = `${addr.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = addr.split("::");
  if (halves.length > 2) return null;

  const head = halves[0] ? halves[0].split(":").filter((s) => s.length > 0) : [];
  let groupsStr: string[];
  if (halves.length === 2) {
    const tailStr = halves[1] ? halves[1].split(":").filter((s) => s.length > 0) : [];
    const missing = 8 - head.length - tailStr.length;
    if (missing < 0) return null;
    groupsStr = [...head, ...Array(missing).fill("0"), ...tailStr];
  } else {
    groupsStr = head;
  }
  if (groupsStr.length !== 8) return null;

  const groups: number[] = [];
  for (const g of groupsStr) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    groups.push(Number.parseInt(g, 16));
  }
  return { groups, ipv4Tail };
}

/** Loopback (::1), link-local (fe80::/10), unique-local (fc00::/7),
 * unspecified (::), multicast (ff00::/8), and any IPv4-mapped literal
 * (::ffff:0:0/96) - the last is rejected as a class regardless of what the
 * embedded IPv4 address is, since it is exactly the kind of literal an SSRF
 * bypass would use to smuggle a private IPv4 address past a naive check. */
function isReservedIPv6(groups: number[]): boolean {
  const allZero = groups.every((g) => g === 0);
  if (allZero) return true; // ::
  if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 &&
      groups[4] === 0 && groups[5] === 0 && groups[6] === 0 && groups[7] === 1) {
    return true; // ::1
  }
  if ((groups[0] & 0xffc0) === 0xfe80) return true; // fe80::/10
  if ((groups[0] & 0xfe00) === 0xfc00) return true; // fc00::/7
  if ((groups[0] & 0xff00) === 0xff00) return true; // ff00::/8
  if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 &&
      groups[4] === 0 && groups[5] === 0xffff) {
    return true; // ::ffff:0:0/96, IPv4-mapped
  }
  return false;
}

export function validateTargetUrl(
  raw: string,
): { ok: true; origin: string } | { ok: false; reason: string } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "not a valid URL" };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: `unsupported protocol: ${url.protocol}` };
  }
  if (url.username || url.password) {
    return { ok: false, reason: "userinfo in the URL is not allowed" };
  }
  if (url.port && url.port !== "80" && url.port !== "443") {
    return { ok: false, reason: `port ${url.port} is not allowed; only 80, 443, or none` };
  }

  const hostname = url.hostname.toLowerCase();

  if (hostname === "localhost" || RESERVED_HOSTNAME_SUFFIXES.some((sfx) => hostname.endsWith(sfx))) {
    return { ok: false, reason: "reserved or local hostname" };
  }

  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    const expanded = expandIPv6(hostname.slice(1, -1));
    if (!expanded) return { ok: false, reason: "unparseable IPv6 literal" };
    if (isReservedIPv6(expanded.groups)) {
      return { ok: false, reason: "IPv6 literal in a loopback, private, link-local, or mapped range" };
    }
  } else {
    const ipv4 = parseIPv4(hostname);
    if (ipv4 && isPrivateIPv4(ipv4)) {
      return { ok: false, reason: "IPv4 literal in a loopback, private, link-local, or reserved range" };
    }
  }

  return { ok: true, origin: `${url.protocol}//${url.host}` };
}

// ---------------------------------------------------------------------------
// Real fetcher: wraps fetch() with manual redirect handling, a per-fetch
// timeout, and a body byte cap. Exported and used by the worker; also the
// thing runAudit's `fetcher` parameter stands in for during tests.
//
// The redirect loop is factored through `rawFetch` (defaults to global
// fetch, `typeof fetch`) precisely so tests can exercise the real
// redirect-following and re-validation logic by injecting a fake rawFetch
// that returns ordinary in-memory Response objects - no network involved,
// but no reimplementation of the logic under test either.
// ---------------------------------------------------------------------------

export type Fetcher = (url: string, init?: { method?: "GET" | "HEAD" }) => Promise<FetchedDoc>;

const MAX_REDIRECTS = 3;
const FETCH_TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 200 * 1024;

export function makeFetcher(rawFetch: typeof fetch = fetch): Fetcher {
  return async function fetchOne(url, init) {
    const method = init?.method ?? "GET";
    let currentUrl = url;
    const start = Date.now();

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const validated = validateTargetUrl(currentUrl);
      if (!validated.ok) {
        return { url: currentUrl, error: `blocked: ${validated.reason}` };
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      let response: Response;
      try {
        response = await rawFetch(currentUrl, {
          method,
          redirect: "manual",
          signal: controller.signal,
        });
      } catch (error) {
        clearTimeout(timer);
        const message = error instanceof Error ? error.message : String(error);
        return { url: currentUrl, error: `fetch failed: ${message}`.slice(0, DETAIL_CAP) };
      }
      clearTimeout(timer);

      // Manual redirects surface as opaqueredirect (status 0) in some fetch
      // implementations, or as an ordinary 3xx with a Location header in
      // Workers/Node; handle both by falling through to the 3xx branch.
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location) {
          return { url: currentUrl, error: `redirect (${response.status}) with no Location header` };
        }
        if (hop === MAX_REDIRECTS) {
          return { url: currentUrl, error: "too many redirects" };
        }
        try {
          currentUrl = new URL(location, currentUrl).toString();
        } catch {
          return { url: currentUrl, error: "redirect Location header is not a valid URL" };
        }
        continue; // re-validate the new hop at the top of the loop
      }

      const contentType = response.headers.get("content-type") ?? "";

      let body = "";
      let truncated = false;
      if (method !== "HEAD" && response.body) {
        const reader = response.body.getReader();
        const chunks: Uint8Array[] = [];
        let total = 0;
        // eslint-disable-next-line no-constant-condition
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value) continue;
          const remaining = MAX_BODY_BYTES - total;
          if (remaining <= 0) {
            truncated = true;
            try {
              await reader.cancel();
            } catch {
              // best effort; the loop exits either way
            }
            break;
          }
          const slice = value.byteLength > remaining ? value.slice(0, remaining) : value;
          chunks.push(slice);
          total += slice.byteLength;
          if (slice.byteLength < value.byteLength) {
            truncated = true;
            try {
              await reader.cancel();
            } catch {
              // best effort
            }
            break;
          }
        }
        const combined = new Uint8Array(total);
        let offset = 0;
        for (const c of chunks) {
          combined.set(c, offset);
          offset += c.length;
        }
        body = new TextDecoder().decode(combined); // utf-8, non-fatal by default
      }

      return {
        url: currentUrl,
        status: response.status,
        contentType,
        body,
        truncated,
        elapsedMs: Date.now() - start,
      };
    }

    return { url: currentUrl, error: "too many redirects" };
  };
}

/** The fetcher `index.ts` actually wires up in production. */
export const realFetcher: Fetcher = makeFetcher();

// ---------------------------------------------------------------------------
// Tier 1 checks, memo section 1, in fixed order. Each is a pure function
// over already-fetched documents.
// ---------------------------------------------------------------------------

const AI_CRAWLER_TOKENS = ["gptbot", "claudebot", "google-extended", "perplexitybot", "ccbot", "anthropic-ai"];

/** True if `line` starts a robots.txt block naming one of the well-known AI
 * crawler user-agent tokens. Case-insensitive per the robots.txt spec. */
function robotsUserAgentLine(line: string): string | null {
  const m = /^\s*user-agent\s*:\s*(.+?)\s*$/i.exec(line);
  return m ? m[1].toLowerCase() : null;
}

/** Parse robots.txt into a map of user-agent token -> its Disallow lines
 * (raw path strings), grouping consecutive User-agent lines that share a
 * following rule block, per the standard robots.txt block shape. */
function parseRobotsBlocks(body: string): Map<string, string[]> {
  const blocks = new Map<string, string[]>();
  const lines = body.split(/\r?\n/);
  let pendingAgents: string[] = [];
  let sawRuleSincePending = false;

  for (const rawLine of lines) {
    const line = rawLine.split("#")[0]; // strip comments
    const agent = robotsUserAgentLine(line);
    if (agent !== null) {
      if (sawRuleSincePending) {
        pendingAgents = []; // a new block starts after rules follow agents
        sawRuleSincePending = false;
      }
      pendingAgents.push(agent);
      if (!blocks.has(agent)) blocks.set(agent, []);
      continue;
    }
    const disallow = /^\s*disallow\s*:\s*(.*?)\s*$/i.exec(line);
    if (disallow && pendingAgents.length > 0) {
      sawRuleSincePending = true;
      for (const agent of pendingAgents) {
        blocks.get(agent)?.push(disallow[1]);
      }
    }
  }
  return blocks;
}

function evalRobotsExists(robots: FetchedDoc): AuditCheck {
  const title = "robots.txt exists and parses";
  if (!isOk(robots)) {
    return check("robots-exists", title, "error", cap(`fetch failed: ${robots.error}`));
  }
  if (robots.status < 200 || robots.status >= 300) {
    return check("robots-exists", title, "fail", `robots.txt returned HTTP ${robots.status}`);
  }
  const hasAnyUserAgent = robots.body.split(/\r?\n/).some((l) => robotsUserAgentLine(l) !== null);
  if (!hasAnyUserAgent) {
    return check("robots-exists", title, "fail", "robots.txt served but no User-agent block found");
  }
  return check("robots-exists", title, "pass", "robots.txt served with at least one User-agent block");
}

function evalRobotsAiDirectives(robots: FetchedDoc): AuditCheck {
  const title = "robots.txt names at least one AI crawler explicitly";
  if (!isOk(robots) || robots.status < 200 || robots.status >= 300) {
    return check("robots-ai-directives", title, "error", "could not evaluate: robots.txt was not fetched");
  }
  const blocks = parseRobotsBlocks(robots.body);
  const named = AI_CRAWLER_TOKENS.filter((token) => blocks.has(token));
  if (named.length > 0) {
    return check("robots-ai-directives", title, "pass", `named crawler blocks found: ${named.join(", ")}`);
  }
  return check(
    "robots-ai-directives",
    title,
    "fail",
    "no named AI crawler block (GPTBot, ClaudeBot, Google-Extended, PerplexityBot, CCBot, anthropic-ai); only a wildcard block (if any) applies",
  );
}

function evalRobotsNotBlanket(robots: FetchedDoc): AuditCheck {
  const title = "AI crawler directives are not a blanket disallow";
  if (!isOk(robots) || robots.status < 200 || robots.status >= 300) {
    return check("robots-not-blanket", title, "error", "could not evaluate: robots.txt was not fetched");
  }
  const blocks = parseRobotsBlocks(robots.body);
  const named = AI_CRAWLER_TOKENS.filter((token) => blocks.has(token));
  if (named.length === 0) {
    return check("robots-not-blanket", title, "info", "no named AI crawler directives to evaluate");
  }
  const blanket = named.filter((token) => (blocks.get(token) ?? []).some((rule) => rule === "/"));
  if (blanket.length === named.length) {
    return check("robots-not-blanket", title, "info", `named crawler(s) fully blocked (Disallow: /): ${blanket.join(", ")}`);
  }
  if (blanket.length > 0) {
    return check("robots-not-blanket", title, "info", `some named crawlers fully blocked (Disallow: /): ${blanket.join(", ")}; others are not`);
  }
  return check("robots-not-blanket", title, "info", "named AI crawler directives are not a blanket Disallow: /");
}

const LLMS_H1_RE = /^#\s+.+/m;
const LLMS_BLOCKQUOTE_RE = /^>\s*.+/m;
const LLMS_SECTION_RE = /^##\s+.+/m;
const MD_LINK_RE = /\[[^\]]*\]\(([^)]+)\)/g;

function evalLlmsExists(llms: FetchedDoc): AuditCheck {
  const title = "llms.txt exists at the root";
  if (!isOk(llms)) {
    return check("llmstxt-exists", title, "error", cap(`fetch failed: ${llms.error}`));
  }
  if (llms.status < 200 || llms.status >= 300) {
    return check("llmstxt-exists", title, "fail", `llms.txt not found (HTTP ${llms.status})`);
  }
  return check("llmstxt-exists", title, "pass", "llms.txt served with a 2xx status");
}

function evalLlmsShape(llms: FetchedDoc): AuditCheck {
  const title = "llms.txt matches the informal spec shape";
  if (!isOk(llms) || llms.status < 200 || llms.status >= 300) {
    return check("llmstxt-shape", title, "fail", "llms.txt is absent; nothing to shape-check");
  }
  const body = llms.body;
  const missing: string[] = [];
  if (!LLMS_H1_RE.test(body)) missing.push("H1 title");
  if (!LLMS_BLOCKQUOTE_RE.test(body)) missing.push("blockquote summary");
  if (!LLMS_SECTION_RE.test(body)) missing.push("a ## section");
  if (missing.length === 0) {
    return check("llmstxt-shape", title, "pass", "found an H1 title, a blockquote summary, and at least one ## section");
  }
  return check("llmstxt-shape", title, "fail", `missing: ${missing.join(", ")}`);
}

/** Extract up to `max` same-origin markdown link targets from llms.txt body. */
function extractSameOriginLinks(body: string, origin: string, max: number): string[] {
  const links: string[] = [];
  const seen = new Set<string>();
  MD_LINK_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MD_LINK_RE.exec(body)) !== null && links.length < max) {
    let resolved: URL;
    try {
      resolved = new URL(m[1], origin);
    } catch {
      continue;
    }
    if (resolved.origin !== origin) continue; // same-origin only, on purpose
    const url = resolved.toString();
    if (seen.has(url)) continue;
    seen.add(url);
    links.push(url);
  }
  return links;
}

function evalLlmsLinks(llms: FetchedDoc, heads: FetchedDoc[]): AuditCheck {
  const title = "llms.txt links resolve on the same origin";
  if (!isOk(llms) || llms.status < 200 || llms.status >= 300) {
    return check("llmstxt-links", title, "fail", "llms.txt is absent; no links to check");
  }
  if (heads.length === 0) {
    return check("llmstxt-links", title, "fail", "llms.txt has no same-origin markdown links to check");
  }
  const ok = heads.filter((h) => isOk(h) && h.status >= 200 && h.status < 400);
  const broken = heads.filter((h) => !(isOk(h) && h.status >= 200 && h.status < 400));
  if (broken.length === 0) {
    return check("llmstxt-links", title, "pass", `${ok.length}/${heads.length} checked links resolved`);
  }
  return check("llmstxt-links", title, "fail", `${ok.length}/${heads.length} checked links resolved; ${broken.length} did not`);
}

function evalMcpAdvert(mcp: FetchedDoc, home: FetchedDoc): AuditCheck {
  const title = "an MCP server is advertised";
  const wellKnownOk = isOk(mcp) && mcp.status >= 200 && mcp.status < 300;
  let wellKnownValidJson = false;
  if (wellKnownOk && isOk(mcp)) {
    try {
      JSON.parse(mcp.body);
      wellKnownValidJson = true;
    } catch {
      wellKnownValidJson = false;
    }
  }
  if (wellKnownOk && wellKnownValidJson) {
    return check("mcp-advert", title, "pass", "/.well-known/mcp.json served valid JSON");
  }

  const headHasLinkTag = isOk(home) && home.status >= 200 && home.status < 300 &&
    /<link[^>]+rel=["']?[^"'>]*mcp-server[^"'>]*["']?/i.test(home.body);
  if (headHasLinkTag) {
    return check("mcp-advert", title, "pass", 'homepage <head> carries a <link rel="mcp-server"> marker');
  }

  if (wellKnownOk && !wellKnownValidJson) {
    return check("mcp-advert", title, "warn", "/.well-known/mcp.json responded but did not parse as JSON");
  }
  // Absence is the overwhelmingly common case today (memo section 1, item 7)
  // and is not itself damning, so this reports warn rather than fail.
  return check("mcp-advert", title, "warn", "no /.well-known/mcp.json and no <link rel=\"mcp-server\"> marker found");
}

const LD_JSON_RE = /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;

function evalStructuredData(home: FetchedDoc): AuditCheck {
  const title = "homepage carries structured data (JSON-LD)";
  if (!isOk(home) || home.status < 200 || home.status >= 300) {
    return check("structured-data", title, "error", "could not evaluate: homepage was not fetched");
  }
  LD_JSON_RE.lastIndex = 0;
  const blocks: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = LD_JSON_RE.exec(home.body)) !== null) blocks.push(m[1]);
  if (blocks.length === 0) {
    return check("structured-data", title, "fail", "no <script type=\"application/ld+json\"> block found");
  }
  const validCount = blocks.filter((b) => {
    try {
      JSON.parse(b);
      return true;
    } catch {
      return false;
    }
  }).length;
  if (validCount > 0) {
    return check("structured-data", title, "pass", `${validCount}/${blocks.length} ld+json block(s) parsed as valid JSON`);
  }
  return check("structured-data", title, "fail", `${blocks.length} ld+json block(s) found but none parsed as valid JSON`);
}

const TITLE_RE = /<title[^>]*>([\s\S]*?)<\/title>/i;
const META_DESC_RE = /<meta[^>]+name=["']description["'][^>]*content=["']([^"']*)["']/i;
const MAX_TITLE_LEN = 70;
const MAX_DESC_LEN = 300;

function evalTitleMeta(home: FetchedDoc): AuditCheck {
  const title = "homepage has a non-empty title and meta description";
  if (!isOk(home) || home.status < 200 || home.status >= 300) {
    return check("title-meta", title, "error", "could not evaluate: homepage was not fetched");
  }
  const titleMatch = TITLE_RE.exec(home.body);
  const descMatch = META_DESC_RE.exec(home.body);
  const titleText = titleMatch ? titleMatch[1].trim() : "";
  const descText = descMatch ? descMatch[1].trim() : "";

  const problems: string[] = [];
  if (!titleText) problems.push("no <title>");
  else if (titleText.length > MAX_TITLE_LEN) problems.push(`title over ${MAX_TITLE_LEN} chars`);
  if (!descText) problems.push("no meta description");
  else if (descText.length > MAX_DESC_LEN) problems.push(`meta description over ${MAX_DESC_LEN} chars`);

  if (problems.length === 0) {
    return check("title-meta", title, "pass", `title (${titleText.length} chars) and meta description (${descText.length} chars) present`);
  }
  return check("title-meta", title, "fail", problems.join("; "));
}

const META_CHARSET_RE = /<meta[^>]+charset=["']?([a-zA-Z0-9_-]+)["']?/i;

function evalCharset(home: FetchedDoc): AuditCheck {
  const title = "charset is declared and consistent";
  if (!isOk(home) || home.status < 200 || home.status >= 300) {
    return check("charset", title, "error", "could not evaluate: homepage was not fetched");
  }
  const metaMatch = META_CHARSET_RE.exec(home.body);
  const metaCharset = metaMatch ? metaMatch[1].toLowerCase() : null;
  const headerMatch = /charset=([a-zA-Z0-9_-]+)/i.exec(home.contentType);
  const headerCharset = headerMatch ? headerMatch[1].toLowerCase() : null;

  if (!metaCharset && !headerCharset) {
    return check("charset", title, "fail", "no <meta charset> and no charset on the Content-Type header");
  }
  if (metaCharset && headerCharset && metaCharset !== headerCharset) {
    return check("charset", title, "fail", `meta charset (${metaCharset}) disagrees with header charset (${headerCharset})`);
  }
  const declared = metaCharset ?? headerCharset;
  return check("charset", title, "pass", `charset declared as ${declared}`);
}

const CONTENT_TYPE_EXPECTATIONS: Array<{ label: string; expect: string }> = [
  { label: "homepage (/)", expect: "text/html" },
  { label: "robots.txt", expect: "text/plain" },
  { label: "llms.txt", expect: "text/plain" },
];

function evalContentTypeSanity(home: FetchedDoc, robots: FetchedDoc, llms: FetchedDoc): AuditCheck {
  const title = "Content-Type headers match what each path implies";
  const docs = [home, robots, llms];
  const mismatches: string[] = [];
  let anyFetched = false;

  docs.forEach((doc, i) => {
    const { label, expect } = CONTENT_TYPE_EXPECTATIONS[i];
    if (!isOk(doc) || doc.status < 200 || doc.status >= 300) return; // absent paths are covered by their own checks
    anyFetched = true;
    const actual = doc.contentType.split(";")[0].trim().toLowerCase();
    if (actual && actual !== expect) {
      mismatches.push(`${label}: expected ${expect}, got ${actual || "(none)"}`);
    } else if (!actual) {
      mismatches.push(`${label}: no Content-Type header`);
    }
  });

  if (!anyFetched) {
    return check("content-type-sanity", title, "error", "could not evaluate: none of /, robots.txt, llms.txt were fetched");
  }
  if (mismatches.length === 0) {
    return check("content-type-sanity", title, "pass", "all fetched paths returned the expected Content-Type");
  }
  return check("content-type-sanity", title, "fail", mismatches.join("; "));
}

function evalHomepageResponse(home: FetchedDoc): AuditCheck {
  const title = "homepage responds with a 2xx, no-render fetch";
  if (!isOk(home)) {
    return check("homepage-response", title, "info", cap(`fetch failed: ${home.error}`));
  }
  const okRange = home.status >= 200 && home.status < 300;
  const trunc = home.truncated ? ", body truncated at the byte cap" : "";
  return check(
    "homepage-response",
    title,
    "info",
    `returned HTTP ${home.status} in ${home.elapsedMs}ms, no-render fetch${trunc}`,
  );
}

// ---------------------------------------------------------------------------
// Orchestration.
// ---------------------------------------------------------------------------

/** Hard cap on outbound requests per audit, per memo section 3. */
export const MAX_FETCHES = 10;
/** Bound on how many llms.txt-linked paths get an exploratory HEAD. */
const MAX_LLMS_LINK_HEADS = 5;

/**
 * Run the full Tier 1 audit against `target` using `fetcher` for every
 * outbound request. Throws if `target` fails `validateTargetUrl` - callers
 * (the worker's tool handler) are expected to catch that and return a 4xx
 * rather than ever reaching a fetch.
 */
export async function runAudit(target: string, fetcher: Fetcher): Promise<AuditPayload> {
  const validated = validateTargetUrl(target);
  if (!validated.ok) {
    throw new Error(`invalid audit target: ${validated.reason}`);
  }
  const origin = validated.origin;
  let fetches = 0;

  async function budgetedFetch(url: string, method: "GET" | "HEAD" = "GET"): Promise<FetchedDoc> {
    if (fetches >= MAX_FETCHES) {
      return { url, error: "fetch budget exhausted for this audit" };
    }
    fetches += 1;
    return fetcher(url, { method });
  }

  const home = await budgetedFetch(`${origin}/`);
  const robots = await budgetedFetch(`${origin}/robots.txt`);
  const llms = await budgetedFetch(`${origin}/llms.txt`);
  const mcp = await budgetedFetch(`${origin}/.well-known/mcp.json`);

  let llmsLinks: string[] = [];
  if (isOk(llms) && llms.status >= 200 && llms.status < 300) {
    const remaining = Math.max(0, Math.min(MAX_LLMS_LINK_HEADS, MAX_FETCHES - fetches));
    llmsLinks = extractSameOriginLinks(llms.body, origin, remaining);
  }
  const heads: FetchedDoc[] = [];
  for (const link of llmsLinks) {
    heads.push(await budgetedFetch(link, "HEAD"));
  }

  const checks: AuditCheck[] = [
    evalRobotsExists(robots),
    evalRobotsAiDirectives(robots),
    evalRobotsNotBlanket(robots),
    evalLlmsExists(llms),
    evalLlmsShape(llms),
    evalLlmsLinks(llms, heads),
    evalMcpAdvert(mcp, home),
    evalStructuredData(home),
    evalTitleMeta(home),
    evalCharset(home),
    evalContentTypeSanity(home, robots, llms),
    evalHomepageResponse(home),
  ];

  return {
    version: "audit-v1",
    target: origin,
    audited_at: new Date().toISOString(),
    fetches,
    checks,
    summary: { pass: checks.filter((c) => c.status === "pass").length, total: 12 },
  };
}
