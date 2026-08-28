#!/usr/bin/env node
// Deploy-smoke KV check: confirms the live worker is serving the free
// summary from KV, not the bundled cold-start fallback baked into the
// deployed artifact. Runs after the buyer journey (src/index.mjs), against
// the same URL, using the same MCP client library - but this is not part
// of the buyer journey and does not touch its code. See src/logic.ts's
// getReport() for what tags a response _source: "kv" vs "bundled".
//
// Usage: node scripts/check-kv-source.mjs <mcp-url>
// Exits nonzero (failing the job) if _source is "bundled" or missing, or
// if the call fails outright.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const url = process.argv[2];
if (!url) {
  console.error("usage: node scripts/check-kv-source.mjs <mcp-url>");
  process.exit(2);
}

const client = new Client({ name: "drift-oracle-kv-check", version: "0.1.0" }, { capabilities: {} });
const transport = new StreamableHTTPClientTransport(new URL(url));

try {
  await client.connect(transport);
  const result = await client.callTool({ name: "drift_summary", arguments: {} });
  const text = result?.content?.find((c) => c.type === "text")?.text;
  const summary = text ? JSON.parse(text) : undefined;
  const source = summary?._source;

  if (source === "kv") {
    console.log(`[PASS] drift_summary _source is "kv" (KV publish confirmed live)`);
  } else {
    console.error(`[FAIL] drift_summary _source is "${source}", expected "kv"`);
    console.error(source === "bundled"
      ? "the worker is serving its cold-start bundled fallback, not the report the deploy just published to KV"
      : `unexpected response shape: ${JSON.stringify(summary).slice(0, 300)}`);
    process.exitCode = 1;
  }
} catch (err) {
  console.error(`[FAIL] could not verify KV source: ${err?.message ?? err}`);
  process.exitCode = 1;
} finally {
  await client.close().catch(() => {});
}
