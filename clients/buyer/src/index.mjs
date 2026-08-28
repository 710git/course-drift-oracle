#!/usr/bin/env node
// Buyer-side smoke test for the Course Drift Oracle MCP server.
//
// Walks the full buyer journey as an independent client: connect, list
// tools, pull the free summary and its receipt, verify that receipt, hit
// the paid tool on both rails (MPP and x402) and confirm each demands
// payment the way it should, then check the findings hash locally using a
// canonicalizer this client owns rather than one imported from the seller.
//
// Usage:
//   node src/index.mjs                        local mode, default dev URL
//   node src/index.mjs local [url]             local mode, optional override
//   node src/index.mjs remote <url>            remote mode against a deploy
//
// See README.md for how to start the local server this talks to.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";

import { sha256Canonical } from "./canonical.mjs";
import { describeRequirements, hasPayer, payX402 } from "./x402-handler.mjs";

const DEFAULT_LOCAL_URL = "http://127.0.0.1:8787/mcp";
const EXPECTED_TOOLS = ["drift_summary", "verify_report", "drift_report", "drift_report_x402"];

function parseArgs(argv) {
  const [first, second] = argv;
  if (!first) return { mode: "local", url: DEFAULT_LOCAL_URL };
  if (first === "local") return { mode: "local", url: second ?? DEFAULT_LOCAL_URL };
  if (first === "remote") {
    if (!second) {
      console.error("remote mode needs a URL: node src/index.mjs remote https://your-worker.example.workers.dev/mcp");
      process.exit(2);
    }
    return { mode: "remote", url: second };
  }
  if (/^https?:\/\//.test(first)) return { mode: "remote", url: first };
  console.error(`unrecognized argument "${first}". Use "local", "local <url>", or "remote <url>".`);
  process.exit(2);
}

// --- pass/fail/skip reporting ----------------------------------------------

const results = [];

function record(name, status, detail) {
  const mark = status === true ? "PASS" : status === false ? "FAIL" : "SKIP";
  results.push({ name, status });
  console.log(`[${mark}] ${name}`);
  if (detail) {
    for (const line of String(detail).split("\n")) console.log(`       ${line}`);
  }
}

function extractJson(result) {
  const text = result?.content?.find((c) => c.type === "text")?.text;
  if (text === undefined) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

// --- the journey -------------------------------------------------------

async function main() {
  const { mode, url } = parseArgs(process.argv.slice(2));
  console.log(`Course Drift Oracle buyer smoke test`);
  console.log(`mode=${mode} url=${url}\n`);

  const client = new Client({ name: "drift-oracle-buyer", version: "0.1.0" }, { capabilities: {} });
  const transport = new StreamableHTTPClientTransport(new URL(url));

  try {
    await client.connect(transport);
  } catch (err) {
    record("1. connect and list tools", false, `could not connect to ${url}: ${err?.message ?? err}`);
    printSummary();
    process.exitCode = 1;
    return;
  }

  // 1. connect + list tools
  let toolNames = [];
  try {
    const { tools } = await client.listTools();
    toolNames = tools.map((t) => t.name);
    const missing = EXPECTED_TOOLS.filter((n) => !toolNames.includes(n));
    record(
      "1. connect and list tools",
      missing.length === 0,
      missing.length ? `missing tools: ${missing.join(", ")}` : `tools: ${toolNames.join(", ")}`,
    );
  } catch (err) {
    record("1. connect and list tools", false, err?.message ?? String(err));
  }

  // 2. drift_summary carries a signed receipt
  let summary;
  let receipt;
  try {
    const result = await client.callTool({ name: "drift_summary", arguments: {} });
    summary = extractJson(result);
    receipt = summary?.receipt;
    const sig = receipt?.signature;
    const hasSignature = sig?.alg === "EdDSA" && typeof sig.sig === "string" && typeof sig.public_key === "string";
    record(
      "2. drift_summary returns a signed receipt",
      hasSignature,
      hasSignature
        ? `alg=${sig.alg} findings_hash=${receipt.findings_hash}`
        : `no usable EdDSA signature on receipt: ${JSON.stringify(receipt)}`,
    );
  } catch (err) {
    record("2. drift_summary returns a signed receipt", false, err?.message ?? String(err));
  }

  // 3. verify_report confirms that signature
  if (receipt) {
    try {
      const result = await client.callTool({ name: "verify_report", arguments: { receipt } });
      const verdict = extractJson(result);
      record("3. verify_report confirms the signature", verdict?.signature === true, JSON.stringify(verdict));
    } catch (err) {
      record("3. verify_report confirms the signature", false, err?.message ?? String(err));
    }
  } else {
    record("3. verify_report confirms the signature", null, "skipped: no receipt from step 2");
  }

  // 4. drift_report - the 402 challenge path (MPP rail)
  let paidFindings;
  try {
    const result = await client.callTool({ name: "drift_report", arguments: {} });
    const report = extractJson(result);
    if (typeof report?._note === "string" && report._note.includes("payments disabled")) {
      paidFindings = report.findings;
      record(
        "4. drift_report payment path",
        Array.isArray(paidFindings) && paidFindings.length > 0,
        `DISABLE_PAYMENTS active: got ${paidFindings?.length ?? 0} findings unpaid, as expected in test mode`,
      );
    } else {
      record(
        "4. drift_report payment path",
        false,
        `payments were not disabled but no challenge was raised - got a report unpaid: ${JSON.stringify(report).slice(0, 300)}`,
      );
    }
  } catch (err) {
    if (err instanceof McpError && err.data && Array.isArray(err.data.challenges)) {
      record(
        "4. drift_report payment path",
        true,
        `402 challenge received (code ${err.code}):\n${JSON.stringify(err.data.challenges, null, 2)}`,
      );
    } else {
      record("4. drift_report payment path", false, `unexpected error: ${err?.message ?? String(err)}`);
    }
  }

  // 5. drift_report_x402 - the x402 payment-required path
  let x402Findings;
  try {
    const result = await client.callTool({ name: "drift_report_x402", arguments: {} });
    const x402Error = result?._meta?.["x402/error"];
    const requirements = x402Error?.accepts;
    const ok = result?.isError === true && Array.isArray(requirements) && requirements.length > 0;
    record(
      "5. drift_report_x402 requires x402 payment",
      ok,
      ok
        ? `x402Version=${x402Error.x402Version} error=${x402Error.error}\n${describeRequirements(requirements)}`
        : `did not get an x402 payment-required response: ${JSON.stringify(result).slice(0, 300)}`,
    );

    // 5b. only runs when BUYER_PRIVATE_KEY is set - see src/x402-handler.mjs.
    // Absent a payer, the unpaid journey above is the entire run, unchanged.
    if (ok && hasPayer()) {
      try {
        const token = await payX402(requirements, x402Error);
        const paidResult = await client.callTool({
          name: "drift_report_x402",
          arguments: {},
          _meta: { "x402/payment": token },
        });
        const report = extractJson(paidResult);
        const settlement = paidResult?._meta?.["x402/payment-response"];
        const settled =
          paidResult?.isError !== true && settlement?.success === true && Array.isArray(report?.findings);
        if (settled) x402Findings = report.findings;
        record(
          "5b. drift_report_x402 payment settles",
          settled,
          settled
            ? `settled: network=${settlement.network} tx=${settlement.transaction} payer=${settlement.payer}, got ${report.findings.length} findings`
            : `payment did not settle: ${JSON.stringify(paidResult).slice(0, 500)}`,
        );
      } catch (err) {
        record("5b. drift_report_x402 payment settles", false, err?.message ?? String(err));
      }
    }
  } catch (err) {
    record("5. drift_report_x402 requires x402 payment", false, err?.message ?? String(err));
  }

  // 6. verify findings_hash locally - RFC 8785 + SHA-256, reimplemented here
  // Prefers findings obtained unpaid in local test mode (step 4); falls back
  // to findings a real x402 payer actually settled for (step 5b) so this
  // step runs whenever either path produced them, rather than only ever the
  // first.
  const findingsToVerify = Array.isArray(paidFindings) ? paidFindings : x402Findings;
  if (Array.isArray(findingsToVerify) && receipt?.findings_hash) {
    try {
      const recomputed = await sha256Canonical(findingsToVerify);
      const ok = recomputed === receipt.findings_hash;
      record(
        "6. findings_hash verifies independently",
        ok,
        ok
          ? `recomputed ${recomputed} matches the receipt`
          : `mismatch: recomputed ${recomputed}, receipt says ${receipt.findings_hash}`,
      );
    } catch (err) {
      record("6. findings_hash verifies independently", false, err?.message ?? String(err));
    }
  } else {
    record(
      "6. findings_hash verifies independently",
      null,
      "skipped: no unpaid findings available to hash (run with DISABLE_PAYMENTS=1, or wire an x402 payer per src/x402-handler.mjs)",
    );
  }

  await client.close();
  printSummary();
}

function printSummary() {
  const pass = results.filter((r) => r.status === true).length;
  const fail = results.filter((r) => r.status === false).length;
  const skip = results.filter((r) => r.status === null).length;
  console.log(`\n${pass} passed, ${fail} failed, ${skip} skipped`);
  if (fail > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error("fatal:", err?.stack ?? err);
  process.exitCode = 1;
});
