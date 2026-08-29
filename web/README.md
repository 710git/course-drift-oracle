# web/

The agent-facing storefront for the Course Drift Oracle. Static files, no
build step, no external requests. The MCP server they describe is live at
`https://signetworks.atelieri.workers.dev/mcp` since 2026-08-28; the
storefront itself is served separately at
`https://710git.github.io/course-drift-oracle/`.

## What goes where

The Worker in `agent-economy/worker` serves the MCP endpoint at `/mcp` and
the free `/badge` endpoint. These static files are served from the GitHub
Pages storefront:

| File | URL | Audience |
|---|---|---|
| `index.html` | `/` | agents first, humans second: terse tables, JSON-LD, links out |
| `llms.txt` | `/llms.txt` | agents that check for the llms.txt convention before crawling |
| `catalog.json` | `/catalog.json` | the machine-readable source of truth: tool names, prices, rails, verification instructions |

All three describe the same catalog. `catalog.json` is authoritative;
`index.html` and `llms.txt` restate it in the two formats agents are actually
documented to read today (see `RESEARCH.md`). If the catalog changes, edit
`catalog.json` first and bring the other two in line with it, the same way
`agent-economy/worker/push-to-kv.sh` refuses to publish a free/paid tier
mismatch.

## Why not a fixed `/.well-known/` manifest for x402

Because there isn't one to write to. This session's research
(`RESEARCH.md`) found that x402 Bazaar discovery is reactive: a service
becomes listed by settling a real payment through a Bazaar-participating
facilitator, not by publishing a file at a well-known path. `catalog.json`
still documents the x402 tool and its price, because an agent reading the
catalog directly benefits from that even though the Bazaar itself won't.

## Deliberately not done here

- No worker deployment steps here. `wrangler deploy`, live Cloudflare state,
  and any secret stay out of scope for this directory; see
  `agent-economy/README.md` for how the Worker itself is deployed and run.
- No WebMCP (`document.modelContext`) integration. Per `RESEARCH.md`, it is
  origin-trial-only in Chrome and Edge and unimplemented in Firefox and
  Safari, so it is not a reliable path today. `index.html` stays plain HTML
  with JSON-LD rather than registering live tools.
- No external requests of any kind: no CDN scripts, no web fonts, no
  analytics, no tracking pixels. Every file here is self-contained.
