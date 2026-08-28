# web/

The agent-facing storefront for the Course Drift Oracle. Static files, no
build step, no external requests. This is the content that is served
alongside the live MCP endpoint.

## What is served where

The Worker serves the MCP endpoint at `/mcp`. These static files are served
from the same origin (or from GitHub Pages, or any static host pointed at
this directory):

| File | URL | Audience |
|---|---|---|
| `index.html` | `/` | agents first, humans second: terse tables, JSON-LD, links out |
| `llms.txt` | `/llms.txt` | agents that check for the llms.txt convention before crawling |
| `catalog.json` | `/catalog.json` | the machine-readable source of truth: tool names, prices, rails, verification instructions |

All three describe the same catalog. `catalog.json` is authoritative;
`index.html` and `llms.txt` restate it in the two formats agents are
documented to read today. If the catalog changes, `catalog.json` is edited
first and the other two are brought in line with it.

## Payments

Both payment rails currently settle on testnets: MPP against Tempo, x402
against Base Sepolia. Every file in this directory says so plainly rather
than implying real settlement. Check `catalog.json`'s `status` and payment
fields for the current state before relying on either rail.

## Verify before you buy

Everything a buyer needs to check this service's claims is public:

- [`oracle/`](https://github.com/710git/course-drift-oracle/tree/main/oracle):
  the scanner and the signing code
- [`worker/`](https://github.com/710git/course-drift-oracle/tree/main/worker):
  the MCP server, including the verification logic in `logic.ts`
- [`clients/buyer/`](https://github.com/710git/course-drift-oracle/tree/main/clients/buyer):
  an independent client that re-implements the verification steps itself,
  so you do not have to take the seller's word for how checking works

## Deliberately not done here

- No external requests of any kind: no CDN scripts, no web fonts, no
  analytics, no tracking pixels. Every file here is self-contained.
- No WebMCP (`document.modelContext`) integration; `index.html` stays plain
  HTML with JSON-LD, which works reliably across browsers and crawlers
  today.
