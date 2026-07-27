# Project 2 Spec: AI Code Review Copilot

## Design principle: keep it simple
This spec is scoped to what one undergrad can build and explain 

## 1. Purpose & framing
Proves agent engineering (LangGraph, MCP, RAG, evaluation) **and** software engineering rigor (testing, CI/CD, deployment) in one system. Ships in three layers, each fully working before the next starts:
1. Backend + agent (the substance)
2. Streamlit frontend (accessible demo, no install)
3. Chrome extension (the unique hook)

The evaluation harness (Section 8) is what makes this credible — do not skip it.

## 2. Default decisions (no need to ask — just build with these)
- LLM: OPEN AI API via `OPENAI_API_KEY` env var. **If the key isn't set, the agent runs in "mock mode"** — a stub LLM function that returns a hardcoded example review — so the whole pipeline can be built and tested end-to-end before you have to worry about API costs
- Severity levels: `high`, `medium`, `low` — fixed, don't invent more
- Backend port: `8001`; database: PostgreSQL, name `reviewdb`
- Static analysis tool: `ruff` (Python only for the MVP — don't try to support every language at once)
- Vector store: Chroma, local, no external service
- Extension scope: `https://github.com/*/pull/*` only for the MVP

## 3. Architecture (core / MVP)

```
                    ┌───────────────────────────────┐
                    │        FastAPI Backend          │
   Streamlit  ─────▶│  POST /review                    │
   (paste URL)       │                                  │
                    │  LangGraph agent:                │
   Chrome ext  ─────▶│   fetch_diff                     │
   (popup button)     │   → run_static_analysis          │
                    │   → llm_review_per_file          │
                    │   → aggregate_findings           │
                    │   → return report (JSON)         │
                    │                                  │
                    │  MCP server, 2 tools:            │
                    │   fetch_diff_from_url             │
                    │   repo_context_search (RAG)       │
                    └───────────────────────────────┘
                              │
                              ▼
        { summary, issues: [{file, line_start, line_end,
          severity, description, suggested_fix}],
          tokens_used, latency_ms }
```

**Guardrail (built into the graph, not bolted on):** the agent has no tool that can post a comment, merge, or modify anything. It only ever returns a report object. This is the simplest possible version of an authorization boundary, and it's exactly what you'll explain in an interview when asked about agent safety.

## 4. Tech stack
| Layer | Choice | Why it's the simple option |
|---|---|---|
| Agent orchestration | LangGraph | ~4 nodes, one linear-with-one-branch graph — not a complex multi-agent system |
| LLM | OPEN AI API, with a mock-mode fallback | Lets you build and test without spending API credits until the end |
| Tool protocol | MCP (official Python SDK) | Two tools only |
| Static analysis | `ruff` | One command, one language, for the MVP |
| RAG | Chroma, indexing only the files touched in the diff plus their direct imports (not the whole repo) | Keeps indexing fast and scope small |
| Backend | FastAPI | One route to start (`/review`) |
| Database | PostgreSQL | Store review history + benchmark results |
| Frontend (Layer 2) | Streamlit | Two tabs, no separate frontend build tooling |
| Extension (Layer 3) | Chrome Manifest V3 | One content script, one popup — no complex DOM manipulation required |
| Testing | pytest, `httpx` | Standard |
| CI/CD | GitHub Actions | lint → test → build → deploy |
| Load testing | Locust | ~20-line script |
| Deployment | Fly.io or Railway (backend), Streamlit Community Cloud (frontend) | Free tiers |

## 5. Repo structure
```
project2-code-review-copilot/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI app, /review route
│   │   ├── agent/
│   │   │   ├── graph.py           # LangGraph definition
│   │   │   ├── nodes.py           # fetch_diff, static_analysis, llm_review, aggregate
│   │   │   └── schemas.py         # Pydantic: Issue, Report
│   │   ├── mcp_server/
│   │   │   ├── server.py
│   │   │   └── tools.py           # fetch_diff_from_url, repo_context_search
│   │   ├── rag/
│   │   │   └── indexer.py
│   │   └── db/
│   │       └── models.py
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── test_contract.py
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── locustfile.py
├── streamlit_app/
│   └── app.py                     # tab 1: paste a PR URL; tab 2: evaluation results
├── extension/
│   ├── manifest.json
│   ├── content_script.js          # detects PR page, adds a "Review" button
│   ├── background.js
│   └── popup.html / popup.js      # renders the report as a list
├── evaluation/
│   ├── benchmark_dataset.json
│   └── run_eval.py
├── .github/workflows/ci.yml
└── README.md
```

## 6. Build phases (in order)

**Phase 1 — Backend skeleton, static-analysis-only.** `/review` accepts a diff (as text, pasted or fetched), runs `ruff`, returns the JSON contract from Section 3 with an empty `llm` contribution. No LLM yet — prove the contract works first.

**Phase 2 — LangGraph + mock LLM.** Add `llm_review_per_file` as a graph node, using the mock-mode stub from Section 2 by default. Add `aggregate_findings`. The graph should run end to end even with zero API keys set.

**Phase 3 — Real LLM + MCP.** Wire the real Claude API in behind the same mock interface (swap implementations, not the contract). Wrap `fetch_diff_from_url` and `repo_context_search` as MCP tools.

**Phase 4 — RAG.** Index the diff's touched files (plus direct imports) into Chroma so the agent can reference existing code patterns.

**Phase 5 — Testing + CI/CD.** Unit tests per node, integration test for the full `/review` flow, contract test for the response schema. GitHub Actions: lint → type-check → test → Docker build → deploy.

**Phase 6 — Deploy + load test.** Deploy the backend live. Run Locust, publish p95 latency and throughput.

**Phase 7 — Evaluation harness.** Build and run the labeled benchmark (Section 8). Publish results.

**Phase 8 — Streamlit frontend.** Built on top of the now-stable, deployed backend.

**Phase 9 — Chrome extension (MVP version).** Content script adds a "Review this PR" button to the page. On click, it sends the diff to the backend and displays the returned report in a popup/side panel as a readable list (file, severity, description, suggested fix) with a link to jump to that file in the diff. **Pixel-perfect inline highlighting directly on GitHub's diff lines is a stretch goal, not required for the MVP** — a clean popup/panel view of the report is a complete, demoable product on its own.

## 7. Output contract
```json
{
  "summary": "string",
  "issues": [
    {
      "file": "path/to/file.py",
      "line_start": 42,
      "line_end": 45,
      "severity": "high | medium | low",
      "description": "string",
      "suggested_fix": "diff-style string"
    }
  ],
  "tokens_used": 1234,
  "latency_ms": 890
}
```

## 8. Evaluation — do not skip this
1. Pull 15–20 real historical PRs from small open-source repos where a bug was later found and fixed in a follow-up commit. Label each with the file/line of the real bug.
2. Run the agent on the *original* diff. Did it flag the real bug? → precision/recall.
3. Run it on 8–10 clean merged PRs to measure false-positive rate.
4. Publish a results table: bugs caught / missed / false positives, avg tokens per review, p95 latency.
5. Show this table in the README and the Streamlit "Evaluation results" tab.

## 9. Stretch goals (optional — only after Sections 5–8 are done and tested)
- Pixel-perfect inline highlighting directly on the GitHub diff DOM
- Multi-language static analysis (JS/TS via eslint)
- Auto-post the report as an actual PR comment, gated behind an explicit user click
- Mutation testing (`mutmut`) on the backend test suite
- Terraform-managed cloud deployment
