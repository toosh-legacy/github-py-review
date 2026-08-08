"""Streamlit dashboard (spec Layer 2).

Open access — no auth. Point BACKEND_URL at your backend (default localhost:8001)
or set it live in the sidebar.

Tabs:
  1. Review      — paste a GitHub PR URL or raw diff, run the agent, see findings,
                   filter by severity, download the report, and (human action)
                   post the report as a PR comment.
  2. History     — browse past reviews and open any one's full report.
  3. Evaluation  — the benchmark table + charts from the eval harness.

Run:  streamlit run src/apps/dashboard/app.py
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import requests
import streamlit as st

DEFAULT_BACKEND = os.getenv("BACKEND_URL", "http://localhost:8001").rstrip("/")
RESULTS = Path(__file__).parents[2] / "ml" / "evaluation" / "results.json"

_SEV_COLOR = {"high": "🔴", "medium": "🟠", "low": "🟡"}
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}

st.set_page_config(page_title="AI Code Review Copilot", page_icon="🤖", layout="wide")


# --------------------------------------------------------------------------- #
# Sidebar: backend config + live health
# --------------------------------------------------------------------------- #
def _health(backend: str) -> dict | None:
    try:
        r = requests.get(f"{backend}/health", timeout=5)
        return r.json() if r.status_code < 400 else None
    except requests.RequestException:
        return None


with st.sidebar:
    st.header("⚙️ Settings")
    backend = st.text_input("Backend URL", value=DEFAULT_BACKEND).rstrip("/")
    health = _health(backend)
    if health:
        st.success(f"Backend online · LLM mode: **{health.get('llm_mode', '?')}**")
    else:
        st.error("Backend unreachable")
    if st.button("🔄 Refresh"):
        st.rerun()
    st.caption("Open access — no authentication.")


st.title("🤖 AI Code Review Copilot")

review_tab, history_tab, eval_tab = st.tabs(
    ["Review a PR", "History", "Evaluation results"]
)


# --------------------------------------------------------------------------- #
# Shared report renderer
# --------------------------------------------------------------------------- #
def _render_report(report: dict, *, review_id: int | None = None) -> None:
    issues = report.get("issues", [])
    counts = {s: sum(1 for i in issues if i.get("severity") == s) for s in _SEV_COLOR}

    st.write(f"**Summary:** {report.get('summary', '')}")
    cols = st.columns(6)
    cols[0].metric("Issues", len(issues))
    cols[1].metric("🔴 High", counts["high"])
    cols[2].metric("🟠 Medium", counts["medium"])
    cols[3].metric("🟡 Low", counts["low"])
    cols[4].metric("Tokens", report.get("tokens_used", 0))
    cols[5].metric("Latency (ms)", report.get("latency_ms", 0))

    if issues:
        chosen = st.multiselect(
            "Filter by severity",
            options=list(_SEV_COLOR),
            default=list(_SEV_COLOR),
            key=f"filter-{review_id}",
        )
    else:
        chosen = []
        st.info("No issues found. 🎉")

    shown = sorted(
        (i for i in issues if i.get("severity") in chosen),
        key=lambda i: _SEV_ORDER.get(i.get("severity"), 9),
    )
    for i in shown:
        badge = _SEV_COLOR.get(i["severity"], "⚪")
        with st.expander(
            f"{badge} {i['severity'].upper()} — {i['file']}:{i['line_start']}"
        ):
            st.write(i["description"])
            if i.get("suggested_fix"):
                st.code(i["suggested_fix"])

    st.download_button(
        "⬇️ Download report (JSON)",
        data=json.dumps(report, indent=2),
        file_name=f"review-{review_id or 'report'}.json",
        mime="application/json",
        key=f"dl-{review_id}",
    )


# --------------------------------------------------------------------------- #
# Tab 1 — Review
# --------------------------------------------------------------------------- #
with review_tab:
    mode = st.radio("Input", ["PR URL", "Raw diff"], horizontal=True)
    payload: dict = {}
    if mode == "PR URL":
        url = st.text_input("GitHub PR URL", placeholder="https://github.com/o/r/pull/1")
        payload = {"pr_url": url} if url else {}
    else:
        diff = st.text_area("Unified diff", height=200)
        payload = {"diff": diff} if diff else {}

    if st.button("Review", type="primary", disabled=not payload):
        with st.spinner("Running the review agent…"):
            try:
                r = requests.post(f"{backend}/review/full", json=payload, timeout=120)
                if r.status_code >= 400:
                    st.error(r.json().get("error", {}).get("message", r.text))
                else:
                    data = r.json()
                    st.session_state["last_review"] = data
            except requests.RequestException as exc:
                st.error(f"Backend unreachable: {exc}")

    last = st.session_state.get("last_review")
    if last:
        st.success(f"Review #{last['id']} complete")
        _render_report(last["report"], review_id=last["id"])

        with st.expander("📮 Post report as a PR comment (human action)"):
            st.caption(
                "Explicit, human-triggered write. Needs GITHUB_TOKEN on the backend "
                "and a PR-URL-based review."
            )
            if st.button("Post comment", key="post-comment"):
                try:
                    pr = requests.post(
                        f"{backend}/reviews/{last['id']}/post-comment", timeout=60
                    )
                    if pr.status_code >= 400:
                        st.error(
                            pr.json().get("error", {}).get("message", pr.text)
                        )
                    else:
                        st.success("Comment posted.")
                except requests.RequestException as exc:
                    st.error(f"Backend unreachable: {exc}")


# --------------------------------------------------------------------------- #
# Tab 2 — History
# --------------------------------------------------------------------------- #
with history_tab:
    st.subheader("Recent reviews")
    try:
        rows = requests.get(f"{backend}/reviews", timeout=10).json()
    except requests.RequestException:
        rows = None
        st.info("Backend history unavailable.")

    if rows:
        st.dataframe(rows, use_container_width=True)
        ids = [row.get("id") for row in rows if isinstance(row, dict) and "id" in row]
        if ids:
            picked = st.selectbox("Open a review", ids)
            if st.button("Load report", key="load-history"):
                try:
                    detail = requests.get(f"{backend}/reviews/{picked}", timeout=30)
                    if detail.status_code >= 400:
                        st.error(detail.text)
                    else:
                        rec = detail.json()
                        _render_report(rec.get("report", rec), review_id=picked)
                except requests.RequestException as exc:
                    st.error(f"Backend unreachable: {exc}")
    elif rows is not None:
        st.info("No reviews yet — run one in the Review tab.")


# --------------------------------------------------------------------------- #
# Tab 3 — Evaluation
# --------------------------------------------------------------------------- #
with eval_tab:
    st.subheader("Benchmark results")
    if RESULTS.exists():
        results = json.loads(RESULTS.read_text())
        c = st.columns(4)
        c[0].metric("Recall", results.get("recall"))
        c[1].metric("Precision", results.get("precision"))
        c[2].metric("FP rate", results.get("false_positive_rate"))
        c[3].metric("p95 latency (ms)", results.get("p95_latency_ms"))
        st.write(
            f"Caught **{results['bugs_caught']}/{results['buggy_total']}** bugs · "
            f"**{results['false_positives']}/{results['clean_total']}** "
            "false positives · "
            f"avg **{results['avg_tokens']}** tokens/review"
        )
        per_entry = results.get("per_entry", [])
        if per_entry:
            st.bar_chart(
                {r[0]: r[3] for r in per_entry},
                y_label="issues found",
            )
        st.table(
            [
                {"id": r[0], "type": r[1], "outcome": r[2], "issues": r[3]}
                for r in per_entry
            ]
        )
    else:
        st.info("Run `python src/ml/evaluation/run_eval.py` to generate results.json.")
