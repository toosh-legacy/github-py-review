"""Streamlit dashboard.

Open access — no auth. Point BACKEND_URL at your backend (default localhost:8001)
or set it live in the sidebar.

Tabs:
  1. Scans       — browse repository scans: findings by category and severity,
                   the evidence, the reason, and the fix.
  2. Benchmark   — precision/recall/F1 per detector from the eval harness.

Severity is rendered as stat tiles with an icon and a label rather than a chart:
three ordered counts are a job for numbers, and severity is a reserved status
scale that must never be carried by colour alone.

Run:  streamlit run src/apps/dashboard/app.py
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import requests
import streamlit as st

DEFAULT_BACKEND = os.getenv("BACKEND_URL", "http://localhost:8001").rstrip("/")
RESULTS = (
    Path(__file__).parents[2]
    / "evaluation"
    / "security_benchmark"
    / "results.json"
)

_SEV_COLOR = {"high": "🔴", "medium": "🟠", "low": "🟡"}
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}

st.set_page_config(page_title="Repo Security Scanner", page_icon="🛡️", layout="wide")


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
        triage = "on" if health.get("security_triage") else "off"
        st.success(
            f"Backend online · LLM mode: **{health.get('llm_mode', '?')}** · "
            f"triage **{triage}**"
        )
    else:
        st.error("Backend unreachable")
    if st.button("🔄 Refresh"):
        st.rerun()
    st.caption("Open access — no authentication.")


st.title("🛡️ Repo Security Scanner")

scans_tab, eval_tab = st.tabs(["Security scans", "Benchmark"])


# --------------------------------------------------------------------------- #
# Tab 1 — Security scans
# --------------------------------------------------------------------------- #
_CAT_LABEL = {
    "secret": "🔑 Secret",
    "dependency": "📦 Dependency",
    "code": "⚠️ Code",
}
_EXPLOIT_LABEL = {
    "direct": "directly exploitable",
    "conditional": "exploitable given a precondition",
    "theoretical": "no plausible path here",
}


def _render_security_report(report: dict, *, scan_id: int | None = None) -> None:
    findings = report.get("findings", [])
    sev = report.get("counts_by_severity", {})
    cat = report.get("counts_by_category", {})

    st.write(f"**{report.get('summary', '')}**")

    # Stat tiles, not a chart: three ordered counts are numbers, and severity is
    # a status scale that has to carry an icon and a label, never colour alone.
    cols = st.columns(6)
    cols[0].metric("Findings", len(findings))
    cols[1].metric("🔴 High", sev.get("high", 0))
    cols[2].metric("🟠 Medium", sev.get("medium", 0))
    cols[3].metric("🟡 Low", sev.get("low", 0))
    cols[4].metric("Files scanned", report.get("scanned_files", 0))
    cols[5].metric("Suppressed", report.get("suppressed", 0))

    # A detector that could not run is never presented as a clean result.
    for note in report.get("degraded", []):
        st.warning(note, icon="⚠️")

    if not findings:
        st.success("No security findings. 🎉")
        return

    # Filters in one row above the content.
    left, right = st.columns(2)
    categories = left.multiselect(
        "Category",
        options=[c for c in _CAT_LABEL if cat.get(c)],
        default=[c for c in _CAT_LABEL if cat.get(c)],
        format_func=lambda c: f"{_CAT_LABEL[c]} ({cat.get(c, 0)})",
        key=f"cat-{scan_id}",
    )
    severities = right.multiselect(
        "Severity",
        options=list(_SEV_COLOR),
        default=list(_SEV_COLOR),
        format_func=lambda s: f"{_SEV_COLOR[s]} {s} ({sev.get(s, 0)})",
        key=f"sev-{scan_id}",
    )

    shown = [
        f
        for f in findings
        if f.get("category") in categories and f.get("severity") in severities
    ]
    shown.sort(key=lambda f: _SEV_ORDER.get(f.get("severity"), 9))

    st.caption(f"Showing {len(shown)} of {len(findings)} findings.")
    for f in shown:
        badge = _SEV_COLOR.get(f.get("severity"), "⚪")
        where = f["file"] if not f.get("line_start") else f"{f['file']}:{f['line_start']}"
        label = _CAT_LABEL.get(f.get("category"), f.get("category", "?"))
        with st.expander(f"{badge} {f['severity'].upper()} · {label} — {where}"):
            st.markdown(f"**{f.get('title', '')}**")
            st.caption(
                f"`{f.get('rule_id', '')}` via `{f.get('detector', '')}`"
                + (
                    f" · {_EXPLOIT_LABEL.get(f['exploitability'], f['exploitability'])}"
                    if f.get("exploitability")
                    else ""
                )
                + ("" if f.get("triaged") else " · not triaged")
            )
            if f.get("evidence"):
                st.code(f["evidence"], language=None)
            if f.get("explanation"):
                st.write(f["explanation"])
            if f.get("suggested_fix"):
                st.info(f["suggested_fix"], icon="🛠️")
            if f.get("merged_from"):
                st.caption(f"{len(f['merged_from'])} duplicate finding(s) merged in.")
            for url in f.get("references", [])[:3]:
                st.caption(url)

    st.download_button(
        "⬇️ Download report (JSON)",
        data=json.dumps(report, indent=2),
        file_name=f"security-scan-{scan_id or 'report'}.json",
        mime="application/json",
        key=f"dl-sec-{scan_id}",
    )


with scans_tab:
    st.caption(
        "Scans are started from the Chrome extension (a repository page → "
        "**🛡️ Security scan**) or the CLI (`python -m security.cli .`). This view "
        "reads what they stored."
    )
    try:
        resp = requests.get(f"{backend}/security/scans", timeout=10)
        scans = resp.json() if resp.status_code < 400 else []
    except requests.RequestException as exc:
        scans = []
        st.error(f"Backend unreachable: {exc}")

    if not scans:
        st.info("No scans yet.")
    else:
        options = {
            f"#{s['id']} · {s.get('repo') or 'unknown repo'}"
            f"{'@' + s['ref'] if s.get('ref') else ''} · "
            f"{s['finding_count']} finding(s) · {s['created_at'][:19]}": s["id"]
            for s in scans
        }
        picked = st.selectbox("Scan", list(options))
        try:
            detail = requests.get(
                f"{backend}/security/scans/{options[picked]}", timeout=30
            )
            if detail.status_code >= 400:
                st.error(detail.json().get("error", {}).get("message", detail.text))
            else:
                record = detail.json()
                _render_security_report(record["report"], scan_id=record["id"])
        except requests.RequestException as exc:
            st.error(f"Backend unreachable: {exc}")


# --------------------------------------------------------------------------- #
# Tab 2 — Benchmark
# --------------------------------------------------------------------------- #
with eval_tab:
    st.subheader("Detector benchmark")
    st.caption(
        "Scored against a labelled fixture repo. Half of it is decoys — an "
        "`.env.example`, AWS's own documented sample key, parameter-bound SQL "
        "that reads like concatenation — because a scanner that fires on "
        "everything has perfect recall and is worthless."
    )
    if not RESULTS.exists():
        st.info(
            "Run `python src/evaluation/run_security_eval.py` to generate "
            "results.json."
        )
    else:
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        detection = results.get("detection", {})

        overall = detection.get("overall", {})
        c = st.columns(4)
        c[0].metric("Precision", overall.get("precision"))
        c[1].metric("Recall", overall.get("recall"))
        c[2].metric("F1", overall.get("f1"))
        c[3].metric("Scan latency (ms)", results.get("latency_ms"))

        st.table(
            [
                {
                    "detector": name,
                    "precision": d.get("precision"),
                    "recall": d.get("recall"),
                    "f1": d.get("f1"),
                    "caught": d.get("caught"),
                    "missed": d.get("missed"),
                    "false positives": d.get("false_positives"),
                }
                for name, d in detection.items()
                if name != "overall"
            ]
        )

        for label, items in (
            ("Missed", results.get("missed", [])),
            ("False positives", results.get("false_positives", [])),
            ("Notes", results.get("notes", [])),
        ):
            if items:
                st.markdown(f"**{label}**")
                for item in items:
                    st.caption(f"- {item}")

        for note in results.get("degraded", []):
            st.warning(note, icon="⚠️")

        triage = results.get("triage")
        if triage:
            st.markdown("**Triage lift**")
            if triage.get("backend") == "mock":
                st.info(
                    "No model was configured for this run, so triage did "
                    "nothing. Point LLM_BACKEND at a model and re-run with "
                    "`--triage` for a meaningful number.",
                    icon="ℹ️",
                )
            t1, t2, t3 = st.columns(3)
            t1.metric(
                "precision@5",
                triage.get("precision_at_5_after"),
                delta=round(
                    (triage.get("precision_at_5_after") or 0)
                    - (triage.get("precision_at_5_before") or 0),
                    3,
                ),
            )
            t2.metric("Merged by the model", triage.get("merged_by_the_model"))
            t3.metric("Tokens", triage.get("tokens_used"))
