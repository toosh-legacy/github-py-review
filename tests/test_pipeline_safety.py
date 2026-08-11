"""The scan pipeline's structural guarantees.

These are the properties the README claims, asserted mechanically rather than
documented and hoped for: the pipeline cannot write, cannot fetch, and cannot
show a raw credential to a model.
"""
from pathlib import Path

from reposec import pipeline

PIPELINE_FILE = Path(pipeline.__file__)
PACKAGE_ROOT = PIPELINE_FILE.parent


def test_pipeline_stages_are_read_only():
    for name in pipeline.STAGE_NAMES:
        assert not any(
            w in name.lower() for w in ("post", "comment", "merge", "write", "push")
        )


def test_the_pipeline_module_cannot_reach_the_network_or_shell():
    # Files are handed to the pipeline by the caller. Nothing here may fetch
    # them, so the scanner has no reach beyond what it was given.
    text = PIPELINE_FILE.read_text(encoding="utf-8")
    for reaching_out in (
        "httpx.get",
        "httpx.post",
        "requests.get",
        "requests.post",
        "urlopen",
        "subprocess",
    ):
        assert reaching_out not in text, f"pipeline.py reaches out via {reaching_out}"


def test_redaction_runs_before_triage():
    # The ordering is the guarantee: no raw credential may reach the model. If
    # someone reorders these stages, this fails rather than leaking silently.
    order = list(pipeline.STAGE_NAMES)
    assert order.index("redact_findings") < order.index("triage_findings")
    # And every detector must run before redaction, or it would emit evidence
    # that the redaction stage has already been and gone past.
    for detector in ("scan_secrets", "scan_dependencies", "scan_code"):
        assert order.index(detector) < order.index("redact_findings")


def test_every_stage_is_reachable_and_runs_exactly_once():
    # A list cannot have an orphaned node the way a graph can, but it can have a
    # duplicate — and running redaction twice while triage sits between the two
    # copies would still leak.
    assert len(pipeline.STAGE_NAMES) == len(set(pipeline.STAGE_NAMES))
    # Every stage is a distinct callable, so a copy-paste that repeated one
    # function under two names is caught too. (Comparing the lengths of
    # `_PIPELINE` and `STAGE_NAMES` would not be: the latter is built from the
    # former, so that assertion cannot fail.)
    functions = [fn for _, fn in pipeline._PIPELINE]
    assert len(set(map(id, functions))) == len(functions)


def test_detection_stages_never_call_a_model():
    # Triage is the only place a model is consulted. A detector that started
    # asking an LLM would make findings unreproducible.
    text = PIPELINE_FILE.read_text(encoding="utf-8")
    detection = text[: text.index("def _triage(")]
    for model_call in ("get_llm", "chat_json", "ChatLLM"):
        assert model_call not in detection, f"a detection stage references {model_call}"


# --------------------------------------------------------------------------- #
# Tracing
#
# The pipeline state holds `files` — the verbatim source of the repository being
# scanned — and, before redact_findings, detector evidence with credentials
# still in it. While the pipeline was a compiled LangGraph it inherited
# langchain-core's global tracer, which turns itself on from an ambient
# LANGSMITH_TRACING in the environment; measured before it was pinned off, a
# three-file scan attempted a 46 KB upload to a third party.
#
# The framework is gone, so the leak is now structurally impossible rather than
# suppressed by a `tracing_context(enabled=False)` that one refactor could drop.
# What has to be defended is that it does not come back.
# --------------------------------------------------------------------------- #
_TRACING_FRAMEWORKS = ("langgraph", "langsmith", "langchain")


def test_no_stage_of_the_scanner_imports_a_tracing_framework():
    offenders = []
    for path in PACKAGE_ROOT.rglob("*.py"):
        if "node_modules" in path.parts:
            continue
        text = path.read_text(encoding="utf-8").lower()
        for framework in _TRACING_FRAMEWORKS:
            if f"import {framework}" in text or f"from {framework}" in text:
                offenders.append(f"{path.name} imports {framework}")
    assert not offenders, (
        "these libraries self-activate a global tracer from an ambient "
        f"LANGSMITH_TRACING and would upload the scanned source: {offenders}"
    )


def test_the_source_of_the_scan_never_leaves_the_process():
    # A second, cruder guard on the same property: the module must not hand any
    # stage a callback or config that could carry state out of it.
    text = PIPELINE_FILE.read_text(encoding="utf-8")
    for escape in ("callbacks=", "LangChainTracer", "langsmith.Client"):
        assert escape not in text, f"pipeline.py must not configure {escape}"


def test_a_scan_runs_end_to_end_without_the_framework():
    # The straight-line runner has to reproduce what the compiled graph did:
    # every key the report needs is present, and the stage that populates it ran.
    report = pipeline.run_security_scan(
        files=[("a.py", "import os\nx = 1\n")], repo="t", offline=True, triage=False
    )
    assert report.scanned_files == 1
    assert report.summary
    assert set(report.counts_by_category) == {"secret", "dependency", "code"}
    assert set(report.counts_by_severity) == {"high", "medium", "low"}
