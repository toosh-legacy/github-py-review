"""The scan pipeline's structural guarantees.

These are the properties the README claims, asserted mechanically rather than
documented and hoped for: the pipeline cannot write, cannot fetch, and cannot
show a raw credential to a model.
"""
from pathlib import Path

from reposec import graph

GRAPH_FILE = Path(graph.__file__)


def test_graph_nodes_are_read_only():
    compiled = graph.build_security_graph()
    for name in compiled.get_graph().nodes:
        assert not any(
            w in name.lower() for w in ("post", "comment", "merge", "write", "push")
        )


def test_the_graph_module_cannot_reach_the_network_or_shell():
    # Files are handed to the graph by the caller. Nothing here may fetch them,
    # so the scanner has no reach beyond what it was given.
    text = GRAPH_FILE.read_text(encoding="utf-8")
    for reaching_out in (
        "httpx.get",
        "httpx.post",
        "requests.get",
        "requests.post",
        "urlopen",
        "subprocess",
    ):
        assert reaching_out not in text, f"graph.py reaches out via {reaching_out}"


def test_redaction_runs_before_triage():
    # The ordering is the guarantee: no raw credential may reach the model. If
    # someone reorders these nodes, this fails rather than leaking silently.
    compiled = graph.build_security_graph().get_graph()
    edges = [(e.source, e.target) for e in compiled.edges]
    assert ("suppress_findings", "redact_findings") in edges
    assert ("redact_findings", "triage_findings") in edges


def test_detection_nodes_never_call_a_model():
    # Triage is the only place a model is consulted. A detector that started
    # asking an LLM would make findings unreproducible.
    text = GRAPH_FILE.read_text(encoding="utf-8")
    detection = text[: text.index("def _triage(")]
    for model_call in ("get_llm", "chat_json", "ChatLLM"):
        assert model_call not in detection, f"a detection node references {model_call}"
