"""The agent's authorization boundary: it can produce a report but never write.

These structural tests guard the core safety story — the scan graph has no node
or tool that can post, push, or modify anything, and it never fetches from a
repository the caller did not send.
"""
from pathlib import Path

from agent import security_graph

AGENT_DIR = Path(security_graph.__file__).parent


def test_graph_nodes_are_read_only():
    compiled = security_graph.build_security_graph()
    for name in compiled.get_graph().nodes:
        assert not any(
            w in name.lower() for w in ("post", "comment", "merge", "write", "push")
        )


def test_the_agent_package_cannot_reach_the_network():
    # Files arrive in the request body. Nothing under agent/ may fetch, so the
    # scanner has no reach into repositories the caller did not choose to send.
    for py in AGENT_DIR.glob("*.py"):
        text = py.read_text(encoding="utf-8")
        for reaching_out in (
            "httpx.get",
            "httpx.post",
            "requests.get",
            "requests.post",
            "urlopen",
            "subprocess",
        ):
            assert reaching_out not in text, f"{py.name} reaches out via {reaching_out}"


def test_redaction_runs_before_triage():
    # The ordering is the guarantee: no raw credential may reach the model. If
    # someone reorders these nodes, this fails rather than leaking silently.
    graph = security_graph.build_security_graph().get_graph()
    edges = [(e.source, e.target) for e in graph.edges]
    assert ("suppress_findings", "redact_findings") in edges
    assert ("redact_findings", "triage_findings") in edges
