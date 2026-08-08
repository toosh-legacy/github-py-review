"""The agent's authorization boundary: it can produce a report but never write.

These structural tests guard the core safety story — the LangGraph agent has no
node or tool that can post a comment, merge, or modify anything. The only write
path (`github_client/comment.py`) must live outside the agent package.
"""
from pathlib import Path

from agent import graph, security_graph

AGENT_DIR = Path(graph.__file__).parent


def test_graph_nodes_are_read_only():
    for build in (graph.build_graph, security_graph.build_security_graph):
        compiled = build()
        for name in compiled.get_graph().nodes:
            assert not any(
                w in name.lower() for w in ("post", "comment", "merge", "write")
            )


def test_security_scan_never_fetches_anything_itself():
    # The scanner works only on files handed to it in the request, so it has no
    # reach into repositories the caller did not choose to send.
    text = Path(security_graph.__file__).read_text(encoding="utf-8")
    for reaching_out in ("httpx.get", "requests.get", "urlopen", "fetch_diff"):
        assert reaching_out not in text


def test_agent_package_does_not_import_write_path():
    # No file under agent/ may reference the comment-posting helper.
    for py in AGENT_DIR.glob("*.py"):
        text = py.read_text(encoding="utf-8")
        assert "github_client.comment" not in text
        assert "post_pr_comment" not in text
