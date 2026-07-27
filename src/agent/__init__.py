"""The LangGraph review agent: diff in, `Report` out. Never writes anything.

Entry point is `agent.graph.run_review_graph`. Nothing is re-exported here so
the sibling packages can import `agent.diff_utils` without pulling in LangGraph.
"""
