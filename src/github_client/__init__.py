"""GitHub I/O, split by direction.

`diff.py` is read-only and is what the agent uses. `comment.py` is the system's
only write path; it is deliberately not re-exported, so nothing reaches it by
importing this package. See `tests/test_agent_safety.py`.
"""
