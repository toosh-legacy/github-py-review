"""The LLM reviewer, behind a swappable interface.

    base.py          the `ReviewLLM` contract, the shared chat implementation,
                     and `get_review_llm()` — the factory everything else calls
    mock_model.py    deterministic stub; needs no key, so the pipeline and the
                     tests run entirely offline
    local_model.py   any OpenAI-compatible local server (Ollama, llama.cpp,
                     vLLM). Nothing leaves the machine.
    openai_model.py  the hosted OpenAI API
    prompts.py       every prompt string, kept out of the client code
    verify.py        the precision layer: a second pass that must confirm a
                     finding, plus a syntax check on suggested fixes

`LLM_BACKEND` picks the reviewer (default "auto": local, then OpenAI, then
mock). Import from the submodules — nothing is re-exported here, which keeps
the OpenAI SDK out of the mock-mode import path.
"""
