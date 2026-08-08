"""The LLM seam, behind a swappable interface.

    base.py          `ChatLLM` (one JSON chat round-trip), `NoLLM` (the null
                     implementation), and `get_llm()` — the factory triage calls
    local_model.py   any OpenAI-compatible local server (Ollama, llama.cpp,
                     vLLM). Nothing leaves the machine.
    openai_model.py  the hosted OpenAI API
    prompts.py       the triage prompts, kept out of the client code

`LLM_BACKEND` picks the backend (default "auto": local, then OpenAI, then none).
Import from the submodules — nothing is re-exported here, which keeps the OpenAI
SDK out of the import path when no model is configured.
"""
