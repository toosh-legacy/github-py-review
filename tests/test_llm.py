"""The LLM seam: reply parsing, the one round-trip, and backend selection.

Only `NoLLM` ran before this file, so client construction and every error path
was unexercised. Triage is optional — a failure here costs ranking, not
detection — but a broken client fails mid-scan on a user's machine, which is the
worst possible moment for it.

No network and no real SDK call: `chat_json` is driven against a fake client
object, and the backends that would import `openai` are given a stub module, so
these tests pass whether or not the SDK is installed.

`reposec.config.settings` is a module-level singleton produced by an
`@lru_cache`d `get_settings()`, and `llm.py` binds that same object at import
time — so monkeypatching attributes *on the instance* is what takes effect
here, exactly as `tests/conftest.py` and `test_triage.py` do it. Setting the
environment variable would not, because the cached Settings is already built.
"""
from __future__ import annotations

import sys
import types

import pytest

from reposec.config import settings
from reposec.llm import (
    ChatLLM,
    LocalLLM,
    NoLLM,
    OpenAILLM,
    get_llm,
    loads_lenient,
)


# --------------------------------------------------------------------------- #
# loads_lenient — small local models do not honour response_format
# --------------------------------------------------------------------------- #
def test_a_clean_json_object_is_parsed():
    assert loads_lenient('{"findings": []}') == {"findings": []}


def test_surrounding_whitespace_is_tolerated():
    assert loads_lenient('\n\n  {"a": 1}\t\n') == {"a": 1}


def test_a_fenced_code_block_is_recovered():
    # ```json fences are the single most common wrapper a 3B model adds.
    raw = '```json\n{"findings": [{"id": "a"}]}\n```'
    assert loads_lenient(raw) == {"findings": [{"id": "a"}]}


def test_a_bare_fence_without_a_language_is_recovered():
    assert loads_lenient('```\n{"a": 1}\n```') == {"a": 1}


def test_leading_prose_before_the_object_is_discarded():
    raw = 'Sure! Here is the triage result:\n{"findings": []}'
    assert loads_lenient(raw) == {"findings": []}


def test_trailing_prose_after_the_object_is_discarded():
    raw = '{"findings": []}\n\nLet me know if you want more detail.'
    assert loads_lenient(raw) == {"findings": []}


def test_nested_braces_survive_because_the_outermost_object_is_taken():
    # A naive `find("}")` would cut the reply at the first inner object and
    # throw away every finding after it.
    raw = (
        'Here you go:\n{"findings": [{"id": "a", "meta": {"nested": {"deep": 1}}}, '
        '{"id": "b"}]}\ndone'
    )
    parsed = loads_lenient(raw)
    assert [f["id"] for f in parsed["findings"]] == ["a", "b"]
    assert parsed["findings"][0]["meta"]["nested"]["deep"] == 1


@pytest.mark.parametrize(
    "raw",
    [
        "[1, 2, 3]",  # a bare list: valid JSON, wrong shape
        '"just a string"',
        "42",
        "true",
        "null",
    ],
)
def test_valid_json_that_is_not_an_object_is_rejected(raw):
    # `_apply` indexes the reply like a dict; returning a list here would turn a
    # sloppy model reply into a TypeError mid-scan.
    assert loads_lenient(raw) is None


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "I cannot help with that request.",
        "{",  # an opening brace with no close
        "}{",  # closing brace before the opening one
        "{not: valid, json at all}",
        "```json\n{oops\n```",
    ],
)
def test_unrecoverable_replies_return_none(raw):
    assert loads_lenient(raw) is None


def test_a_truncated_reply_returns_none_rather_than_half_an_object():
    # Small models hit their context limit mid-object. Half a findings list is
    # worse than none: triage falls back to the detector output instead.
    assert loads_lenient('{"findings": [{"id": "a", "severity": "hi') is None


# --------------------------------------------------------------------------- #
# ChatLLM.chat_json — one round-trip over an OpenAI-compatible client
# --------------------------------------------------------------------------- #
class FakeCompletions:
    def __init__(self, response=None, error=None):
        self.response, self.error = response, error
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


class FakeClient:
    """Mimics `client.chat.completions.create(...)` and nothing else."""

    def __init__(self, response=None, error=None):
        self.completions = FakeCompletions(response, error)
        self.chat = types.SimpleNamespace(completions=self.completions)


def reply(content, *, usage=10):
    """An SDK-shaped response object: choices[0].message.content plus usage."""
    message = types.SimpleNamespace(content=content)
    resp = types.SimpleNamespace(
        choices=[types.SimpleNamespace(message=message)],
        usage=None if usage is None else types.SimpleNamespace(total_tokens=usage),
    )
    return resp


def chat_llm(response=None, error=None):
    llm = ChatLLM()
    llm.client = FakeClient(response, error)
    llm.model = "test-model"
    return llm


def test_a_json_reply_is_parsed_and_tokens_are_reported():
    llm = chat_llm(reply('{"findings": [{"id": "a"}]}', usage=1234))
    parsed, tokens = llm.chat_json("system prompt", "user prompt")
    assert parsed == {"findings": [{"id": "a"}]}
    assert tokens == 1234


def test_the_request_pins_json_mode_and_a_reproducible_temperature():
    # Triage must be reproducible: the same scan twice should not swing
    # severities. And without json_object the reply parsing gets much harder.
    llm = chat_llm(reply("{}"))
    llm.chat_json("SYS", "USR")
    sent = llm.client.completions.calls[0]

    assert sent["model"] == "test-model"
    assert sent["temperature"] == 0.0
    assert sent["response_format"] == {"type": "json_object"}
    assert sent["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "USR"},
    ]


def test_a_fenced_reply_from_a_local_model_still_parses():
    llm = chat_llm(reply('```json\n{"findings": []}\n```'))
    assert llm.chat_json("s", "u")[0] == {"findings": []}


def test_content_of_none_is_treated_as_an_empty_object():
    # The SDK sets content=None when a model returns only a refusal or a tool
    # call. `_apply` rejects an empty dict, so triage falls back cleanly.
    parsed, tokens = chat_llm(reply(None)).chat_json("s", "u")
    assert parsed == {}
    assert tokens == 10


def test_an_unparseable_reply_returns_none_but_still_reports_its_cost():
    # The tokens were spent whether or not the reply was usable; hiding that
    # would under-report the scan's cost.
    parsed, tokens = chat_llm(reply("I'm sorry, I can't do that.", usage=77)).chat_json(
        "s", "u"
    )
    assert parsed is None
    assert tokens == 77


@pytest.mark.parametrize("usage", [None, 0])
def test_missing_usage_data_counts_as_zero_tokens(usage):
    # Local servers (llama.cpp, some Ollama builds) omit usage entirely. That
    # must read as "0 tokens", not crash the scan.
    resp = reply("{}", usage=usage)
    assert chat_llm(resp).chat_json("s", "u") == ({}, 0)


def test_a_usage_object_without_total_tokens_counts_as_zero():
    resp = reply("{}")
    resp.usage = types.SimpleNamespace(prompt_tokens=5)  # no total_tokens field
    assert chat_llm(resp).chat_json("s", "u")[1] == 0


def test_a_null_total_tokens_counts_as_zero():
    resp = reply("{}")
    resp.usage = types.SimpleNamespace(total_tokens=None)
    assert chat_llm(resp).chat_json("s", "u")[1] == 0


def test_transport_failure_propagates_for_the_caller_to_absorb():
    # chat_json is documented to raise; `triage` catches it and keeps the
    # detector findings (see test_triage.py). Swallowing it here would hide
    # a misconfigured endpoint completely.
    llm = chat_llm(error=ConnectionError("connection reset by peer"))
    with pytest.raises(ConnectionError):
        llm.chat_json("s", "u")


def test_no_llm_is_not_a_chat_llm_so_callers_can_tell_them_apart():
    # `isinstance(llm, ChatLLM)` is how the pipeline decides to skip triage.
    assert not isinstance(NoLLM(), ChatLLM)
    assert isinstance(chat_llm(reply("{}")), ChatLLM)


# --------------------------------------------------------------------------- #
# get_llm — backend selection
#
# The `openai` SDK is stubbed rather than imported so these run in an
# environment without it, and so that no client ever opens a socket.
# --------------------------------------------------------------------------- #
class StubOpenAI:
    instances: list[StubOpenAI] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        StubOpenAI.instances.append(self)


@pytest.fixture
def stub_openai(monkeypatch):
    StubOpenAI.instances = []
    module = types.ModuleType("openai")
    module.OpenAI = StubOpenAI
    monkeypatch.setitem(sys.modules, "openai", module)
    return StubOpenAI


@pytest.fixture
def configure(monkeypatch):
    """Set backend selection inputs on the shared, lru_cached settings object."""

    def apply(backend, *, local_url=None, api_key=None):
        monkeypatch.setattr(settings, "llm_backend", backend)
        monkeypatch.setattr(settings, "local_llm_base_url", local_url)
        monkeypatch.setattr(settings, "openai_api_key", api_key)

    return apply


def test_mock_backend_returns_no_model_even_when_credentials_exist(
    configure, stub_openai
):
    # "mock" is the explicit off switch used by the test suite and by CI; a
    # stray OPENAI_API_KEY in the environment must not override it.
    configure("mock", local_url="http://localhost:11434/v1", api_key="sk-test")
    assert isinstance(get_llm(), NoLLM)
    assert stub_openai.instances == []  # nothing was constructed


def test_local_backend_builds_a_local_client(configure, stub_openai):
    configure("local", local_url="http://localhost:11434/v1")
    llm = get_llm()

    assert isinstance(llm, LocalLLM)
    assert llm.model == settings.local_llm_model
    kwargs = stub_openai.instances[0].kwargs
    assert kwargs["base_url"] == "http://localhost:11434/v1"
    # Local servers ignore the key but the SDK refuses to construct without one.
    assert kwargs["api_key"] == "local"
    # Local generation on CPU is slow; a short timeout would fail every scan.
    assert kwargs["timeout"] == 180.0
    assert kwargs["max_retries"] == 1


def test_local_backend_without_a_configured_server_falls_back_to_no_model(
    configure, stub_openai
):
    # Asking for "local" with nothing running must skip triage, not crash mid-
    # scan against a URL that was never set.
    configure("local", local_url=None, api_key="sk-test")
    assert isinstance(get_llm(), NoLLM)
    assert stub_openai.instances == []


def test_openai_backend_builds_a_hosted_client(configure, stub_openai):
    configure("openai", api_key="sk-test-not-a-real-key")
    llm = get_llm()

    assert isinstance(llm, OpenAILLM)
    assert llm.model == settings.openai_model
    assert stub_openai.instances[0].kwargs == {"api_key": "sk-test-not-a-real-key"}


def test_openai_backend_without_a_key_falls_back_to_no_model(configure, stub_openai):
    configure("openai", local_url="http://localhost:11434/v1", api_key=None)
    assert isinstance(get_llm(), NoLLM)
    assert stub_openai.instances == []


def test_auto_prefers_the_local_model_so_configuring_it_goes_offline(
    configure, stub_openai
):
    # The privacy-relevant branch: with both configured, prompts containing
    # source code must not leave the machine.
    configure("auto", local_url="http://localhost:11434/v1", api_key="sk-test")
    llm = get_llm()
    assert isinstance(llm, LocalLLM)
    assert stub_openai.instances[0].kwargs["base_url"] == "http://localhost:11434/v1"


def test_auto_falls_through_to_openai_when_only_a_key_is_set(configure, stub_openai):
    configure("auto", local_url=None, api_key="sk-test")
    assert isinstance(get_llm(), OpenAILLM)


def test_auto_with_nothing_configured_returns_no_model(configure, stub_openai):
    # The default install: detection is complete without a model, so this is a
    # supported configuration rather than an error.
    configure("auto", local_url=None, api_key=None)
    assert isinstance(get_llm(), NoLLM)
    assert stub_openai.instances == []


def test_the_backend_label_in_config_matches_what_get_llm_actually_picks(configure):
    # `--version` and the scan header print `settings.active_backend`. If it
    # drifts from get_llm's real choice the tool reports the wrong backend.
    cases = [
        ("mock", "http://localhost:11434/v1", "sk-test", "mock"),
        ("local", "http://localhost:11434/v1", None, "local"),
        ("local", None, "sk-test", "mock"),
        ("openai", None, "sk-test", "openai"),
        ("openai", None, None, "mock"),
        ("auto", "http://localhost:11434/v1", "sk-test", "local"),
        ("auto", None, "sk-test", "openai"),
        ("auto", None, None, "mock"),
    ]
    for backend, url, key, expected in cases:
        configure(backend, local_url=url, api_key=key)
        assert settings.active_backend == expected, (backend, url, key)


def test_the_real_sdk_constructs_a_local_client_without_touching_the_network(
    configure,
):
    # The stub above proves the wiring; this proves the kwargs are ones the
    # installed SDK actually accepts. Skipped where openai is not installed.
    pytest.importorskip("openai")
    configure("local", local_url="http://localhost:11434/v1")
    llm = get_llm()
    assert isinstance(llm, LocalLLM)
    assert str(llm.client.base_url).startswith("http://localhost:11434")
