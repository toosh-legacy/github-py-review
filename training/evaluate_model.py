"""Score a reviewer on the held-out val set: recall, false-positive rate, F1.

The metric mirrors the project's eval philosophy (bugs caught vs false alarms),
computed over the synthetic val split where every example's ground truth is
known:

    recall  = planted bugs caught (predicted line within +/-1 of the label)
    FP-rate = clean files that got any finding (a false alarm)
    F1      = harmonic mean of precision (TP / (TP + false alarms)) and recall

Two prediction backends:
    - endpoint : an OpenAI-compatible server (Ollama/vLLM) — same path the app
                 uses at runtime
    - adapter  : a base model + LoRA adapter loaded directly with transformers,
                 for scoring a freshly-trained round without serving it

Heavy deps (openai / torch / transformers / peft) are imported lazily.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm_model.base import loads_lenient  # noqa: E402

PredictFn = Callable[[str, str], list[dict]]
_TOL = 1  # line tolerance when matching a predicted issue to the planted bug


def _load(val_path: Path) -> list[dict]:
    lines = val_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _messages(record: dict) -> tuple[str, str]:
    msgs = record["messages"]
    system = next(m["content"] for m in msgs if m["role"] == "system")
    user = next(m["content"] for m in msgs if m["role"] == "user")
    return system, user


def _predicted_lines(issues: list[dict]) -> list[int]:
    out = []
    for i in issues:
        try:
            out.append(int(i.get("line_start", 0)))
        except (TypeError, ValueError):
            continue
    return out


def score(records: list[dict], predict: PredictFn) -> dict:
    """Return {recall, fp_rate, precision, f1, ...} for `predict` over records."""
    tp = fn = false_alarms = clean_total = buggy_total = 0

    for rec in records:
        system, user = _messages(rec)
        pred_lines = _predicted_lines(predict(system, user))
        label = rec["meta"]["label"]

        if label == "buggy":
            buggy_total += 1
            gold = json.loads(rec["messages"][-1]["content"])["issues"][0]["line_start"]
            if any(abs(p - gold) <= _TOL for p in pred_lines):
                tp += 1
            else:
                fn += 1
        else:
            clean_total += 1
            if pred_lines:
                false_alarms += 1

    precision = tp / (tp + false_alarms) if (tp + false_alarms) else 0.0
    recall = tp / buggy_total if buggy_total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "f1": round(f1, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fp_rate": round(false_alarms / clean_total, 4) if clean_total else 0.0,
        "tp": tp,
        "fn": fn,
        "false_alarms": false_alarms,
        "buggy_total": buggy_total,
        "clean_total": clean_total,
    }


def predict_via_endpoint(base_url: str, model: str) -> PredictFn:
    """A predict_fn backed by an OpenAI-compatible server (e.g. Ollama)."""
    from openai import OpenAI

    client = OpenAI(base_url=base_url, api_key="local", timeout=180.0, max_retries=1)

    def predict(system: str, user: str) -> list[dict]:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.0,
            response_format={"type": "json_object"},
        )
        data = loads_lenient(resp.choices[0].message.content or "{}")
        return (data or {}).get("issues", []) if isinstance(data, dict) else []

    return predict


def predict_via_adapter(base_model: str, adapter_dir: str | None) -> PredictFn:
    """A predict_fn that loads a base model (+ optional LoRA adapter) locally."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    model = AutoModelForCausalLM.from_pretrained(
        base_model, torch_dtype="auto", device_map="auto"
    )
    if adapter_dir:
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, adapter_dir)
    model.eval()

    def predict(system: str, user: str) -> list[dict]:
        prompt = tokenizer.apply_chat_template(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            add_generation_prompt=True,
            tokenize=False,
        )
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=512, do_sample=False)
        new_tokens = out[0][inputs["input_ids"].shape[1]:]
        text = tokenizer.decode(new_tokens, skip_special_tokens=True)
        data = loads_lenient(text)
        return (data or {}).get("issues", []) if isinstance(data, dict) else []

    return predict


def evaluate(val_path: Path, predict: PredictFn) -> dict:
    return score(_load(val_path), predict)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--val", default="training/data/val.jsonl")
    ap.add_argument("--backend", choices=["endpoint", "adapter"], default="endpoint")
    ap.add_argument("--base-url", default="http://localhost:11434/v1")
    ap.add_argument("--model", default="qwen2.5-coder:3b")
    ap.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-3B-Instruct")
    ap.add_argument("--adapter", default=None)
    args = ap.parse_args()

    if args.backend == "endpoint":
        predict = predict_via_endpoint(args.base_url, args.model)
    else:
        predict = predict_via_adapter(args.base_model, args.adapter)

    result = evaluate(Path(args.val), predict)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
