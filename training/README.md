# Fine-tuning the local reviewer (LoRA / QLoRA)

Turns a stock **Qwen2.5-Coder** into a sharper bug detector for this app, then
serves it **locally on CPU** via Ollama. Training runs on a **GPU** (Colab /
RunPod / Lambda) — QLoRA needs one; serving the result does not.

## Why the data is synthesized, not "good codebases"

Fine-tuning a model on clean code teaches it to *write* code, not to *detect
bugs*. A reviewer needs **positives** (buggy code, defect labeled) and
**negatives** (clean code that must return an empty report). `curate_dataset.py`
manufactures both from good source files: it injects one taxonomy bug per example
(bare-except, off-by-one, flipped condition, inverted None-guard, wrong operator)
on a single line and keeps it only if the file still parses — so the bug is
semantic, and the original line is the ground-truth fix. Every example uses the
**same prompts the app uses at inference** (`llm_model/prompts.py`), so training
matches serving.

## The pipeline

```
curate_dataset.py  → training/data/{train,val}.jsonl   (CPU, runs anywhere)
train_lora.py      → training/adapters/roundN/         (GPU: QLoRA)
evaluate_model.py  → recall / FP-rate / F1 on val       (GPU or via a server)
export_to_gguf.py  → merged model → GGUF → Ollama       (CPU ok)
iterate.py         → runs the above in rounds, stops at the plateau
```

## Quick start (on a GPU box, from the repo root)

```bash
pip install -r training/requirements-train.txt
# 1. Build a labeled dataset from any tree of good Python:
python training/curate_dataset.py --src /path/to/good/repos --out training/data --max 8000
# 2. Fine-tune once...
python training/train_lora.py --data training/data --out training/adapters/round1
# 3. ...or fine-tune repeatedly until improvement flattens (the bottleneck):
python training/iterate.py --data training/data --out training/adapters \
    --max-rounds 6 --min-gain 0.01 --patience 2
```

`iterate.py` escalates effort each round (more epochs, then more LoRA rank),
scores F1 on the held-out val split, and **stops when `patience` rounds in a row
fail to gain `min-gain` F1** — that's the "keep fine-tuning until a bottleneck"
loop. The curve is written to `training/adapters/iterations.json`.

## Serve the winner on your CPU

```bash
python training/export_to_gguf.py --base Qwen/Qwen2.5-Coder-3B-Instruct \
    --adapter training/adapters/round3 --out training/merged \
    --llama-cpp /path/to/llama.cpp --quant Q4_K_M
ollama create codereview-qwen -f training/Modelfile
```
Then in `.env`: `LLM_BACKEND=local` and `LOCAL_LLM_MODEL=codereview-qwen`.
Restart the backend — `/debug/file` now runs your fine-tuned model. No code change.

## Measuring the gain end-to-end

`evaluate_model.py` scores the val split (recall = planted bugs caught,
FP-rate = clean files falsely flagged, F1). To compare the base vs the tuned
model against the *project* benchmark instead, point the backend at each in turn
(`LOCAL_LLM_MODEL=...`) and run `python evaluation/run_eval.py`.

## Honest limits

- **CPU can't train.** QLoRA needs a CUDA GPU; `train_lora.py` exits early
  without one. Use a rented/Colab GPU for training, then serve on CPU.
- The synthetic bugs cover the app's fixed taxonomy. Broaden coverage by adding
  operators to `curate_dataset.py`, or by mixing in mined (buggy → fixed) commit
  pairs from real repos — the JSONL format is the only contract the trainer needs.
