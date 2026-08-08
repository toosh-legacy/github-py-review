"""Fine-tune in rounds and stop when improvement flattens out (the bottleneck).

Each round trains a LoRA adapter with a bit more capacity/effort than the last
(more epochs, higher rank), scores it on the held-out val set, and compares its
F1 to the best so far. When `patience` consecutive rounds fail to gain at least
`min_gain` F1, we've hit diminishing returns and stop — that's the bottleneck
you asked to fine-tune up to. The full improvement curve is written to
src/ml/iterations.json.

Run on a GPU box (from the repo root):
    pip install -r src/ml/requirements-train.txt
    python src/ml/curate_dataset.py --src <good-code-dir> --out src/ml/data
    python src/ml/iterate.py --data src/ml/data --out src/ml/adapters \
        --max-rounds 6 --min-gain 0.01 --patience 2

Serving the winning adapter on your CPU: export it (src/ml/export_to_gguf.py)
and point LOCAL_LLM_MODEL at it.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from evaluate_model import evaluate, predict_via_adapter
from train_lora import TrainConfig, train


def _schedule(base_model: str, data_dir: str, out_root: str, n: int) -> list[TrainConfig]:
    """Rounds of increasing effort: more epochs, then more LoRA capacity."""
    plans = []
    for k in range(n):
        plans.append(
            TrainConfig(
                base_model=base_model,
                data_dir=data_dir,
                out_dir=str(Path(out_root) / f"round{k + 1}"),
                epochs=float(1 + k),          # 1, 2, 3, ...
                lora_r=8 * (1 + min(k, 3)),   # 8, 16, 24, 32, 32, ...
                lora_alpha=16 * (1 + min(k, 3)),
                seed=k,
            )
        )
    return plans


def run(
    base_model: str,
    data_dir: str,
    out_root: str,
    max_rounds: int,
    min_gain: float,
    patience: int,
) -> dict:
    val_path = Path(data_dir) / "val.jsonl"
    history: list[dict] = []
    best_f1 = -1.0
    best_round = 0
    stale = 0

    for cfg in _schedule(base_model, data_dir, out_root, max_rounds):
        rnd = len(history) + 1
        print(f"\n=== Round {rnd}: epochs={cfg.epochs} lora_r={cfg.lora_r} ===")
        adapter = train(cfg)
        metrics = evaluate(val_path, predict_via_adapter(cfg.base_model, adapter))
        f1 = metrics["f1"]
        gain = round(f1 - best_f1, 4)
        print(f"  F1={f1}  (best so far {max(best_f1, 0.0)}, gain {gain})")

        history.append(
            {
                "round": rnd, "f1": f1, "gain": gain,
                "metrics": metrics, "config": asdict(cfg),
            }
        )

        if f1 - best_f1 >= min_gain:
            best_f1, best_round, stale = f1, rnd, 0
        else:
            stale += 1
            if stale >= patience:
                print(f"\nPlateau reached after round {rnd}: "
                      f"{stale} rounds under +{min_gain} F1. Stopping.")
                break

    best_adapter = str(Path(out_root) / f"round{best_round}") if best_round else None
    result = {
        "best_round": best_round,
        "best_f1": best_f1,
        "best_adapter": best_adapter,
        "history": history,
    }
    out = Path(out_root)
    out.mkdir(parents=True, exist_ok=True)
    (out / "iterations.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    _print_curve(history, best_round)
    return result


def _print_curve(history: list[dict], best_round: int) -> None:
    print("\nround  epochs  lora_r   F1     gain   marker")
    print("-" * 48)
    for h in history:
        mark = "  <-- best" if h["round"] == best_round else ""
        print(
            f"{h['round']:>5}  {h['config']['epochs']:>6}  "
            f"{h['config']['lora_r']:>6}  {h['f1']:<6} {h['gain']:<6}{mark}"
        )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-model", default=TrainConfig.base_model)
    ap.add_argument("--data", default="src/ml/data")
    ap.add_argument("--out", default="src/ml/adapters")
    ap.add_argument("--max-rounds", type=int, default=6)
    ap.add_argument("--min-gain", type=float, default=0.01)
    ap.add_argument("--patience", type=int, default=2)
    args = ap.parse_args()

    run(
        args.base_model, args.data, args.out,
        args.max_rounds, args.min_gain, args.patience,
    )


if __name__ == "__main__":
    main()
