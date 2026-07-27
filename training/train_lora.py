"""QLoRA fine-tune of a Qwen2.5-Coder base into a sharper local reviewer.

Runs on a single GPU (Colab / RunPod / Lambda). 4-bit base + a small LoRA
adapter keeps it inside ~12-16 GB of VRAM. The user is CPU-only, so training
happens in the cloud; the exported model is then served locally (see
export_to_gguf.py).

Usage (on a GPU box, from the repo root):
    pip install -r training/requirements-train.txt
    python training/curate_dataset.py --src <good-code-dir> --out training/data
    python training/train_lora.py --data training/data --out training/adapters/round1

Heavy deps (torch, transformers, peft, trl, bitsandbytes, datasets) are imported
lazily so the module stays importable — and lint/compile-checkable — without them.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TrainConfig:
    base_model: str = "Qwen/Qwen2.5-Coder-3B-Instruct"
    data_dir: str = "training/data"
    out_dir: str = "training/adapters/latest"
    epochs: float = 2.0
    lr: float = 2e-4
    lora_r: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    max_seq_len: int = 2048
    batch_size: int = 1
    grad_accum: int = 8
    seed: int = 0
    target_modules: list[str] = field(
        default_factory=lambda: [
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ]
    )


def train(cfg: TrainConfig) -> str:
    """Fine-tune and save a LoRA adapter to cfg.out_dir. Returns that path."""
    import torch
    from datasets import load_dataset
    from peft import LoraConfig
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
    )
    from trl import SFTConfig, SFTTrainer

    if not torch.cuda.is_available():
        raise SystemExit(
            "No CUDA GPU found. QLoRA training needs a GPU — run this on "
            "Colab/RunPod/Lambda. (Serving the result on CPU is fine.)"
        )

    tokenizer = AutoTokenizer.from_pretrained(cfg.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        cfg.base_model, quantization_config=bnb, device_map="auto"
    )

    peft_config = LoraConfig(
        r=cfg.lora_r,
        lora_alpha=cfg.lora_alpha,
        lora_dropout=cfg.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=cfg.target_modules,
    )

    data = load_dataset(
        "json",
        data_files={
            "train": str(Path(cfg.data_dir) / "train.jsonl"),
            "val": str(Path(cfg.data_dir) / "val.jsonl"),
        },
    )

    sft = SFTConfig(
        output_dir=cfg.out_dir,
        num_train_epochs=cfg.epochs,
        learning_rate=cfg.lr,
        per_device_train_batch_size=cfg.batch_size,
        gradient_accumulation_steps=cfg.grad_accum,
        max_seq_length=cfg.max_seq_len,
        logging_steps=10,
        save_strategy="epoch",
        bf16=True,
        seed=cfg.seed,
        report_to="none",
        # The dataset rows are {"messages": [...]}, which SFTTrainer renders with
        # the tokenizer's chat template — so training matches how we prompt at
        # inference (llm_model.prompts).
    )

    trainer = SFTTrainer(
        model=model,
        args=sft,
        train_dataset=data["train"],
        eval_dataset=data["val"],
        peft_config=peft_config,
        processing_class=tokenizer,
    )
    trainer.train()
    trainer.save_model(cfg.out_dir)
    tokenizer.save_pretrained(cfg.out_dir)
    return cfg.out_dir


def _config_from_args(args: argparse.Namespace) -> TrainConfig:
    return TrainConfig(
        base_model=args.base_model,
        data_dir=args.data,
        out_dir=args.out,
        epochs=args.epochs,
        lr=args.lr,
        lora_r=args.lora_r,
        seed=args.seed,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-model", default=TrainConfig.base_model)
    ap.add_argument("--data", default="training/data")
    ap.add_argument("--out", default="training/adapters/latest")
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    out = train(_config_from_args(args))
    print(f"Saved LoRA adapter to {out}")


if __name__ == "__main__":
    main()
