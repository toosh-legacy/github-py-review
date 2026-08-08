"""Merge a LoRA adapter into its base and prepare it for local CPU serving.

Pipeline:
    1. merge the adapter into the base weights (peft merge_and_unload) and save a
       standalone HF model  -- this script, always
    2. convert that to GGUF + quantize with llama.cpp                 -- shelled
       out when --llama-cpp is given, else printed as the next step
    3. register it with Ollama via the generated Modelfile            -- printed

After that, serve on CPU with no code change:
    ollama create codereview-qwen -f src/ml/Modelfile
    # then in .env:  LLM_BACKEND=local  LOCAL_LLM_MODEL=codereview-qwen

Usage (GPU box for step 1; CPU is fine for 2-3):
    python src/ml/export_to_gguf.py --base Qwen/Qwen2.5-Coder-3B-Instruct \
        --adapter src/ml/adapters/round3 --out src/ml/merged \
        --llama-cpp /path/to/llama.cpp --quant Q4_K_M
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def merge(base_model: str, adapter_dir: str, out_dir: str) -> str:
    """Merge adapter into base and save a standalone model. Returns out_dir."""
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    model = AutoModelForCausalLM.from_pretrained(base_model, torch_dtype="auto")
    model = PeftModel.from_pretrained(model, adapter_dir)
    model = model.merge_and_unload()

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    model.save_pretrained(out_dir)
    tokenizer.save_pretrained(out_dir)
    return out_dir


def to_gguf(merged_dir: str, llama_cpp: str, quant: str) -> str:
    """Convert a merged HF model to a quantized GGUF using llama.cpp. Returns path."""
    llama = Path(llama_cpp)
    convert = llama / "convert_hf_to_gguf.py"
    if not convert.exists():
        raise SystemExit(f"convert_hf_to_gguf.py not found under {llama_cpp}")

    f16 = Path(merged_dir) / "model-f16.gguf"
    subprocess.run(
        [sys.executable, str(convert), merged_dir,
         "--outfile", str(f16), "--outtype", "f16"],
        check=True,
    )
    quantized = Path(merged_dir) / f"codereview-qwen-{quant}.gguf"
    quantize = llama / "llama-quantize"
    subprocess.run([str(quantize), str(f16), str(quantized), quant], check=True)
    return str(quantized)


def write_modelfile(gguf_path: str, path: str = "src/ml/Modelfile") -> None:
    Path(path).write_text(
        f"FROM {gguf_path}\n"
        "PARAMETER temperature 0\n"
        "PARAMETER num_ctx 4096\n",
        encoding="utf-8",
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", required=True, help="Base model id/path")
    ap.add_argument("--adapter", required=True, help="LoRA adapter dir")
    ap.add_argument("--out", default="src/ml/merged", help="Merged model dir")
    ap.add_argument("--llama-cpp", default=None, help="Path to a llama.cpp checkout")
    ap.add_argument("--quant", default="Q4_K_M", help="GGUF quant type")
    args = ap.parse_args()

    merged = merge(args.base, args.adapter, args.out)
    print(f"Merged model saved to {merged}")

    if args.llama_cpp:
        gguf = to_gguf(merged, args.llama_cpp, args.quant)
        write_modelfile(gguf)
        print(f"GGUF written to {gguf}; Modelfile updated.")
        print("Next:  ollama create codereview-qwen -f src/ml/Modelfile")
    else:
        print(
            "Skipped GGUF conversion (no --llama-cpp). To finish on any machine:\n"
            "  git clone https://github.com/ggerganov/llama.cpp && make -C llama.cpp\n"
            f"  python llama.cpp/convert_hf_to_gguf.py {merged} "
            f"--outfile {merged}/model-f16.gguf --outtype f16\n"
            f"  llama.cpp/llama-quantize {merged}/model-f16.gguf "
            f"{merged}/codereview-qwen-Q4_K_M.gguf Q4_K_M\n"
            "  # then set FROM <that gguf> in src/ml/Modelfile and:\n"
            "  ollama create codereview-qwen -f src/ml/Modelfile"
        )


if __name__ == "__main__":
    main()
