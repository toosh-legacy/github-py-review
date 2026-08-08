#!/usr/bin/env bash
# Set up the local CPU reviewer via Ollama (macOS / Linux).
#
#   1. checks Ollama is present and running
#   2. pulls a CPU-friendly coding model
#   3. smoke-tests the OpenAI-compatible /v1 endpoint the backend talks to
#
# After this, put these in .env (see .env.example) and restart the backend:
#   LLM_BACKEND=local
#   LOCAL_LLM_BASE_URL=http://localhost:11434/v1
#   LOCAL_LLM_MODEL=qwen2.5-coder:3b
#
# Usage:  ./scripts/setup_local_model.sh [model]
set -euo pipefail

MODEL="${1:-qwen2.5-coder:3b}"
BASE_URL="${BASE_URL:-http://localhost:11434}"

if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama is not installed. Get it from https://ollama.com/download" >&2
  exit 1
fi

# Ollama runs as a background service once installed; make sure the API is up.
if ! curl -sf "$BASE_URL/api/tags" >/dev/null 2>&1; then
  (ollama serve >/dev/null 2>&1 &) || true
  for _ in $(seq 1 10); do
    curl -sf "$BASE_URL/api/tags" >/dev/null 2>&1 && break
    sleep 1
  done
fi
curl -sf "$BASE_URL/api/tags" >/dev/null 2>&1 || { echo "Ollama API not reachable at $BASE_URL" >&2; exit 1; }

echo "Pulling $MODEL (first run downloads a few GB)..."
ollama pull "$MODEL"

echo "Smoke-testing the /v1 chat endpoint..."
curl -sf "$BASE_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the single word: ok\"}]}" \
  | sed -n 's/.*"content":"\([^"]*\)".*/Model replied: \1/p'

echo
echo "Done. Set LLM_BACKEND=local + LOCAL_LLM_MODEL=$MODEL in .env, then restart the backend."
