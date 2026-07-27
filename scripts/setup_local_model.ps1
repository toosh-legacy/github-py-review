# Set up the local CPU reviewer via Ollama (Windows / PowerShell).
#
#   1. installs nothing — checks Ollama is present and running
#   2. pulls a CPU-friendly coding model
#   3. smoke-tests the OpenAI-compatible /v1 endpoint the backend talks to
#
# After this, put these in .env (see .env.example) and restart the backend:
#   LLM_BACKEND=local
#   LOCAL_LLM_BASE_URL=http://localhost:11434/v1
#   LOCAL_LLM_MODEL=qwen2.5-coder:3b
#
# Usage:  ./scripts/setup_local_model.ps1 [-Model qwen2.5-coder:3b]
param(
    [string]$Model = "qwen2.5-coder:3b",
    [string]$BaseUrl = "http://localhost:11434"
)
$ErrorActionPreference = "Stop"

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Host "Ollama is not installed. Get it from https://ollama.com/download" -ForegroundColor Red
    exit 1
}

# Ollama serves in the background once installed; nudge it and wait for the API.
try { Start-Process -NoNewWindow ollama -ArgumentList "serve" -ErrorAction SilentlyContinue } catch {}
$ready = $false
foreach ($i in 1..10) {
    try { Invoke-RestMethod "$BaseUrl/api/tags" -TimeoutSec 2 | Out-Null; $ready = $true; break }
    catch { Start-Sleep -Seconds 1 }
}
if (-not $ready) { Write-Host "Ollama API not reachable at $BaseUrl" -ForegroundColor Red; exit 1 }

Write-Host "Pulling $Model (first run downloads a few GB)..." -ForegroundColor Cyan
ollama pull $Model

Write-Host "Smoke-testing the /v1 chat endpoint..." -ForegroundColor Cyan
$body = @{
    model    = $Model
    messages = @(@{ role = "user"; content = "Reply with the single word: ok" })
} | ConvertTo-Json -Depth 5
$resp = Invoke-RestMethod "$BaseUrl/v1/chat/completions" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 180
Write-Host "Model replied: $($resp.choices[0].message.content)" -ForegroundColor Green
Write-Host "`nDone. Set LLM_BACKEND=local + LOCAL_LLM_MODEL=$Model in .env, then restart the backend." -ForegroundColor Green
