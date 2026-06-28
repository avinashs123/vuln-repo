#!/bin/bash
# triage_with_llm.sh — wrapper to call the Python triage script
set -e

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SARIF="$REPO_DIR/codeql-analysis/results/results.sarif"
OUTPUT="$REPO_DIR/codeql-analysis/results/triage_report.md"
MODEL_FILE="$HOME/.ollama_vuln_model"

# Load saved model or fall back to default
if [ -f "$MODEL_FILE" ]; then
    MODEL=$(cat "$MODEL_FILE")
else
    MODEL="qwen2.5-coder:1.5b"
fi

echo "=== CodeQL → LLM Triage Pipeline ==="
echo "SARIF  : $SARIF"
echo "Model  : $MODEL"
echo "Output : $OUTPUT"
echo ""

if [ ! -f "$SARIF" ]; then
    echo "[!] SARIF not found. Run scripts/run_codeql_local.sh first."
    exit 1
fi

python3 "$REPO_DIR/scripts/triage_with_llm.py" \
    --sarif   "$SARIF" \
    --source  "$REPO_DIR" \
    --model   "$MODEL" \
    --output  "$OUTPUT" \
    --max     10

echo ""
echo "[+] Report: $OUTPUT"
echo "    View with: cat $OUTPUT | less"
