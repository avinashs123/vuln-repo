#!/bin/bash
# =============================================================
# setup_ollama.sh — Install Ollama + pull model for 3 GB RAM VM
# =============================================================
set -e

echo "=== Ollama Setup for 3 GB RAM Ubuntu VM ==="

# ── 1. Install Ollama ─────────────────────────────────────────
if ! command -v ollama &>/dev/null; then
    echo "[*] Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    echo "[+] Ollama installed"
else
    echo "[+] Ollama already installed: $(ollama --version)"
fi

# ── 2. Start Ollama service ───────────────────────────────────
echo "[*] Starting Ollama service..."
sudo systemctl enable ollama 2>/dev/null || true
sudo systemctl start ollama  2>/dev/null || true
sleep 3

# ── 3. Model selection for 3 GB RAM ───────────────────────────
echo ""
echo "=== Model Recommendations for 3 GB RAM ==="
echo ""
echo "  A) qwen2.5:1.5b          ~1.0 GB  (fastest, good enough)"
echo "  B) qwen2.5-coder:1.5b    ~1.0 GB  (code-focused, recommended)"
echo "  C) dolphin-mistral:7b-q2  ~2.8 GB (larger, may swap on 3 GB)"
echo "  D) tinyllama:1.1b-chat    ~0.6 GB  (smallest, least capable)"
echo ""
echo "NOTE: Qwen3 full models require 8+ GB. On 3 GB RAM, use quantized"
echo "      Qwen2.5 variants (functionally equivalent for this task)."
echo ""

read -rp "Choose model [A/B/C/D] (default B): " choice
choice=${choice:-B}

case "${choice^^}" in
    A) MODEL="qwen2.5:1.5b" ;;
    B) MODEL="qwen2.5-coder:1.5b" ;;
    C) MODEL="dolphin-mistral:7b-q2_k" ;;
    D) MODEL="tinyllama:1.1b-chat" ;;
    *) MODEL="qwen2.5-coder:1.5b" ;;
esac

echo "[*] Pulling model: $MODEL"
ollama pull "$MODEL"
echo "[+] Model ready: $MODEL"

# Save selected model for use by triage script
echo "$MODEL" > ~/.ollama_vuln_model
echo "[+] Model name saved to ~/.ollama_vuln_model"

echo ""
echo "=== Test the model ==="
echo "Run:  ollama run $MODEL 'Hello, are you ready?'"
echo "Or:   ./scripts/triage_with_llm.sh"
