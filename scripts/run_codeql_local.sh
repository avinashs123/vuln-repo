#!/bin/bash
# =============================================================
# run_codeql_local.sh — Run CodeQL locally on the vuln-repo
# Tested on Ubuntu 22.04 / 24.04 (works on 3 GB RAM VMs)
# =============================================================
set -e

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CODEQL_HOME="$HOME/codeql-home"
CODEQL_BIN="$CODEQL_HOME/codeql/codeql"
DB_PATH="$REPO_DIR/codeql-analysis/cpp-db"
RESULTS_DIR="$REPO_DIR/codeql-analysis/results"
SARIF_OUT="$RESULTS_DIR/results.sarif"

echo "=== CodeQL Local Analysis Runner ==="
echo "Repo: $REPO_DIR"

# ── 1. Install CodeQL CLI if not present ──────────────────────
if [ ! -f "$CODEQL_BIN" ]; then
    echo "[*] Downloading CodeQL CLI bundle..."
    mkdir -p "$CODEQL_HOME"
    cd "$CODEQL_HOME"

    # Get the latest release URL (adjust version as needed)
    CODEQL_VERSION="2.17.6"
    BUNDLE_URL="https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz"

    curl -L -o codeql-bundle.tar.gz "$BUNDLE_URL"
    tar -xzf codeql-bundle.tar.gz
    rm codeql-bundle.tar.gz
    echo "[+] CodeQL CLI installed at $CODEQL_BIN"
else
    echo "[+] CodeQL CLI found: $CODEQL_BIN"
fi

# ── 2. Create database ────────────────────────────────────────
echo "[*] Creating CodeQL database for C/C++..."
mkdir -p "$RESULTS_DIR"
rm -rf "$DB_PATH"

"$CODEQL_BIN" database create "$DB_PATH" \
    --language=cpp \
    --command="make -C $REPO_DIR clean all" \
    --source-root="$REPO_DIR" \
    --overwrite

echo "[+] Database created at $DB_PATH"

# ── 3. Run analysis ───────────────────────────────────────────
echo "[*] Running security queries (this takes 2–5 minutes on 3 GB RAM)..."

"$CODEQL_BIN" database analyze "$DB_PATH" \
    cpp-security-and-quality.qls \
    --format=sarif-latest \
    --output="$SARIF_OUT" \
    --ram=2000 \
    --threads=1

echo "[+] SARIF report written to: $SARIF_OUT"

# ── 4. Also generate CSV for easy viewing ─────────────────────
"$CODEQL_BIN" database analyze "$DB_PATH" \
    cpp-security-and-quality.qls \
    --format=csv \
    --output="$RESULTS_DIR/results.csv" \
    --ram=2000 \
    --threads=1

echo "[+] CSV report: $RESULTS_DIR/results.csv"
echo ""
echo "=== Done! Next: run ./scripts/triage_with_llm.sh ==="
