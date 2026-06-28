# vuln-repo — CodeQL + Local LLM Exploitation Analysis Lab

A self-contained lab for practising **static analysis triage** with CodeQL and an **offline LLM** (Qwen2.5-Coder / Dolphin-Mistral via Ollama) on a 3 GB RAM Ubuntu VM.

## Repository Layout

```
vuln-repo/
├── src/
│   ├── memory_bugs.c       # Buffer overflow, UAF, double-free, OOB
│   ├── format_injection.c  # Format string, command injection, integer overflow
│   └── logic_bugs.c        # TOCTOU, null ptr, uninitialized vars
├── include/                # Headers
├── Makefile
├── scripts/
│   ├── setup_ollama.sh          # Install Ollama + pull model
│   ├── run_codeql_local.sh      # Download CodeQL CLI + run analysis
│   ├── triage_with_llm.sh       # Shell wrapper
│   └── triage_with_llm.py       # Core triage engine (Python3, stdlib only)
├── .github/workflows/
│   └── codeql.yml               # CI workflow for GitHub
└── codeql-analysis/
    └── results/
        ├── results.sarif         # CodeQL findings (SARIF format)
        └── triage_report.md      # LLM-generated exploitation report
```

## Vulnerabilities Covered

| CWE | Class | File | Function |
|-----|-------|------|----------|
| CWE-121 | Stack Buffer Overflow | memory_bugs.c | vuln_stack_overflow |
| CWE-122 | Heap Buffer Overflow | memory_bugs.c | vuln_heap_overflow |
| CWE-416 | Use-After-Free | memory_bugs.c | vuln_use_after_free |
| CWE-415 | Double Free | memory_bugs.c | vuln_double_free |
| CWE-125 | OOB Read | memory_bugs.c | vuln_oob_read |
| CWE-787 | OOB Write | memory_bugs.c | vuln_oob_write |
| CWE-134 | Format String | format_injection.c | vuln_format_string |
| CWE-78  | Command Injection | format_injection.c | vuln_command_injection |
| CWE-22  | Path Traversal | format_injection.c | vuln_path_traversal |
| CWE-190 | Integer Overflow | format_injection.c | vuln_integer_overflow |
| CWE-362 | TOCTOU Race Condition | logic_bugs.c | vuln_toctou_file |
| CWE-476 | NULL Pointer Deref | logic_bugs.c | vuln_null_ptr |

---

## Step-by-Step Setup on a 3 GB RAM Ubuntu VM

### Prerequisites

```bash
sudo apt update && sudo apt install -y \
    git curl build-essential python3 make
```

### Step 1 — Clone / set up this repo

```bash
git clone <your-repo-url> vuln-repo
cd vuln-repo
chmod +x scripts/*.sh
```

### Step 2 — Build the vulnerable code (sanity check)

```bash
make all
# Expected: compiles with warnings, produces ./vuln_demo
```

### Step 3 — Install Ollama and pull a model

```bash
bash scripts/setup_ollama.sh
```

**Model guide for 3 GB RAM:**

| Model | RAM Usage | Quality | Recommended For |
|-------|-----------|---------|-----------------|
| `qwen2.5-coder:1.5b` | ~1.0 GB | ★★★☆ | **Best balance** |
| `qwen2.5:1.5b` | ~1.0 GB | ★★★☆ | General analysis |
| `dolphin-mistral:7b-q2_k` | ~2.8 GB | ★★★★ | Richer output, tight on 3 GB |
| `tinyllama:1.1b-chat` | ~0.6 GB | ★★☆☆ | Fallback if OOM |

> **Qwen3 note:** Qwen3 base models start at 8B parameters (~5 GB). On 3 GB RAM, use Qwen2.5 variants — they are functionally excellent for code analysis.

### Step 4 — Run CodeQL locally (OR use the sample SARIF)

**Option A — Full CodeQL run (requires ~1.5 GB download):**
```bash
bash scripts/run_codeql_local.sh
```

**Option B — Use the included sample SARIF (instant, no download):**
```bash
# Sample SARIF already at codeql-analysis/results/results.sarif
# Skip to Step 5
```

### Step 5 — Run LLM triage

```bash
bash scripts/triage_with_llm.sh
# OR with custom options:
python3 scripts/triage_with_llm.py \
    --sarif  codeql-analysis/results/results.sarif \
    --source . \
    --model  qwen2.5-coder:1.5b \
    --output codeql-analysis/results/triage_report.md \
    --max    5
```

### Step 6 — Read the report

```bash
cat codeql-analysis/results/triage_report.md | less
# Or copy to host machine via scp
```

---

## Using GitHub Actions (cloud CodeQL)

Push to GitHub and the `.github/workflows/codeql.yml` workflow will:
1. Build the project
2. Run the full CodeQL security suite
3. Upload SARIF to GitHub Security tab
4. Save SARIF as a downloadable artifact

Download the artifact, replace `codeql-analysis/results/results.sarif`, then run Step 5.

---

## Memory Tuning for 3 GB RAM

If Ollama OOMs, add to `/etc/systemd/system/ollama.service`:
```
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_NUM_PARALLEL=1"
```
Then: `sudo systemctl daemon-reload && sudo systemctl restart ollama`

Also set swap if not already present:
```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

---

## Example LLM Output

For `cpp/format-string-vulnerability` in `format_injection.c:18`, the LLM produces:

```
### 1. Vulnerability Summary
The printf() call passes user input directly as the format string,
allowing an attacker to inject format specifiers...

### 2. Step-by-Step Exploitation Scenario
1. Attacker supplies: "%x.%x.%x.%x.%n" as input
2. printf() interprets each %x as a stack read...
3. %n writes the byte count to an attacker-controlled address...
4. With enough %x padding, attacker controls the write target...

### 3. Real-World Impact
Arbitrary write → overwrite GOT entry → redirect execution to shellcode

### 4. Severity: CRITICAL (CVSS ~9.8)
...

### 5. Remediation
- printf("%s", user_input);  // Always use a literal format string
```
