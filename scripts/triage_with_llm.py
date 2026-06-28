#!/usr/bin/env python3
"""
triage_with_llm.py
──────────────────
Parses a CodeQL SARIF report, extracts findings, reads the source
context, and for each finding asks the local Ollama model to produce:
  1. Vulnerability explanation
  2. Step-by-step exploitation scenario
  3. Severity assessment
  4. Suggested fix

Usage:
    python3 scripts/triage_with_llm.py \
        --sarif  codeql-analysis/results/results.sarif \
        --source .  \
        --model  qwen2.5-coder:1.5b \
        --output codeql-analysis/results/triage_report.md
"""

import json
import sys
import os
import argparse
import subprocess
import textwrap
from pathlib import Path
from datetime import datetime

# ── Ollama REST endpoint ───────────────────────────────────────
OLLAMA_URL = "http://localhost:11434/api/generate"


def ollama_query(model: str, prompt: str, timeout: int = 300) -> str:
    """Send a prompt to the local Ollama instance and return the response."""
    import urllib.request, urllib.error

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,      # Low temp for reproducible analysis
            "num_predict": 1024,
            "num_ctx": 4096,
        }
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return data.get("response", "").strip()
    except urllib.error.URLError as e:
        return f"[ERROR] Ollama unreachable: {e}\nEnsure `ollama serve` is running."


def read_source_context(source_root: str, uri: str, start_line: int,
                        context_lines: int = 10) -> str:
    """Read lines around the finding from the source file."""
    path = Path(source_root) / uri
    if not path.exists():
        return f"(source file not found: {uri})"
    try:
        lines = path.read_text(errors="replace").splitlines()
        lo = max(0, start_line - context_lines - 1)
        hi = min(len(lines), start_line + context_lines)
        snippet = []
        for i, line in enumerate(lines[lo:hi], start=lo + 1):
            marker = ">>>" if i == start_line else "   "
            snippet.append(f"{marker} {i:4d}: {line}")
        return "\n".join(snippet)
    except Exception as e:
        return f"(could not read source: {e})"


def parse_sarif(sarif_path: str):
    """Extract findings from a SARIF file."""
    with open(sarif_path) as f:
        sarif = json.load(f)

    findings = []
    for run in sarif.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {})
                               .get("driver", {})
                               .get("rules", [])}
        for result in run.get("results", []):
            rule_id   = result.get("ruleId", "unknown")
            rule_meta = rules.get(rule_id, {})
            rule_name = rule_meta.get("name", rule_id)
            message   = result.get("message", {}).get("text", "")
            severity  = (result.get("properties", {}).get("problem.severity")
                         or rule_meta.get("properties", {}).get("problem.severity")
                         or "unknown")
            kind      = result.get("kind", "")
            locations = result.get("locations", [])
            uri, start_line = "(unknown)", 1
            if locations:
                loc = (locations[0].get("physicalLocation", {})
                                   .get("artifactLocation", {}))
                uri = loc.get("uri", "(unknown)")
                region = (locations[0].get("physicalLocation", {})
                                      .get("region", {}))
                start_line = region.get("startLine", 1)

            findings.append({
                "rule_id":    rule_id,
                "rule_name":  rule_name,
                "message":    message,
                "severity":   severity,
                "kind":       kind,
                "uri":        uri,
                "line":       start_line,
            })
    return findings


def build_prompt(finding: dict, source_snippet: str) -> str:
    return textwrap.dedent(f"""\
    You are a senior application security engineer performing vulnerability triage.

    ## Finding from CodeQL Static Analysis

    | Field       | Value |
    |-------------|-------|
    | Rule ID     | {finding['rule_id']} |
    | Rule Name   | {finding['rule_name']} |
    | Severity    | {finding['severity']} |
    | File        | {finding['uri']} |
    | Line        | {finding['line']} |

    **CodeQL Message:** {finding['message']}

    ## Vulnerable Source Code (surrounding context)

    ```c
{source_snippet}
    ```

    ## Your Task

    Provide a structured security analysis with ALL of the following sections:

    ### 1. Vulnerability Summary
    Explain what the vulnerability is and why this code is vulnerable.

    ### 2. Step-by-Step Exploitation Scenario
    Describe concretely how an attacker would exploit this vulnerability:
    - What input/action triggers the bug
    - What happens at the memory/OS level
    - What the attacker gains (code execution, info leak, DoS, etc.)
    - Example payload or trigger (where applicable)

    ### 3. Real-World Impact
    What can an attacker achieve in a real application that uses this code?

    ### 4. Severity Justification (CVSS-style reasoning)
    Rate as Critical / High / Medium / Low and explain why.

    ### 5. Remediation
    Show the corrected code or the specific fix needed.
    """)


def triage_all(sarif_path: str, source_root: str, model: str,
               output_path: str, max_findings: int):
    print(f"[*] Parsing SARIF: {sarif_path}")
    findings = parse_sarif(sarif_path)
    print(f"[+] Found {len(findings)} CodeQL findings")

    if not findings:
        print("[!] No findings to triage.")
        sys.exit(0)

    if max_findings and len(findings) > max_findings:
        print(f"[*] Limiting to first {max_findings} findings (use --max 0 for all)")
        findings = findings[:max_findings]

    report_lines = [
        f"# CodeQL Triage Report — Exploitation Analysis",
        f"",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Model:** `{model}`  ",
        f"**SARIF:** `{sarif_path}`  ",
        f"**Findings triaged:** {len(findings)}",
        f"",
        "---",
        "",
    ]

    for idx, finding in enumerate(findings, start=1):
        print(f"\n[{idx}/{len(findings)}] Triaging: {finding['rule_id']} "
              f"@ {finding['uri']}:{finding['line']}")

        snippet = read_source_context(source_root, finding["uri"], finding["line"])
        prompt  = build_prompt(finding, snippet)

        print(f"  → Querying {model} (may take 30–120s on 3 GB RAM)...")
        response = ollama_query(model, prompt)

        report_lines += [
            f"## Finding {idx}: `{finding['rule_id']}`",
            f"",
            f"**File:** `{finding['uri']}` | **Line:** {finding['line']} | "
            f"**Severity:** {finding['severity']}",
            f"",
            response,
            "",
            "---",
            "",
        ]
        print(f"  ✓ Done ({len(response)} chars)")

    # Write report
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    Path(output_path).write_text("\n".join(report_lines))
    print(f"\n[+] Triage report written to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Triage CodeQL SARIF with local LLM")
    parser.add_argument("--sarif",   required=True,  help="Path to SARIF file")
    parser.add_argument("--source",  default=".",    help="Source root directory")
    parser.add_argument("--model",   default=None,   help="Ollama model name")
    parser.add_argument("--output",  default="codeql-analysis/results/triage_report.md",
                        help="Output markdown report path")
    parser.add_argument("--max",     type=int, default=10,
                        help="Max findings to process (0 = all)")
    args = parser.parse_args()

    # Auto-detect model
    if not args.model:
        model_file = Path.home() / ".ollama_vuln_model"
        if model_file.exists():
            args.model = model_file.read_text().strip()
        else:
            args.model = "qwen2.5-coder:1.5b"
    print(f"[*] Using model: {args.model}")

    # Verify Ollama is reachable
    test = ollama_query(args.model, "Reply with: READY", timeout=30)
    if "[ERROR]" in test:
        print(f"[!] {test}")
        print("    Start Ollama with: ollama serve")
        sys.exit(1)
    print("[+] Ollama is reachable")

    triage_all(
        sarif_path=args.sarif,
        source_root=args.source,
        model=args.model,
        output_path=args.output,
        max_findings=args.max if args.max > 0 else 9999,
    )


if __name__ == "__main__":
    main()
