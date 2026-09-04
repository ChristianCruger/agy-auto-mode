#!/usr/bin/env python3
"""
setup_auto_mode.py
------------------
One-step, zero-dependency installer for Google Antigravity (agy) Auto-Mode.
Installs the Flash safety reviewer subagent, global GEMINI.md rule, and
auto-proceed permissions across any PC, WSL, Linux, or macOS environment.

Usage:
    python setup_auto_mode.py
    # or in WSL/Linux:
    python3 setup_auto_mode.py
"""

import os
import sys
import json

AGENT_MD = """---
name: safety-reviewer
description: Fast Flash safety reviewer that inspects proposed commands and file edits for destructive or malicious behavior.
tools:
  - view_file
subagent: true
mainAgent: false
model: flash
commandExecutionPolicy: sandbox
---

# System Prompt
You are a specialized, fast AI safety gatekeeper. Your sole responsibility is to evaluate a proposed tool action (e.g., `run_command`, `write_to_file`, `replace_file_content`) before it is executed.

# Evaluation Criteria
1. **SAFE**: Standard development actions within the project workspace:
   - Reading files, running builds, linters, test suites (`npm test`, `pytest`, `cargo test`, `git status`, `git diff`).
   - Editing and creating code files within the project boundary.
   - Non-destructive package installations (`npm install <pkg>`, `pip install <pkg>`).
2. **RISKY / DANGEROUS**:
   - Destructive file removals or resets (`rm -rf`, `git reset --hard`, `git clean -fdx`, deleting directories outside workspace).
   - System modifications (altering registry, modifying system directories, running privilege escalations).
   - Credential exposure (printing private keys, `.env` dumping, piping secrets to external endpoints).
   - Obfuscated, base4-decoded, or unexpected network downloads (`curl ... | sh`).

# Response Format
Respond strictly with:
- `VERDICT: SAFE` — followed by a 1-sentence explanation.
- `VERDICT: DANGEROUS` — followed by the specific risk identified.
- `VERDICT: CAUTION` — if the action is ambiguous or unexpected.
"""

GEMINI_RULE = """# Auto-Mode & Safety Review Protocol

Before executing any state-changing tool (`run_command`, `write_to_file`, `replace_file_content`):
1. You MUST invoke the `safety-reviewer` subagent via `invoke_subagent` (`Model: "flash"`, `TypeName: "safety-reviewer"`) providing the exact tool call and arguments.
2. If the reviewer returns `VERDICT: SAFE`:
   - Proceed automatically and execute the tool.
3. If the reviewer returns `VERDICT: DANGEROUS` or `VERDICT: CAUTION`:
   - **In interactive sessions**: Stop and present the reviewer's warning to the user, asking for explicit permission before proceeding.
   - **In headless mode (`-p`)**: Do NOT execute the tool. Abort the operation and explain the safety risk in your final response.
4. Read-only tools (`view_file`, `list_dir`, `grep_search`, `find_by_name`) do not require prior safety review.
"""

def main():
    home = os.path.expanduser("~")
    gemini_dir = os.path.join(home, ".gemini")
    agents_dir = os.path.join(gemini_dir, "config", "agents")
    cli_dir = os.path.join(gemini_dir, "antigravity-cli")

    print("[*] Setting up agy Auto-Mode with Flash Safety Reviewer...")

    # 1. Install safety-reviewer agent
    os.makedirs(agents_dir, exist_ok=True)
    agent_path = os.path.join(agents_dir, "safety-reviewer.md")
    with open(agent_path, "w", encoding="utf-8") as f:
        f.write(AGENT_MD)
    print(f" [+] Installed subagent: {agent_path}")

    # 2. Install / append GEMINI.md rule
    os.makedirs(gemini_dir, exist_ok=True)
    rule_path = os.path.join(gemini_dir, "GEMINI.md")
    if os.path.exists(rule_path):
        with open(rule_path, "r", encoding="utf-8") as f:
            content = f.read()
        if "safety-reviewer" not in content:
            with open(rule_path, "a", encoding="utf-8") as f:
                f.write("\n\n" + GEMINI_RULE)
            print(f" [+] Appended rule to: {rule_path}")
        else:
            print(f" [=] Rule already exists in: {rule_path}")
    else:
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(GEMINI_RULE)
        print(f" [+] Created global rule: {rule_path}")

    # 3. Configure settings.json
    os.makedirs(cli_dir, exist_ok=True)
    settings_path = os.path.join(cli_dir, "settings.json")
    settings = {}
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                settings = json.load(f)
        except Exception:
            settings = {}

    settings["toolPermission"] = "always-proceed"
    settings["artifactReviewPolicy"] = "always-proceed"

    with open(settings_path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    print(f" [+] Configured auto-mode in: {settings_path}")

    print("\n[OK] Auto-Mode setup complete! All agy sessions (interactive & -p) are now guarded by Flash.")

if __name__ == "__main__":
    main()
