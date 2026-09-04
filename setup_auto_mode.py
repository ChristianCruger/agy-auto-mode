#!/usr/bin/env python3
"""
setup_auto_mode.py
------------------
One-step, zero-dependency installer for Google Antigravity (agy) Auto-Mode.
Installs the Flash safety reviewer subagent, global GEMINI.md rule, and
auto-proceed permissions across any PC, WSL, Linux, or macOS environment.

Usage:
    python setup_auto_mode.py            # install
    python setup_auto_mode.py --revert   # undo the install
    # or in WSL/Linux: python3 setup_auto_mode.py
"""

import os
import sys
import json
import shutil

MARKER_BEGIN = "<!-- BEGIN agy-auto-mode -->"
MARKER_END = "<!-- END agy-auto-mode -->"

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
   - Obfuscated, base64-decoded, or unexpected network downloads (`curl ... | sh`).

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

RULE_BLOCK = MARKER_BEGIN + "\n" + GEMINI_RULE + MARKER_END + "\n"

AUTO_MODE_SETTINGS = {
    "toolPermission": "always-proceed",
    "artifactReviewPolicy": "always-proceed",
}


class Paths:
    def __init__(self):
        home = os.path.expanduser("~")
        self.gemini_dir = os.path.join(home, ".gemini")
        self.agents_dir = os.path.join(self.gemini_dir, "config", "agents")
        self.cli_dir = os.path.join(self.gemini_dir, "antigravity-cli")
        self.agent = os.path.join(self.agents_dir, "safety-reviewer.md")
        self.rule = os.path.join(self.gemini_dir, "GEMINI.md")
        self.settings = os.path.join(self.cli_dir, "settings.json")
        self.backup = os.path.join(self.cli_dir, "settings.json.auto-mode.bak")


def read_settings(path):
    """Return the parsed settings, or None if the file does not exist.

    Exits with an error if the file exists but is not valid JSON, so that
    existing user settings are never silently discarded.
    """
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    try:
        return json.loads(raw)
    except ValueError as exc:
        sys.exit(
            "[!] {} is not valid JSON ({}).\n"
            "    Fix or remove the file, then run this script again.\n"
            "    Nothing was changed.".format(path, exc)
        )


def write_settings(path, settings):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")


def install(paths):
    print("[*] Setting up agy Auto-Mode with Flash Safety Reviewer...")

    # Read settings first, so a broken file aborts before anything is written.
    settings = read_settings(paths.settings)

    # 1. Install safety-reviewer agent
    os.makedirs(paths.agents_dir, exist_ok=True)
    with open(paths.agent, "w", encoding="utf-8") as f:
        f.write(AGENT_MD)
    print(" [+] Installed subagent: {}".format(paths.agent))

    # 2. Install / append GEMINI.md rule inside removable markers
    os.makedirs(paths.gemini_dir, exist_ok=True)
    if os.path.exists(paths.rule):
        with open(paths.rule, "r", encoding="utf-8") as f:
            content = f.read()
        if MARKER_BEGIN in content:
            print(" [=] Rule already exists in: {}".format(paths.rule))
        else:
            sep = "" if not content or content.endswith("\n\n") else "\n\n"
            with open(paths.rule, "a", encoding="utf-8") as f:
                f.write(sep + RULE_BLOCK)
            print(" [+] Appended rule to: {}".format(paths.rule))
    else:
        with open(paths.rule, "w", encoding="utf-8") as f:
            f.write(RULE_BLOCK)
        print(" [+] Created global rule: {}".format(paths.rule))

    # 3. Configure settings.json, keeping a backup for --revert
    os.makedirs(paths.cli_dir, exist_ok=True)
    if settings is None:
        settings = {}
    elif not os.path.exists(paths.backup):
        shutil.copyfile(paths.settings, paths.backup)
        print(" [+] Saved backup: {}".format(paths.backup))

    settings.update(AUTO_MODE_SETTINGS)
    write_settings(paths.settings, settings)
    print(" [+] Configured auto-mode in: {}".format(paths.settings))

    print("\n[OK] Auto-Mode setup complete! All agy sessions (interactive & -p) are now guarded by Flash.")
    print("     Undo with: python setup_auto_mode.py --revert")


def revert(paths):
    print("[*] Removing agy Auto-Mode...")

    # 1. Remove the subagent
    if os.path.exists(paths.agent):
        os.remove(paths.agent)
        print(" [-] Removed subagent: {}".format(paths.agent))
    else:
        print(" [=] Subagent not installed.")

    # 2. Strip the rule block from GEMINI.md
    if os.path.exists(paths.rule):
        with open(paths.rule, "r", encoding="utf-8") as f:
            content = f.read()
        start = content.find(MARKER_BEGIN)
        end = content.find(MARKER_END)
        if start != -1 and end != -1:
            content = (content[:start] + content[end + len(MARKER_END):]).strip()
            if content:
                with open(paths.rule, "w", encoding="utf-8") as f:
                    f.write(content + "\n")
                print(" [-] Removed rule from: {}".format(paths.rule))
            else:
                os.remove(paths.rule)
                print(" [-] Removed empty file: {}".format(paths.rule))
        else:
            print(" [=] No auto-mode rule found in: {}".format(paths.rule))

    # 3. Restore the previous permission settings
    settings = read_settings(paths.settings)
    if settings is None:
        print(" [=] No settings file to restore.")
    else:
        previous = read_settings(paths.backup) or {}
        for key in AUTO_MODE_SETTINGS:
            if key in previous:
                settings[key] = previous[key]
            else:
                settings.pop(key, None)
        if not settings and not previous:
            # The installer created this file; nothing is left in it.
            os.remove(paths.settings)
            print(" [-] Removed empty file: {}".format(paths.settings))
        else:
            write_settings(paths.settings, settings)
            print(" [-] Restored permissions in: {}".format(paths.settings))
        if os.path.exists(paths.backup):
            os.remove(paths.backup)

    print("\n[OK] Auto-Mode removed.")


def main():
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        print((__doc__ or "").strip())
        return
    paths = Paths()
    if not args:
        install(paths)
    elif args[0] == "--revert":
        revert(paths)
    else:
        sys.exit("[!] Unknown option: {} (use --help)".format(args[0]))


if __name__ == "__main__":
    main()
