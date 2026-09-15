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

import json
import os
import sys
import tempfile

MARKER_BEGIN = "<!-- BEGIN agy-auto-mode -->"
MARKER_END = "<!-- END agy-auto-mode -->"

STATE_VERSION = 1

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


class AbortError(Exception):
    """Bad input found while planning, before anything has been written."""


class ApplyError(Exception):
    """A filesystem error hit midway through applying a plan."""


class Paths:
    """Every file the installer touches.

    ``gemini_dir`` is injectable so the test suite can point a whole install
    at a temporary directory.
    """

    def __init__(self, gemini_dir=None):
        if gemini_dir is None:
            gemini_dir = os.path.join(os.path.expanduser("~"), ".gemini")
        self.gemini_dir = gemini_dir
        self.agents_dir = os.path.join(gemini_dir, "config", "agents")
        self.cli_dir = os.path.join(gemini_dir, "antigravity-cli")
        self.agent = os.path.join(self.agents_dir, "safety-reviewer.md")
        self.rule = os.path.join(gemini_dir, "GEMINI.md")
        self.rule_backup = os.path.join(gemini_dir, "GEMINI.md.auto-mode.bak")
        self.settings = os.path.join(self.cli_dir, "settings.json")
        self.backup = os.path.join(self.cli_dir, "settings.json.auto-mode.bak")
        self.state = os.path.join(self.cli_dir, "auto-mode-state.json")


class Action:
    """One planned change: write a file, or remove one."""

    def __init__(self, op, path, content=None, message=""):
        self.op = op  # "write" or "remove"
        self.path = path
        self.content = content
        self.message = message


# --------------------------------------------------------------------------
# Filesystem helpers
# --------------------------------------------------------------------------

def read_text(path):
    """Return the file's text, or None when it does not exist.

    Any other read problem (a directory in the way, bad permissions) aborts
    the run while it is still safe to abort.
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise AbortError("cannot read {}: {}".format(path, exc.strerror or exc))
    except UnicodeDecodeError:
        raise AbortError("{} is not valid UTF-8 text.".format(path))


def atomic_write(path, content):
    """Write via a temp file in the same directory, then rename into place.

    An interrupted run can then leave the old file or the new one, never a
    half-written one.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    handle_fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".auto-mode-", suffix=".tmp")
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temp_path, path)
    except BaseException:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def remove_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def parse_settings(path, raw):
    """Parse settings text into a dict, or None when the file is absent."""
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise AbortError(
            "{} is not valid JSON ({}).\n"
            "    Fix or remove the file, then run this script again.".format(path, exc)
        )
    if not isinstance(parsed, dict):
        raise AbortError("{} does not contain a JSON object.".format(path))
    return parsed


def dump_json(data):
    return json.dumps(data, indent=2) + "\n"


def read_state(paths):
    """Return the installer's own state record, or None when not installed."""
    raw = read_text(paths.state)
    if raw is None:
        return None
    try:
        state = json.loads(raw)
    except ValueError:
        return None
    return state if isinstance(state, dict) else None


# --------------------------------------------------------------------------
# GEMINI.md rule block
# --------------------------------------------------------------------------

def find_block(content):
    """Return (start, end) of the marked rule block, or None when absent.

    The end marker is searched for *after* the begin marker, so a stray end
    marker earlier in the file cannot produce a nonsense slice.
    """
    start = content.find(MARKER_BEGIN)
    if start == -1:
        return None
    if content.count(MARKER_BEGIN) > 1:
        raise AbortError(
            "found more than one '{}' marker in GEMINI.md.\n"
            "    Remove the extra block by hand, then run this script again.".format(MARKER_BEGIN)
        )
    end = content.find(MARKER_END, start)
    if end == -1:
        raise AbortError(
            "GEMINI.md has a '{}' marker with no matching '{}'.\n"
            "    Repair the file by hand, then run this script again.".format(MARKER_BEGIN, MARKER_END)
        )
    return start, end + len(MARKER_END)


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------

def plan_install(paths):
    """Read and validate everything, then return (actions, notes).

    Nothing is written during planning, so a bad GEMINI.md or settings.json
    aborts the run with the config still untouched.
    """
    actions = []
    notes = []

    settings_raw = read_text(paths.settings)
    settings = parse_settings(paths.settings, settings_raw)
    rule_raw = read_text(paths.rule)
    agent_raw = read_text(paths.agent)
    state = read_state(paths)
    rule_span = find_block(rule_raw) if rule_raw is not None else None

    if state is None:
        created = set()
        if rule_raw is None:
            created.add("rule")
        if settings_raw is None:
            created.add("settings")
    else:
        created = set(state.get("created", []))

    # 1. The safety-reviewer subagent.
    if agent_raw == AGENT_MD:
        notes.append(" [=] Subagent already up to date: {}".format(paths.agent))
    else:
        verb = "Installed" if agent_raw is None else "Updated"
        actions.append(Action("write", paths.agent, AGENT_MD,
                              " [+] {} subagent: {}".format(verb, paths.agent)))

    # 2. The GEMINI.md rule, inside removable markers.
    if rule_raw is None:
        new_rule = RULE_BLOCK
        message = " [+] Created global rule: {}".format(paths.rule)
    elif rule_span is None:
        head = rule_raw.rstrip("\n")
        new_rule = (head + "\n\n" if head else "") + RULE_BLOCK
        message = " [+] Appended rule to: {}".format(paths.rule)
    else:
        start, end = rule_span
        new_rule = rule_raw[:start] + RULE_BLOCK.rstrip("\n") + rule_raw[end:]
        message = " [+] Updated rule in: {}".format(paths.rule)

    if new_rule == rule_raw:
        notes.append(" [=] Rule already up to date: {}".format(paths.rule))
    else:
        # Back up the user's own GEMINI.md, but only the pristine one.
        if rule_raw is not None and rule_span is None and not os.path.exists(paths.rule_backup):
            actions.append(Action("write", paths.rule_backup, rule_raw,
                                  " [+] Saved backup: {}".format(paths.rule_backup)))
        actions.append(Action("write", paths.rule, new_rule, message))

    # 3. Permissions, with a backup so --revert can put the old values back.
    if settings is None:
        settings = {}
    elif state is None and not os.path.exists(paths.backup):
        actions.append(Action("write", paths.backup, settings_raw,
                              " [+] Saved backup: {}".format(paths.backup)))

    new_settings = dict(settings)
    new_settings.update(AUTO_MODE_SETTINGS)
    new_settings_raw = dump_json(new_settings)
    if new_settings_raw == settings_raw:
        notes.append(" [=] Permissions already set in: {}".format(paths.settings))
    else:
        actions.append(Action("write", paths.settings, new_settings_raw,
                              " [+] Configured auto-mode in: {}".format(paths.settings)))

    # 4. Record what we created, so --revert knows what it may delete.
    state_raw = dump_json({"version": STATE_VERSION, "created": sorted(created)})
    if state_raw != read_text(paths.state):
        actions.append(Action("write", paths.state, state_raw, None))

    return actions, notes


def plan_revert(paths):
    """Return (actions, notes) that undo an install."""
    actions = []
    notes = []

    state = read_state(paths)
    if state is None:
        # A pre-state-file install, or none at all. A missing backup is the
        # only evidence that the installer created the file itself.
        created = set()
        if not os.path.exists(paths.backup):
            created.add("settings")
        if not os.path.exists(paths.rule_backup):
            created.add("rule")
    else:
        created = set(state.get("created", []))

    # 1. The subagent.
    if os.path.exists(paths.agent):
        actions.append(Action("remove", paths.agent,
                              message=" [-] Removed subagent: {}".format(paths.agent)))
    else:
        notes.append(" [=] Subagent not installed.")

    # 2. The rule block, leaving the rest of GEMINI.md alone.
    rule_raw = read_text(paths.rule)
    if rule_raw is None:
        notes.append(" [=] No GEMINI.md to clean up.")
    else:
        span = find_block(rule_raw)
        if span is None:
            notes.append(" [=] No auto-mode rule found in: {}".format(paths.rule))
        else:
            start, end = span
            remaining = (rule_raw[:start] + rule_raw[end:]).rstrip("\n")
            if remaining:
                actions.append(Action("write", paths.rule, remaining + "\n",
                                      " [-] Removed rule from: {}".format(paths.rule)))
            elif "rule" in created:
                actions.append(Action("remove", paths.rule,
                                      message=" [-] Removed empty file: {}".format(paths.rule)))
            else:
                actions.append(Action("write", paths.rule, "",
                                      " [-] Removed rule from: {}".format(paths.rule)))

    # 3. The permission keys.
    settings = parse_settings(paths.settings, read_text(paths.settings))
    if settings is None:
        notes.append(" [=] No settings file to restore.")
    else:
        previous = parse_settings(paths.backup, read_text(paths.backup))
        restored = dict(settings)
        for key in AUTO_MODE_SETTINGS:
            if previous is not None and key in previous:
                restored[key] = previous[key]
            else:
                restored.pop(key, None)
        if not restored and "settings" in created:
            actions.append(Action("remove", paths.settings,
                                  message=" [-] Removed empty file: {}".format(paths.settings)))
        else:
            restored_raw = dump_json(restored)
            if restored_raw == dump_json(settings):
                notes.append(" [=] No auto-mode permissions found in: {}".format(paths.settings))
            else:
                actions.append(Action("write", paths.settings, restored_raw,
                                      " [-] Restored permissions in: {}".format(paths.settings)))

    # 4. The installer's own bookkeeping.
    for path in (paths.backup, paths.rule_backup, paths.state):
        if os.path.exists(path):
            actions.append(Action("remove", path, message=None))

    return actions, notes


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

def apply_actions(actions):
    for action in actions:
        try:
            if action.op == "write":
                atomic_write(action.path, action.content)
            else:
                remove_file(action.path)
        except OSError as exc:
            raise ApplyError("cannot write {}: {}".format(action.path, exc.strerror or exc))
        if action.message:
            print(action.message)


def run(paths, header, planner, footer):
    print(header)
    actions, notes = planner(paths)
    for note in notes:
        print(note)
    apply_actions(actions)
    print(footer)


def install(paths):
    run(
        paths,
        "[*] Setting up agy Auto-Mode with Flash Safety Reviewer...",
        plan_install,
        "\n[OK] Auto-Mode setup complete! All agy sessions (interactive & -p) are now guarded by Flash."
        "\n     Undo with: python setup_auto_mode.py --revert",
    )


def revert(paths):
    run(paths, "[*] Removing agy Auto-Mode...", plan_revert, "\n[OK] Auto-Mode removed.")


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if args and args[0] in ("-h", "--help"):
        print((__doc__ or "").strip())
        return 0

    paths = Paths()
    try:
        if not args:
            install(paths)
        elif args[0] == "--revert":
            revert(paths)
        else:
            sys.stderr.write("[!] Unknown option: {} (use --help)\n".format(args[0]))
            return 2
    except AbortError as exc:
        sys.stderr.write("[!] {}\n    Nothing was changed.\n".format(exc))
        return 1
    except ApplyError as exc:
        sys.stderr.write(
            "[!] {}\n"
            "    The install is incomplete. Fix the problem and run this script again.\n".format(exc)
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
