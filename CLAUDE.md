# CLAUDE.md

Notes for agents working in this repo. The README is for people who install
the gate; this file holds what you need to change it safely, and what is not
obvious from the code.

## What this is

A PreToolUse permission gate for coding agents, backed by TypeSafe's Jev
model. Two targets share one gate program:

- **agy** (Antigravity CLI): `~/.gemini/config/hooks.json`.
- **copilot** (GitHub Copilot agent mode in VS Code, and Copilot CLI):
  `~/.copilot/hooks/jev-gate.json`, gate in `~/.copilot/jev-gate/`.

| File | Role |
| --- | --- |
| `jev_gate.py` | The gate. Reads one hook event on stdin, prints a decision. |
| `setup_auto_mode.py` | Installer: plans every change first, then writes. Install, `--status`, `--revert`, `--dry-run`. |
| `test_jev_gate.py`, `test_setup_auto_mode.py` | Unit tests. No network, no SDK. |
| `docs/review-notes.md` | History of an earlier review and its dispositions. |

For Jev or TypeSafe SDK code, use the `typesafe:typesafe-ai` skill.

## Commands

```
python -m pytest -q                                   # all tests, ~7 s
python setup_auto_mode.py --target copilot            # reinstall the Copilot gate
python setup_auto_mode.py --target copilot --status
python jev_gate.py --copilot --check EVENT.json       # judge one saved event with real Jev
```

The installed gate is a **copy**. After you change `jev_gate.py`, reinstall,
then reload VS Code. The installed copy has CRLF line endings, so a plain
`diff` reports every line; use `diff --strip-trailing-cr`.

## Invariants

- **Fail closed.** A missing key, a network error, a bad event or an
  exception gives `deny`. In `--copilot` mode a crash exits 2, because VS Code
  runs the call after any other exit code.
- **`allow` only for calls Jev judged.** A tool not in `GUARDED_TOOLS` /
  `COPILOT_GUARDED_TOOLS` gets no decision, so the agent's own approval
  applies. Never `allow` a tool nobody judged.
- **Assessment and policy are separate.** `HAZARDS`/`SEVERITY` define what
  Jev is asked; `Policy` and `decide()` define what the numbers mean.
  `decide()` is pure; keep it that way.
- **Tests never touch the network.** Inject the asker (`review(asker=...)`,
  or patch `gate.ask_jev`).
- **The installer only touches files it owns.** VS Code reads every `*.json`
  in `~/.copilot/hooks/`, so the gate itself lives outside that folder. Keep
  other users' hook files and key files intact.

## Copilot hook contract (learned, partly undocumented)

- VS Code reads only `hookSpecificOutput` for PreToolUse. Copilot CLI reads
  the top-level `permissionDecision`. The gate writes both.
- `permissionDecisionReason` is shown to the **user**. `additionalContext`
  (inside `hookSpecificOutput`) goes to the **model**. The CLI has no
  `additionalContext`, so its top-level reason also carries the guidance.
- Tool names vary by release; `is_guarded()` ignores case, `_` and `-`. MCP
  tools carry a server prefix (`mcp_pylance_mcp_s_pylanceRunCodeSnippet`), so
  list both spellings.
- **The "rethink" step:** a `force_ask` first becomes a deny with
  `additionalContext` that asks the agent for a safer way. The same call again
  (same session, tool and input, ignoring `DESCRIPTIVE_FIELDS`) within
  `RETHINK_TTL` goes to the user without calling Jev. State is in
  `rethink-state.json` next to the gate (`JEV_GATE_STATE_FILE` overrides it).
  If the state cannot be written, the gate asks the user at once, so the
  agent cannot loop. `JEV_GATE_RETHINK=0` turns this off.

## Latency: do not chase the 1.6 s

On Windows, VS Code runs every hook as `powershell.exe -ExecutionPolicy
Bypass -NoProfile -NoLogo -Command <command>` (function near `process.env.ComSpec`
in the bundled `resources/app/extensions/copilot/dist/extension.js`). That
start alone is ~1.4 s, for every tool call, reads included. No hook property
changes the shell. The gate's own cost is ~0.25 s, most of it Python start.
Keep imports in the unguarded path cheap (`hashlib`, `time`, the SDK are
imported lazily), but there is little left to win.

## Changing the questions: test against real Jev

Unit tests cannot tell you whether a wording works. Before you change a
hazard's instructions or criteria:

1. Load the key without printing it:
   `export $(grep '^TYPESAFE_API_KEY=' ~/.copilot/jev-gate/jev_gate.env | tr -d '\r')`
2. Save the real event (from the transcript, see below) as JSON. Write it with
   Python, not a heredoc: the shell mangles Windows backslashes.
3. Score each variant 3–5 times. Scores vary by about ±0.02 between runs.
4. Score clearly risky calls too (copy to a sibling folder, `~/.bashrc`, a
   SharePoint path, a snippet that writes to Documents). A wording that
   lowers false positives must keep these near the top.

Put scratch scripts in the session scratchpad, not in the repo.

What was learned so far:

- Asking about effects the text cannot show (a test run's temp files) makes
  Jev guess near the threshold. Ask about what the call **names**.
- Naming an extra allowed location in the instructions can **raise** the
  score, because it primes Jev to think about writes. Measure; do not assume.

## Debugging a Copilot session

- Hook log, per VS Code window:
  `%APPDATA%\Code\logs\<session>\window<N>\exthost\GitHub.copilot-chat\GitHub Copilot Chat Hooks.log`.
  One `[#n]` per hook run: tool name, duration, output. It redacts
  `tool_input` to `"..."`.
- Full tool inputs and timing are in the transcript:
  `%APPDATA%\Code\User\workspaceStorage\<hash>\GitHub.copilot-chat\transcripts\<session_id>.jsonl`
  (the path is in every hook input). Match a hook run to a call by
  `tool_use_id` = `toolCallId`. Transcript times are UTC; the hook log uses
  local time.
- A long gap between a `tool.execution_start` and its `tool.execution_complete`
  is a permission prompt waiting for the user. "no output" in the hook log
  means the gate gave no decision, so VS Code's own approval applied.
- `JEV_GATE_AUDIT_LOG=<path>` in `jev_gate.env` logs every probability.
- Copilot CLI logs are in `~/.copilot/logs/`.

## Commits

Short subject; a body only where the why is not obvious from the diff.
