# agy-auto-mode

An "auto-mode" for the Google Antigravity CLI and IDE extension (`agy`): the
agent keeps working without a confirmation prompt for routine work, and a
safety check looks at each state-changing tool call first.

There are two engines. Use the first one.

**`jev` (default).** A `PreToolUse` hook runs [`jev_gate.py`](jev_gate.py)
before each state-changing tool call. The gate asks TypeSafe's
[Jev](https://docs.typesafe.ai) model one batch of typed questions about the
call, applies a policy written in code, and returns a decision. **agy enforces
that decision:** `deny` blocks the call, and the agent cannot talk its way
past it.

**`subagent` (the original design).** A Flash `safety-reviewer` subagent, a
global `GEMINI.md` rule that tells the agent to consult it, and permission
settings that switch confirmation prompts off. The agent asks the reviewer
and reads the verdict itself, so the review is advice, not a control.

## How the Jev gate decides

For each guarded call, the gate sends the workspace root, the working
directory, the tool name, and the verbatim arguments to Jev, with seven
yes/no questions and one scale:

| Question | Asks whether the call… |
| --- | --- |
| `escapes_workspace` | writes, moves or deletes outside the workspace |
| `destructive` | destroys work that cannot be recovered |
| `system_change` | changes the machine outside the workspace |
| `secret_exposure` | reads, prints or sends credentials |
| `remote_code` | runs code fetched from the network, or hides what it runs |
| `weakens_guard` | edits or evades this safety check |
| `injection_attempt` | contains text that tries to steer the check |
| `blast_radius` | (scale) how far the damage reaches if the call is wrong |

Jev returns a probability for each question. The policy in `jev_gate.py`
turns those numbers into one of three decisions:

| Decision | When | What agy does |
| --- | --- | --- |
| `allow` | every hazard is low | runs the call, no prompt |
| `force_ask` | a hazard is in the middle band | prompts you, even if you chose "Always Allow" before |
| `deny` | a hazard is high, or the blast radius leaves the workspace | blocks the call and shows the reason |

Anything that goes wrong — no API key, a network error, a timeout, a payload
the gate cannot read — gives `deny`. Tools the gate does not judge (reads,
browser actions) are not sent to the gate; agy's normal permission rules
apply to them. With default permissions, agy asks before a read outside the
workspace.

The thresholds are in the `Policy` class. `JEV_GATE_POLICY=strict` makes
every threshold tighter.

## WARNING — read this before you install

**The gate judges the text of a tool call, not its effects.** `bash
deploy.sh` looks harmless; the gate does not read `deploy.sh`. Jev is a
general judgment model, not a shell-safety model, and it can be wrong. This
is not a sandbox. Use it where a wrong call costs you a scratch checkout, not
a production system.

**Every guarded tool call now waits for a network round trip.** agy starts a
new process for each hook call, so expect roughly one to three seconds per
guarded call.

**The command text goes to TypeSafe.** Each guarded call sends its arguments —
command lines, file paths, and the full content of file writes — to the
TypeSafe API.

The `subagent` engine is weaker than all of this: it switches off every
confirmation prompt for every project on the machine, and the only guard is
an instruction in a prompt that the main model can ignore.

## Requirements

- Python 3.6 or later. The installer itself needs no packages.
- The Google Antigravity CLI or IDE extension (`agy`).
- For the `jev` engine: `pip install typesafe-sdk`, and a TypeSafe API key
  from the [TypeSafe console](https://console.typesafe.ai/).

## Install

```
pip install typesafe-sdk
export TYPESAFE_API_KEY=...        # PowerShell: $env:TYPESAFE_API_KEY = "..."
python setup_auto_mode.py
```

On WSL, Linux, or macOS use `python3`.

The installer copies the key into `~/.gemini/config/hooks/jev_gate.env`,
because agy starts hooks with its own environment. If the key is not set when
you install, create that file yourself with one line:
`TYPESAFE_API_KEY=<key>`. Then reload any open agy session.

To check that the gate runs, add `JEV_GATE_AUDIT_LOG=<path>` to the same file.
The gate then writes one JSON line per judged call, with every probability.
That log is also what you tune the thresholds from.

Reinstalling is safe and is how you upgrade: the hook entry and the gate are
rewritten in place, and a key file you made yourself is never touched.

To install the old engine instead: `python setup_auto_mode.py --engine subagent`.
Only one engine can be installed at a time; `--revert` the other one first.

## Uninstall

```
python setup_auto_mode.py --revert
```

Revert detects which engine is installed. For `jev` it removes the `jev-gate`
entry from `hooks.json` (other hooks stay), removes the gate, and removes the
key file only if the installer created it. For `subagent` it removes the
subagent file and the rule block, and puts back your previous permission
settings.

## Options

| Flag | Effect |
| --- | --- |
| `--engine jev\|subagent` | What to install (default: `jev`) |
| `--status` | Report what is installed, without changing anything |
| `--dry-run` | Show the changes an install or revert would make, and write nothing |
| `--python CMD` | `jev`: the interpreter agy runs the gate with (default: `python`, or `python3` off Windows). It needs `typesafe-sdk` |
| `--model NAME` | `subagent`: run the reviewer on a different model (default: `flash`) |
| `--gemini-dir DIR` | Install into another config directory instead of `~/.gemini` |
| `--revert` | Undo the install |

`--gemini-dir` also reads `$AGY_GEMINI_DIR`.

Exit codes: `0` success (for `--status`, fully installed), `1` not installed
or aborted, `2` partially installed.

```
$ python setup_auto_mode.py --status
[*] agy Auto-Mode status (jev engine) for C:\Users\you\.gemini
 [+] 'jev-gate' hook present in hooks.json
 [+] gate installed
 [+] API key found in jev_gate.env

[OK] Auto-Mode is installed.
```

## Files that the installer changes

`jev` engine:

| Path | Change |
| --- | --- |
| `~/.gemini/config/hooks.json` | A `jev-gate` entry is added; other hooks are kept |
| `~/.gemini/config/hooks/jev_gate.py` | Copy of the gate (rewritten on reinstall) |
| `~/.gemini/config/hooks/jev_gate.env` | Your API key, only if absent and the key is in the environment |
| `~/.gemini/antigravity-cli/auto-mode-state.json` | Records the engine and which files the installer created |

The `jev` engine does not change `settings.json` or `GEMINI.md`.

`subagent` engine:

| Path | Change |
| --- | --- |
| `~/.gemini/config/agents/safety-reviewer.md` | Created (rewritten on reinstall) |
| `~/.gemini/GEMINI.md` | A marked block is appended (rewritten in place on reinstall) |
| `~/.gemini/GEMINI.md.auto-mode.bak` | Backup of your rule file |
| `~/.gemini/antigravity-cli/settings.json` | Two keys are set |
| `~/.gemini/antigravity-cli/settings.json.auto-mode.bak` | Backup of your settings |
| `~/.gemini/antigravity-cli/auto-mode-state.json` | Records the engine and which files the installer created |

The rule block sits between `<!-- BEGIN agy-auto-mode -->` and
`<!-- END agy-auto-mode -->` markers. The rest of your `GEMINI.md` is not
touched.

The installer reads and checks every file before it writes any of them, so bad
input (a `settings.json` or `hooks.json` that is not valid JSON, a `GEMINI.md`
it cannot read, or one with mismatched markers) stops the run with nothing
changed. Writes go to a temporary file and are renamed into place, so an
interrupted run leaves either the old file or the new one, never half of
either.

## The hook contract

agy documents its hooks in its own install:
`~/.gemini/antigravity/builtin/skills/agy-customizations/docs/hooks.md`. The
parts this project depends on:

- Global hooks live in `~/.gemini/config/hooks.json`; a project can have its
  own in `.agents/hooks.json`.
- Top-level keys are hook names. `PreToolUse` handlers have a `matcher`
  regex over tool names, and run through `cmd /c` on Windows or `sh -c`
  elsewhere.
- The handler gets camelCase JSON on stdin (`toolCall.name`, `toolCall.args`,
  `workspacePaths`) and prints `{"decision": "...", "reason": "..."}`.

[docs/hooks.example.json](docs/hooks.example.json) shows the entry the
installer writes, for a manual install.

## Tests

```
python -m unittest discover
```

The suite installs into throwaway directories and never touches your real
`~/.gemini`. The gate tests never call the network: the policy is a pure
function of the answers, and the Jev call is injected.

## Design notes

[docs/review-notes.md](docs/review-notes.md) records the review that shaped
this project: the original bugs, why the subagent could not block a command,
and how the Jev hook closed that gap.

## License

MIT. See [LICENSE](LICENSE).
