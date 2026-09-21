# agy-auto-mode

An "auto-mode" for the Google Antigravity CLI (`agy`).

The installer does three things:

1. Installs a `safety-reviewer` subagent that runs on the fast Flash model.
2. Adds a global `GEMINI.md` rule. The rule tells the main agent to ask the
   reviewer before each state-changing tool call, to hand it the workspace
   root and the exact unparaphrased arguments, and to treat anything other
   than a first-line `VERDICT: SAFE` as a refusal.
3. Sets `toolPermission` and `artifactReviewPolicy` to `always-proceed`, so the
   CLI stops asking you to confirm each tool call.

The result: the agent keeps working without confirmation prompts, and a cheap
model looks at each command first.

## WARNING — read this before you install

**This tool turns off all tool-confirmation prompts, for every project on your
machine.** After the install, `agy` can run commands and edit files without
asking you.

**The only guard is an instruction in a prompt. Nothing enforces it in code.**
The main model can ignore the rule, or forget it in a long session. The Flash
reviewer can also be wrong. This is not a sandbox and it is not a security
control.

The reviewer is invoked *by* the agent that wants to run the command, and its
verdict is read by that same agent, so a `DANGEROUS` verdict cannot stop
anything on its own. If `agy` ever exposes a pre-tool-use hook, that is where
this belongs; until then the prompt rule is the most that can be done. The
prompts are written to fail closed (an unparseable or missing verdict counts
as `DANGEROUS`) and to treat command text and file contents as data rather
than instructions, but that too is a prompt, not a mechanism.

Use this only in an environment where you accept that risk. Examples: a
container, a virtual machine, or a scratch working copy that you can delete.

## Requirements

- Python 3.6 or later. No packages to install.
- The Google Antigravity CLI (`agy`).

## Install

```
python setup_auto_mode.py
```

On WSL, Linux, or macOS use `python3`.

Reinstalling is safe and is how you upgrade: the subagent and the rule block
are rewritten in place, and your original backups are kept.

## Uninstall

```
python setup_auto_mode.py --revert
```

The revert step removes the subagent file, removes the rule block from
`GEMINI.md`, and puts back your previous permission settings.

## Options

| Flag | Effect |
| --- | --- |
| `--status` | Report what is installed, without changing anything |
| `--dry-run` | Show the changes an install or revert would make, and write nothing |
| `--model NAME` | Run the reviewer on a different model (default: `flash`) |
| `--gemini-dir DIR` | Install into another config directory instead of `~/.gemini` |
| `--revert` | Undo the install |

`--gemini-dir` also reads `$AGY_GEMINI_DIR`. Point it at a project-local
config directory if your `agy` version looks for one — the installer only
writes where you tell it to, and does not itself know which directories the
CLI reads.

Exit codes: `0` success (for `--status`, fully installed), `1` not installed
or aborted, `2` partially installed.

```
$ python3 setup_auto_mode.py --status
[*] agy Auto-Mode status for /home/you/.gemini
 [+] subagent installed
 [+] rule block present in GEMINI.md
 [+] confirmation prompts are OFF

[OK] Auto-Mode is installed.
```

## Files that the installer changes

| Path | Change |
| --- | --- |
| `~/.gemini/config/agents/safety-reviewer.md` | Created (rewritten on reinstall) |
| `~/.gemini/GEMINI.md` | A marked block is appended (rewritten in place on reinstall) |
| `~/.gemini/GEMINI.md.auto-mode.bak` | Backup of your rule file |
| `~/.gemini/antigravity-cli/settings.json` | Two keys are set |
| `~/.gemini/antigravity-cli/settings.json.auto-mode.bak` | Backup of your settings |
| `~/.gemini/antigravity-cli/auto-mode-state.json` | Records which files the installer created |

The rule block sits between `<!-- BEGIN agy-auto-mode -->` and
`<!-- END agy-auto-mode -->` markers. The rest of your `GEMINI.md` is not
touched.

Backups are taken once, from your pristine files, and are left alone by a
reinstall. The state file is what lets `--revert` tell a `settings.json` you
already had from one the installer created: only the second kind is deleted.

The installer reads and checks every file before it writes any of them, so bad
input (`settings.json` that is not valid JSON, a `GEMINI.md` it cannot read, or
one with mismatched markers) stops the run with nothing changed. Writes go to a
temporary file and are renamed into place, so an interrupted run leaves either
the old file or the new one, never half of either.

## Tests

```
python3 -m unittest discover
```

The suite installs into throwaway directories; it never touches your real
`~/.gemini`.

## Design notes

[docs/review-notes.md](docs/review-notes.md) records the review that motivated
the current implementation: what was wrong, what was fixed, and what is still
open — including why the safety reviewer cannot block a command on its own.

## License

MIT. See [LICENSE](LICENSE).
