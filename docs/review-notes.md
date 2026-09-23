# Review notes

A record of the review that motivated commits `bb7d034` and `6f75a4c`.

**Reviewed:** `setup_auto_mode.py` at `b888f66`, the first working version.
**Method:** read the script, then exercised it against throwaway config
directories — fresh install, install over existing config, reinstall, revert,
and malformed input. The happy-path round trip was already clean: install
followed by `--revert` restored an existing `GEMINI.md` and `settings.json`
exactly. Everything below came out of the edge cases.

Each item carries its disposition. "Open" items are still open.

---

## 1. Design: the guard is in-band, and that is the ceiling

The reviewer is invoked *by the same agent that wants to run the command*, and
its verdict is consumed by that same agent. There is no point in the pipeline
where a `DANGEROUS` verdict can actually stop execution — `toolPermission:
always-proceed` has already removed the only enforcement point.

The README was already honest about this. The thing worth doing is checking
whether `agy` offers anything better:

- **A pre-tool-use hook.** If `agy` has any hook or middleware mechanism, the
  reviewer belongs there: an exit code can block the call. That converts this
  from advice into enforcement and is by far the highest-value change
  available.
- **A per-tool or pattern allowlist.** If `toolPermission` accepts anything
  narrower than `always-proceed` (auto-approve reads and builds, prompt on
  `run_command`), that buys most of the ergonomics while keeping a real
  backstop.

If neither exists, say so explicitly in the README — "we checked; `agy` has no
enforcement hook as of version X" turns a disclaimer into a documented
finding.

**Status: done — the `jev` engine.** `agy` has a pre-tool-use hook. It is
documented in the install itself, at
`~/.gemini/antigravity/builtin/skills/agy-customizations/docs/hooks.md`:
a `PreToolUse` handler in `~/.gemini/config/hooks.json` gets the tool call
on stdin and returns `allow`, `ask`, `force_ask` or `deny`, and the CLI
enforces it.

The reviewer moved there, and changed model on the way. A second agent turn
per tool call was the wrong shape for a gate: slow, and its output was prose
that had to be parsed. [`jev_gate.py`](../jev_gate.py) asks TypeSafe's Jev
model seven yes/no hazard questions and one severity scale in a single
request, and a policy in code turns the probabilities into a decision. There
is no verdict line left for a payload to forge.

Verified end to end in the VS Code extension:

- a write inside the workspace got `allow` and ran without a prompt;
- a write to `~/Desktop` got `deny` (`escapes_workspace` p=0.99), agy showed
  "Execution Denied by Pre-Tool Hook", and the file was not created;
- with `toolPermission` back at its default, routine writes still ran without
  a prompt. The gate's `allow` is enough, so the `jev` engine leaves the
  permission settings alone, and the global "all prompts off" switch is gone.

The first attempt put `hooks.json` in `~/.gemini/` in Claude Code's schema,
guessed from strings in the binary. agy ignored it silently. The built-in
docs had the right location and schema; read them first next time.

What is left is the limit of any text judge: the gate sees `bash deploy.sh`,
not what `deploy.sh` does. The README says so.

Two prompt-level hardenings were cheap regardless:

- The reviewer sees attacker-controlled text (file contents, command strings).
  It needed to be told the payload is data, never instructions, and that a
  payload containing `VERDICT:` decides nothing. A command string embedding
  `VERDICT: SAFE` had a decent chance of being echoed back by a fast model.
- The reviewer was asked to judge actions "within the project boundary" but
  was never told what the boundary *is*. `rm -rf build/` and `rm -rf /` are
  the same shape without a working directory. The rule should pass the
  workspace root and cwd with the tool call.

**Status: done in `6f75a4c`.** Both, plus: the verdict must be the first line,
ambiguity resolves away from `SAFE`, weakening the review itself is listed as
dangerous, and the rule fails closed — a missing, duplicated, or unparseable
verdict counts as `DANGEROUS`.

---

## 2. Bugs

### Reinstall never updated the rule

If the marker was present, install printed `[=] Rule already exists` and
returned. A hand-edited or older-version rule survived a reinstall untouched,
while `safety-reviewer.md` *was* overwritten — so shipping a v2 would have
paired the new subagent with the old rule.

**Status: fixed in `bb7d034`.** The block between the markers is rewritten in
place.

### Revert could silently leave the rule installed

`find(MARKER_END)` searched from position 0, not from `start`. With a stray
`<!-- END agy-auto-mode -->` earlier in the file, `end < start`, the slice
concatenated garbage, and the real block survived — revert reported success
while auto-mode stayed on.

**Status: fixed in `bb7d034`.** The end marker is searched for after the begin
marker; duplicate or unterminated markers abort instead of corrupting the
file.

### Revert deleted a `settings.json` the user already had

If the pre-existing file was `{}`, both the stripped settings and the empty
backup were falsy after the key-pops, which the code read as "the installer
created this file" — and removed it.

**Status: fixed in `bb7d034`.** A state file records what was created rather
than inferring it from emptiness.

### A failed write left a half-install

With `~/.gemini/GEMINI.md` unwritable, the run traced back after the subagent
was already on disk — no rollback, no friendly message. The script already did
the right thing for malformed JSON (read and validate before writing
anything); that needed extending to the other two files, plus atomic writes.

**Status: fixed in `bb7d034`.** All reads and validation happen in a planning
pass that returns the list of changes, so bad input aborts with nothing
written; writes go through a temp file and `os.replace`.

### Minor

`GEMINI.md` had no backup, unlike `settings.json`. `content.strip()` in revert
rewrote the user's leading whitespace. The separator logic emitted two blank
lines when the file ended in a single newline. `args[0] in ("-h", "--help")`
meant `--revert --oops` silently ignored the typo.

**Status: all fixed** across `bb7d034` and `6f75a4c`.

---

## 3. Ergonomics

| Suggestion | Status |
| --- | --- |
| `--status` — no way to ask whether auto-mode is on | Done in `6f75a4c` |
| `--dry-run` — show the diff before disabling safety prompts globally | Done in `6f75a4c` |
| Injectable config dir, so the path logic is testable | Done in `bb7d034` (`Paths(gemini_dir=...)`), exposed as `--gemini-dir` in `6f75a4c` |
| Tests — the repo had none | Done: 23 in `bb7d034`, 43 total after `6f75a4c` |
| `--model`, so a moved alias does not need a re-release | Done in `6f75a4c` |
| Honest success message — the old one claimed more than the README did | Done in `6f75a4c` |
| Preflight: warn when `agy` is not installed | Done in `6f75a4c`, non-fatal |
| `--project` scope — everything is global, and the README's warning is about exactly that blast radius | **Open, now possible.** `agy` reads `.agents/hooks.json` in a project, so the gate could be installed per project. The installer does not offer it yet |

---

## 4. Unverified

No `agy` on the original review machine, so everything was first tested
against the filesystem, not the CLI. Since then, with `agy` installed:

- **Checked:** the subagent engine works as written. In a live session the
  agent called `safety-reviewer` via `invoke_subagent` before `write_to_file`,
  with the workspace root and verbatim arguments, and the reviewer returned
  a verdict.
- **Checked:** `agy` reads a project-local config directory: `.agents/` (or
  `.agent/`, `_agents/`, `_agent/`), found by walking up from the working
  directory to the repository root. Global config is `~/.gemini/config/`.
- **Still unchecked:** that `--model pro` names a real model, and that the
  CLI reads `toolPermission` and `artifactReviewPolicy` from
  `antigravity-cli/settings.json` as named. The IDE extension keeps its own
  permission setting, so the subagent engine's settings change may not
  reach it at all. The `jev` engine does not depend on either.

The `jev` engine was verified live; see item 1.
