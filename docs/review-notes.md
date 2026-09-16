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

**Status: open.** Neither could be checked — no `agy` on the machine the
review ran on. The README now explains why the verdict cannot block on its
own, but the enforcement point is still missing.

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
| `--project` scope — everything is global, and the README's warning is about exactly that blast radius | **Partly.** `--gemini-dir` writes wherever it is pointed, but whether `agy` reads a project-local config directory was never verified |

---

## 4. Unverified

No `agy` on the review machine, so everything was tested against the
filesystem, not the CLI. Still unchecked:

- that `toolPermission` and `artifactReviewPolicy` are the right key names,
  and that `always-proceed` is the right value;
- that the subagent frontmatter fields are accepted as written;
- that `--model pro` names a real model;
- whether `agy` reads a project-local config directory.

`--dry-run` before the first real install and `--status` after will surface
most of this quickly.
