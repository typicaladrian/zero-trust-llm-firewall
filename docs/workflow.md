# Development workflow

How every change gets from an idea to `main`. AI agents follow it through the `/new-feature` and `/fix-issue` skills (`.claude/skills/`). Humans follow the same steps.

```
Plan ──► GATE 1: owner approves ──► Branch ──► Tests first ──► Implement ──► Review ──► PR + CI ──► GATE 2: owner merges
```

The owner (repository maintainer) makes the decisions at the two gates. Agents never skip a gate, and never treat silence as approval.

## 0. Start clean
```bash
git switch main && git pull --ff-only && git status
```
The tree must be clean. If it isn't, stop and ask the owner what to do with the existing changes.

## 1. Plan → GATE 1
- Use the **`planner`** subagent (read-only) to explore and draft the plan in its standard format.
- Show the owner the plan, including its risks and open questions.
- **Stop and wait for explicit approval.** If the owner changes the plan, revise it and confirm again.

## 2. Track
- New work: create an issue whose body is the approved plan: `gh issue create --title "…" --body-file <file> --label <bug|enhancement|security>`.
- Existing issue: post the approved plan as a comment, including the owner's answers to its open questions: `gh issue comment <n> --body-file <file>`. The issue then records why the fix took the shape it did.
- Read issues with `gh issue view <n> --json title,body,labels,comments`. The plain-text `--comments` view can print nothing.

## 3. Baseline, then branch
- **If the plan touches `EntityVault`, `PII_LABELS`, `REGEX_PATTERNS` or `STOPWORDS`, start the "before" benchmark now, before editing anything.** Run it from a throwaway worktree of `main`, so edits on your branch can't affect it, and keep it in the background (about 13 min):
  ```bash
  git fetch && git worktree add ../zt-baseline origin/main && mkdir -p evals/output
  venv/Scripts/python.exe ../zt-baseline/evals/benchmark.py > evals/output/benchmark_before.txt 2>&1
  git worktree remove ../zt-baseline   # after it finishes
  ```
  Timings are only comparable if nothing else heavy runs at the same time; recall numbers are always comparable.
- Branch: `feature/<issue>-<slug>`, `fix/<issue>-<slug>`, `docs/…` or `chore/…`, cut from an up-to-date `main`.

## 4. Tests first
- Write the tests from the plan. Run them and **confirm they fail for the reason the plan predicts.** A test that passes before the change proves nothing.
- Fixing a known gap: the reproducing test already exists as `xfail` (its reason starts with `#<issue>`). Remove the marker, confirm it fails, and keep it.
- Commit: `Testing: …`.

## 5. Implement
- Make the smallest change that turns the new tests green.
- Fast tier: `venv/Scripts/python.exe -m pytest` (the Stop hook also enforces this).
- Model tier, if entity detection could change: `ZT_REAL_MODEL=1 venv/Scripts/python.exe -m pytest -m model`.
- If `EntityVault`, `PII_LABELS`, `REGEX_PATTERNS` or `STOPWORDS` changed: run `evals/benchmark.py` again (the "after" run, in the background) and compare with the step 3 baseline. Put both recall numbers, and which entities leak in each, in the PR. **Recall must not drop.**
- Update docs where behavior changed: the `docs/product.md` promise table, architecture, README, and a decision record for a significant design choice.

## 6. Review
- Run the **`redaction-reviewer`** subagent on the branch.
- Fix every *blocker* and *should-fix*. Re-run the reviewer if there were blockers.
- If you disagree with a finding, say so in the PR. Don't ignore it silently.

## 7. Pull request
- Commit in logical pieces: `Type: Title Case Summary` (Feature, Fix, Testing, Refactor, Security, Docs, Chore). No attribution trailers.
- `git push -u origin <branch>`, then `gh pr create` using the template in `.github/pull_request_template.md`. Include `Closes #<issue>`.

## 8. GATE 2
Report to the owner: PR link, CI status, the reviewer's verdict, eval numbers, and **anything not verified**. Then stop.
Merge only when the owner asks, with a merge commit: `gh pr merge <n> --merge`. Never squash, never force-push, never bypass CI.

## When stuck
Ask the owner instead of guessing. This applies especially to anything touching redaction behavior, data persistence, secrets, or a past decision record.
