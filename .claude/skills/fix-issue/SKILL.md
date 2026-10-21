---
name: fix-issue
description: Fix an existing GitHub issue through the gated delivery loop (plan, owner approval, failing test first, fix, security review, PR that closes the issue). Use when the owner names an issue number to work on.
argument-hint: <issue number>
disable-model-invocation: true
---

# Fix issue #$ARGUMENTS

If no issue number was given, run `gh issue list` and ask the owner which one to take.

Follow [docs/workflow.md](../../../docs/workflow.md). For this skill specifically:

1. **Read the issue:** `gh issue view $ARGUMENTS --json title,body,labels,comments` (the plain-text `--comments` view can print nothing). Its acceptance criteria define "done".
2. **Find the reproduction:** search `tests/` for an `xfail` whose reason starts with `#$ARGUMENTS`. If there is one, it's the failing test. If not, the plan must include writing one.
3. **Plan, then GATE 1:** run the `planner` subagent with the issue text and the reproducing test. Present the plan. **Stop and wait for the owner's approval.**
4. **Record the decision:** once approved, post the plan as an issue comment, including the owner's answers to its open questions: write it to a file and run `gh issue comment $ARGUMENTS --body-file <file>`.
5. **Baseline:** if the plan changes the redaction engine, start the "before" benchmark now, before editing anything (see docs/workflow.md step 3).
6. **Branch:** `fix/$ARGUMENTS-<slug>` from an up-to-date `main`.
7. **Failing test first:** remove the `xfail` marker (or write the new test), run it, and show it fails for the reason in the issue. Commit it.
8. **Fix, verify, document:** implement; run the fast tier, the model tier if detection could change, and the "after" CUAD benchmark if the redaction engine changed (compare with the baseline from step 5). Update the `docs/product.md` status column for the affected promise.
9. **Review:** run the `redaction-reviewer` subagent and address its findings.
10. **PR, then GATE 2:** push, open the PR with `Closes #$ARGUMENTS`, report the PR link, CI status, reviewer verdict and anything not verified. **Stop. Don't merge** unless the owner says so.
