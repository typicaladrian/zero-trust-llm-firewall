---
name: new-feature
description: Take a new feature from idea to pull request through the gated delivery loop (plan, owner approval, tests first, implement, security review, PR). Use when the owner asks for a new capability.
argument-hint: <what the feature should do>
disable-model-invocation: true
---

# New feature

Requested feature: **$ARGUMENTS**

If no feature was given, ask the owner what they want, then continue.

Follow [docs/workflow.md](../../../docs/workflow.md) step by step. It's the source of truth. For this skill specifically:

1. **Step 0:** start from a clean, up-to-date `main`.
2. **Step 1:** run the `planner` subagent with the feature request and anything the owner said. Present its plan. **Then stop and wait for the owner's approval.** Don't create branches, issues or files before approval.
3. **Step 2:** after approval, create a GitHub issue from the approved plan (label `enhancement`, plus `security` if it touches redaction, secrets or persistence). Use its number in the branch name: `feature/<issue>-<slug>`.
4. **Steps 3–7:** baseline benchmark first if the redaction engine will change, then branch, tests first (show the failing output), implement, update docs, run the `redaction-reviewer` subagent, then commit, push and open the PR with `Closes #<issue>`.
5. **Step 8:** report the PR link, CI status, reviewer verdict, eval numbers and anything not verified. **Stop. Don't merge** unless the owner says so.

Keep the task list updated so the owner can follow progress. If the plan turns out wrong while building, stop and re-plan with the owner instead of drifting from what they approved.
