# Zero-Trust LLM Firewall

On-premises FastAPI proxy that redacts client-identifying data from law-firm prompts before they reach cloud LLMs, then restores it in the response. Runs on a small appliance on the firm's LAN, behind Open WebUI. The product promise is **"raw client data never leaves the building"**. Treat any change that could weaken that promise as high risk.

Read on demand: [docs/architecture.md](docs/architecture.md) (request flow, components, data stores), [docs/product.md](docs/product.md) (customer, product promises and how each is verified), [docs/decisions/](docs/decisions/) (why things are the way they are).

## Non-negotiables

1. **No real client data anywhere**: not in fixtures, tests, prompts, commits or logs. Use synthetic text or the public CUAD contracts in `evals/fixtures/`.
2. **Never read, print or commit `.env`.** Configuration is documented in `.env.example`. No hardcoded secrets or fallback secrets in code.
3. **Every outbound message in the zero-trust lane must pass through `EntityVault.anonymize_text`.** If you add a new message shape, role or route, it gets redacted too, or the PR explains why not.
4. **Audit logs record metadata only**: counts, latency, user, model. Never prompt or response text.
5. **Redaction recall must not regress.** Any change to `EntityVault`, `PII_LABELS`, `REGEX_PATTERNS` or `STOPWORDS` needs benchmark numbers before and after in the PR.
6. **Bugs get a reproducing test first**, then the fix.

## Repo map

```
main.py              Everything (for now): config, EntityVault redaction engine, routes, audit, PDF reports
evals/               benchmark.py (CUAD recall), verify_redaction.py, document_stress_test.py, fixtures/
scripts/             prune_chats.sh, sync_vault.py, stress_test.py, multiturn_smoke_test.py
assets/logo.png      PDF report branding
tests/               pytest: fast tier (FakeNER) + tests/model/ (real GLiNER2)
docs/                Architecture, product promises, decision records, workflow
.claude/             Agent settings: permissions, hooks, subagents (planner, redaction-reviewer), skills
private/             Gitignored local business notes (may not exist); never copy its contents into tracked files
```

## Commands

```bash
docker compose up --build                                                # full stack: proxy :8000 (localhost only), Open WebUI :3000
docker compose -f docker-compose.yml -f docker-compose.dev.yml up        # dev: mounts main.py with --reload
venv/Scripts/python.exe -m pytest                                        # fast tier: fake NER model, ~15 s. Run before every commit
ZT_REAL_MODEL=1 venv/Scripts/python.exe -m pytest -m model               # model tier: real GLiNER2, ~40 s once the model is cached
venv/Scripts/python.exe evals/benchmark.py                               # full CUAD recall benchmark, about 13 min on CPU
venv/Scripts/python.exe scripts/stress_test.py                           # needs the proxy running; uses the auditor lane (no API cost)
```

- Local venv is Python 3.13; the Docker image is Python 3.11. Keep code compatible with 3.11. Dev dependencies: `requirements-dev.txt`.
- **Testing:** the fast tier replaces GLiNER2 with `FakeNER` (`tests/conftest.py`); register what it should detect with the `ner` fixture. The `upstream` fixture captures everything that would be sent to the LLM, so check it with `assert_no_leak`. Tests never call real LLM APIs.
- **Known gaps are `xfail(strict=True)` tests whose reason starts with the issue number** (e.g. `#4: …`). When you fix one, remove its marker in the same PR and write `Closes #N` in the PR body. Never mark a newly failing test xfail to get a green run without the owner agreeing.
- **CI** (`.github/workflows/tests.yml`) runs both tiers on Python 3.11 for every PR. Both checks must pass before merging.
- Map new tests to the promise they protect (P1–P10 in `docs/product.md`) and update that table.

## Gotchas

- **Importing `main` loads the GLiNER2 model at import time** (slow; downloads weights on the first run). Scripts that `from main import EntityVault` pay this cost.
- **Audit logs and the client vault live in `LOG_DIR`** (`AUDIT_LOG_DIR`, default `/app/logs`, the container volume). Running `main.py` directly on Windows without it writes to `C:\app\logs\`.
- **Streaming is only enabled on `public-research-base`.** The zero-trust lane forces `stream=False` because de-anonymization needs the whole response.
- **Placeholder format is `[LABEL_N]`**, e.g. `[PERSON_1]`. `internal_token_pattern` relies on it to avoid re-redacting tokens. Changing the format means changing both. Regex-layer labels keep their punctuation (`[ADDRESS_(US)_1]`, `[WEBSITE_/_URL_1]`).
- **Model IDs in `/v1/models` must be valid LiteLLM model names**, except `elm-tech-auditor` and `public-research-base`, which are handled locally.
- Open WebUI sends background prompts (titles, tags, follow-ups). `write_audit_log` filters them out by phrase. Keep that list in sync if Open WebUI changes.
- On Windows, `gh` may not be on PATH in agent shells. It installs to `C:\Program Files\GitHub CLI\gh.exe`. The owner-approval guard applies however `gh` is invoked.
- `WEBUI_SECRET_KEY` must be identical for Open WebUI and the proxy, or every audit entry's user becomes `ERROR_INVALID_SIGNATURE`.

## Workflow

- **Every change follows [docs/workflow.md](docs/workflow.md)**: plan → owner approval → tests first → implement → `redaction-reviewer` → PR → owner merges. `/new-feature <idea>` and `/fix-issue <n>` run this loop.
- **Guardrails in `.claude/settings.json`**: `.env` is unreadable (tools and shell). Pushing to `main` and force-pushing are blocked. Merging, releases and repo settings always ask the owner. A Stop hook won't let a turn end while the fast tier fails on changed code.
- One issue → one branch (`feature/…`, `fix/…`, `docs/…`, `chore/…`) → one PR. Never commit to `main` directly (branch protection enforces it).
- Commit subject style: `Type: Title Case Summary`, with Type one of Feature, Fix, Testing, Refactor, Security, Docs or Chore. Add a body when the why isn't obvious.
- **No `Co-Authored-By` or "Generated with" lines** in commits or PRs (owner's preference).
- PR descriptions include: summary, testing done (and what was *not* tested), eval numbers if redaction changed, deployment notes.
- Merge with a merge commit, never squash. The commit history is part of the portfolio.
- Significant design choices get a short record in `docs/decisions/` (see the README there).
