## Summary
<!-- What changed and why, in 2–4 bullets. -->

Closes #

## Product promises
<!-- P-numbers from docs/product.md this strengthens or touches. "None" is fine for tooling/docs. -->

## Testing
- [ ] New/changed tests fail before the change and pass after
- [ ] Fast tier: `pytest`
- [ ] Model tier (if entity detection could change): `ZT_REAL_MODEL=1 pytest -m model`
- [ ] CUAD benchmark (if the redaction engine changed): before → after recall

**Not verified:**
<!-- Be explicit about anything you did not test. -->

## Review
<!-- redaction-reviewer verdict and how findings were handled. -->

## Deployment notes
<!-- Config changes, re-sync steps, anything an appliance operator must do. "None" if nothing. -->
