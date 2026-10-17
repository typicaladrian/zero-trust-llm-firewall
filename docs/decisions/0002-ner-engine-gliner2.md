# 0002. GLiNER2 as the NER engine
- **Status:** Accepted
- **Date:** 2026-08-03

## Context
The engine went through four versions in three weeks:
1. **spaCy + a small language model** (2026-07-14)
2. **Microsoft Presidio** (2026-07-18): adopted "for increased accuracy and more resource efficient redacting" (commit `3ca92a7`). A custom legal spaCy model was also trained (now in the untracked `depreciated/` folder).
3. **GLiNER via ONNX** (2026-07-27): reason not recorded. **Owner to confirm.**
4. **GLiNER2** with `fastino/gliner2-privacy-filter-PII-multi` (2026-08-03): reason not recorded. **Owner to confirm.**

## Decision
Use GLiNER2 zero-shot entity extraction on CPU, with labels supplied at runtime (`PII_LABELS`) and a confidence threshold of 0.30, chosen for recall.

## Consequences
- New entity types can be added by editing a label list, with no retraining.
- Runs fully offline on the appliance's CPU. Weights are baked into the Docker image.
- The low threshold favors recall over precision, so false positives are handled with `STOPWORDS`.
- Loading the model happens at import time, which slows startup and any script that imports `main`.
