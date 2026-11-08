"""The GLiNER2 named-entity model, loaded once, on first use.

Importing this module is cheap: gliner2 (and PyTorch with it) is imported inside
get_model(), so code that imports the redaction engine only pays for the model
when it actually redacts something.
"""
from functools import cache

MODEL_NAME = "fastino/gliner2-privacy-filter-PII-multi"


@cache
def get_model():
    """Return the shared GLiNER2 model, loading it on the first call."""
    from gliner2 import GLiNER2  # deferred import: pulls in PyTorch

    print("Loading GLiNER2-PII (Fastino) for local CPU inference...")
    model = GLiNER2.from_pretrained(MODEL_NAME)
    print("GLiNER2 model loaded successfully.")
    return model
