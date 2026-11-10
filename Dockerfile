# Lightweight Python 3.11 base image (Lambda-ready: see docs/decisions/0013 and issue #26)
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# CPU-only PyTorch FIRST. requirements.txt (via gliner2) would otherwise pull the default CUDA
# build, which is about 5 GB bigger (8 GB vs 3 GB), slower to pull and start, and useless on a
# CPU-only Lambda. Once a CPU
# torch is installed, pip sees the requirement as already satisfied and leaves it alone.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install the remaining Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Cache Hugging Face files in /opt/hf, NOT under /root. Lambda runs the container as a non-root
# user and /root is not readable by it, so weights cached there would look missing at runtime.
# This must be set BEFORE the download below.
ENV HF_HOME=/opt/hf

# PRE-DOWNLOAD MODEL BEFORE COPYING MAIN.PY
# (This ensures heavy model weights are cached permanently)
RUN python -c "from gliner2 import GLiNER2; GLiNER2.from_pretrained('fastino/gliner2-privacy-filter-PII-multi')"

# Offline from here on (P10: redaction needs zero cloud connectivity). These must come AFTER the
# download above, or the download itself would be refused. Consequence: changing MODEL_NAME in
# zt_firewall/redaction/ner.py needs an image rebuild; weights are never fetched at runtime.
ENV HF_HUB_OFFLINE=1
ENV LITELLM_LOCAL_MODEL_COST_MAP=True

# AWS Lambda Web Adapter: on Lambda it turns invocations into HTTP calls to uvicorn on port 8000.
# Lambda loads extensions from /opt/extensions; anywhere else (Docker Compose, CI) this file is
# inert. Pinned by DIGEST, not just by tag: the adapter sees every raw prompt on Lambda, and a tag
# can be re-pointed at different bytes. To upgrade, verify the release, then update tag and digest.
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:1.1.0@sha256:17cfd08eff1dfea3f6a9a1e9c65fdac80aa4919b6085e746615530f43f57d2f1 /lambda-adapter /opt/extensions/lambda-adapter

# Copy the application code LAST
COPY main.py .
COPY zt_firewall/ ./zt_firewall/
COPY assets/logo.png ./logo.png

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
