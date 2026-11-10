# 0013. Deploy to AWS Lambda as a container image with the Lambda Web Adapter
- **Status:** Accepted
- **Date:** 2026-11-09

## Context
The proxy started as an on-prem appliance (Docker Compose). It is being moved to AWS as a low-cost portfolio deployment (issue #26), with one hard rule: **spend as little as possible, and nothing billed per hour**. Demo traffic is a handful of requests a day, so the platform must cost about nothing when idle.

The app is a FastAPI service that loads a PyTorch NER model (about 1.2 GB of weights) at startup and needs roughly 3 GB of RAM.

## Decision
Run the existing Docker image on **AWS Lambda** as a container image, reached through a **function URL**, with the **AWS Lambda Web Adapter** translating invocations into plain HTTP calls to uvicorn on port 8000. The application code does not change.

The image is shaped for that target (the Dockerfile and `scripts/container_check.sh` enforce it):
- **CPU-only PyTorch**, installed before `requirements.txt`. The default CUDA wheels add about 5 GB (measured by layer sum: 8.0 GB with CUDA, 3.0 GB with CPU torch) and nothing uses a GPU on Lambda. Both fit under Lambda's 10 GB uncompressed limit; the smaller image pulls and cold-starts faster, costs less ECR storage and leaves headroom.
- **Model cache in `/opt/hf`** (`HF_HOME`) and `HF_HUB_OFFLINE=1`: Lambda runs as a non-root user that cannot read `/root`, and redaction must work with no network (P10).
- **Adapter pinned by digest**, copied to `/opt/extensions/`. It sees every raw prompt on Lambda, so the bytes must not change under a tag. Inert under Docker Compose.
- **Lambda-only settings** (`AUDIT_LOG_DIR`, `HOME`, `AWS_LWA_*`) live in Terraform, not the image, so the appliance's behavior is unchanged.
- **Built with `--provenance=false`**: Lambda rejects images with attestation manifests.

## Alternatives rejected
- **ECS Fargate or App Runner:** both bill by the hour or have a fixed minimum while running, which breaks the rule above.
- **Zip-package Lambda:** the 250 MB unzipped limit cannot hold PyTorch and the model.
- **Mangum (an ASGI-to-Lambda shim in the app code):** it would couple the code to Lambda and need its own handler; the adapter does the same job with no code change, and the same image keeps running on the appliance.
- **EC2:** hourly billing, and servers to patch.

## Consequences
- Cold starts are slow (model load); they will be measured and documented in the Terraform steps. Lambda's 10 s init limit is handled with the adapter's async init setting, which belongs to those steps.
- No local disk survives between invocations; audit storage on Lambda is ephemeral `/tmp` until the S3 backend exists (Milestone 4, decision 0011 is the seam).
- A changed `MODEL_NAME` needs an image rebuild, since weights are never fetched at runtime.
- On Docker Desktop (containerd image store), `docker images` adds the compressed and unpacked sizes, so the old image showed 12.5 GB although its layers sum to 8.0 GB (issue #26 quoted the 12.5 GB). The size gate in `scripts/container_check.sh` uses the layer sum.
- The container CI job runs on every PR. Its duration (estimated at about 10 minutes, a full build plus the model load) will be measured on its first CI runs.
- **What "never leaves the building" means changes on Lambda.** On the appliance, raw text stays on the firm's LAN. On Lambda, raw prompts reach AWS (TLS ends at the function URL, and the adapter and app see them in memory) before they are redacted; what is guaranteed is that they never reach the LLM provider. P1's wording and the pitch must say which deployment they describe. That is reviewed in a later step (`docs/product.md`), once the function exists.
- Extends decision 0010 (model loaded at startup) and decision 0011 (storage interface).
