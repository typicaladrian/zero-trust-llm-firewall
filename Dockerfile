# Use a lightweight Python 3.11 base image
FROM python:3.11-slim

# Set environment variables for non-interactive installs and unbuffered Python output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set up a working directory
WORKDIR /app

# Install system dependencies (needed for ONNX and build wheels if required)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the proxy application code
COPY main.py .

# Pre-download the GLiNER2 model into the Docker layer to speed up startup times
RUN python -c "from gliner2 import GLiNER2; GLiNER2.from_pretrained('fastino/gliner2-privacy-filter-PII-multi')"

# Expose the default FastAPI port
EXPOSE 8000

# Start the proxy with Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]