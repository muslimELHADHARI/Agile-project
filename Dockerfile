FROM python:3.11-slim-bookworm as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# Stage 2: Final image
FROM python:3.11-slim-bookworm

WORKDIR /app

# Copy only necessary files from build stage
COPY --from=builder /app/wheels /wheels

# Install application dependencies
RUN pip install --no-cache /wheels/*

COPY . .
COPY ressources ressources/

EXPOSE 8000

CMD ["gunicorn", "scan_server:app", "--workers", "1", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
