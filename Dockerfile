# Local CDR service (src/app.py) — a containerised FastAPI front-end over the same
# cdr_dispatch engine the AWS Lambda uses. No AWS account required.
#
# Build:  docker build -t cdr-gateway:local .
# Run:    docker run --rm -p 8000:8000 cdr-gateway:local
# Health: curl localhost:8000/healthz
#
# Python 3.12 matches the Lambda runtime and the pinned pikepdf/Pillow wheels.

# ── Stage 1: build wheels ─────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY src/requirements.txt src/requirements-local.txt ./

# Build all deps into a wheelhouse so the runtime image needs no compiler toolchain.
RUN pip install --no-cache-dir --upgrade pip \
 && pip wheel --no-cache-dir --wheel-dir /wheels \
      -r requirements.txt -r requirements-local.txt

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Non-root: the service never needs root, and an upload-disarming service is exactly
# where you want least privilege.
RUN useradd --create-home --uid 10001 cdr

WORKDIR /app

# Install from the prebuilt wheelhouse (no build tools in the final image).
COPY --from=builder /wheels /wheels
COPY src/requirements.txt src/requirements-local.txt ./
RUN pip install --no-cache-dir --no-index --find-links /wheels \
      -r requirements.txt -r requirements-local.txt \
 && rm -rf /wheels requirements.txt requirements-local.txt

# Only the code the service needs: the engine + the FastAPI front-end.
COPY src/lambda_function.py src/app.py ./

USER cdr

# Bind all interfaces *inside the container*; publish to the host with -p. The service has
# no built-in auth — front it with your own controls before exposing beyond a trusted host.
ENV CDR_HOST=0.0.0.0 \
    CDR_PORT=8000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Liveness via the service's own /healthz. Uses python (already present) — no curl needed.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,os,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('CDR_PORT','8000')+'/healthz',timeout=2).status==200 else 1)"

# Run uvicorn directly (not via app.py __main__) for clean PID-1 signal handling.
CMD ["sh", "-c", "uvicorn app:app --host \"$CDR_HOST\" --port \"$CDR_PORT\""]
