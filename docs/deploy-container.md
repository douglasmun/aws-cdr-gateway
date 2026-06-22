# Deploying the CDR service as a container / sidecar

The local CDR service (`src/app.py`) ships as a small, self-contained Docker image — a
drop-in **file-disarming sidecar** for any application, in any language, with **no AWS
account and no shared state**. Your app POSTs an upload to the sidecar and gets back
disarmed bytes (or a fail-closed rejection).

It runs the *same* `cdr_dispatch` engine as the AWS Lambda, so a file disarmed locally is
disarmed by identical logic to the cloud pipeline. See [`local-cdr.md`](local-cdr.md) for
the API contract and security model, and [`local_cdr_architecture.svg`](local_cdr_architecture.svg)
for the "one core, two front-ends" picture.

---

## Quickstart

Pull the published image (multi-arch: amd64 + arm64):

```bash
docker run --rm -p 8000:8000 ghcr.io/douglasmun/aws-cdr-gateway:latest
```

…or build it yourself from source:

```bash
docker build -t cdr-gateway:local .
docker run --rm -p 8000:8000 cdr-gateway:local
```

Then:

```bash
curl -sS http://localhost:8000/healthz
curl -sS -o clean.docx -F file=@dirty.docm http://localhost:8000/sanitise
```

> Images are published to GHCR by the `docker-publish` workflow on a version tag
> (`git tag v1.0.0 && git push origin v1.0.0` → `:1.0.0`, `:1.0`, `:1`, `:latest`).

Or with Compose (includes the sidecar wiring and hardening):

```bash
docker compose up --build
```

---

## The sidecar pattern

Your app accepts uploads but never trusts them. Before storing or forwarding a file, it
hands the bytes to the CDR sidecar and uses the response:

```
┌────────────┐   POST /sanitise (bytes)   ┌──────────────────┐
│  your app  │ ─────────────────────────▶ │  CDR sidecar     │
│ (any lang) │ ◀───────────────────────── │  app.py / uvicorn │
└────────────┘   200 clean bytes          └──────────────────┘
                 413 too large · 422 rejected · 500 error        (no AWS, no state)
```

Example client call (Python; the contract is plain HTTP, so any language works):

```python
import os, requests

resp = requests.post(
    os.environ["CDR_URL"],                       # http://cdr:8000/sanitise
    files={"file": ("upload.docx", raw_bytes)},
)
if resp.status_code == 200:
    clean_bytes = resp.content                   # safe to store / forward
    report = resp.headers.get("X-CDR-Report")
elif resp.status_code in (413, 422):
    reject(resp.json()["reason"])                # fail closed — do not store the original
else:
    handle_error()                               # 500: unparseable input
```

`docker-compose.yml` in the repo root has a commented `app:` service showing exactly this
wiring (`CDR_URL=http://cdr:8000/sanitise`, `depends_on: cdr: condition: service_healthy`).

---

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `CDR_HOST` | `0.0.0.0` (in image) | bind address; the image sets `0.0.0.0` so it's reachable when you publish a port |
| `CDR_PORT` | `8000` | listen port |
| `CDR_MAX_FILE_BYTES` | `104857600` (100 MB) | upload ceiling; over it → **413** |
| `CDR_MAX_ENTRY_BYTES` | `209715200` (200 MB) | per-ZIP-entry decompression limit (zip-bomb guard) |

```bash
docker run --rm -p 8000:8000 -e CDR_MAX_FILE_BYTES=26214400 cdr-gateway:local  # 25 MB cap
```

---

## Hardening

The image is built for a least-privilege deployment of an upload-handling service, and
each property below is verified:

- **Non-root** — runs as user `cdr` (uid 10001), never root.
- **No build toolchain** — multi-stage build; the runtime image installs from a prebuilt
  wheelhouse, so no compiler is present in the final image.
- **Read-only root filesystem capable** — runs with `read_only: true` given a writable
  `/tmp` (`tmpfs`); the Compose file sets both.
- **Drops all Linux capabilities** and sets `no-new-privileges` (Compose).
- **Built-in `HEALTHCHECK`** hits `/healthz`; orchestrators see the container go `healthy`.
- **Size-bounded before parsing** — `BodySizeLimitMiddleware` rejects oversize uploads
  before the body is fully buffered (no OOM / disk-fill from a giant upload).

> **No built-in auth or rate limiting.** This is a disarming engine, not an edge gateway.
> Keep the sidecar on an internal network reachable only by your app (drop the `ports:`
> block in production), and put auth / rate limiting / TLS at your own edge or reverse proxy.

---

## Kubernetes sidecar

Run the CDR container in the same Pod as your app; your app reaches it on `localhost:8000`
(containers in a Pod share a network namespace):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-cdr
spec:
  containers:
    - name: app
      image: your-app:latest
      env:
        - name: CDR_URL
          value: "http://localhost:8000/sanitise"
    - name: cdr
      image: cdr-gateway:local        # or your registry path
      ports:
        - containerPort: 8000
      env:
        - name: CDR_MAX_FILE_BYTES
          value: "104857600"
      readinessProbe:
        httpGet: { path: /healthz, port: 8000 }
        initialDelaySeconds: 5
      livenessProbe:
        httpGet: { path: /healthz, port: 8000 }
        periodSeconds: 30
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
      volumeMounts:
        - { name: tmp, mountPath: /tmp }
  volumes:
    - name: tmp
      emptyDir: {}
```

For a cluster-wide service instead of a per-Pod sidecar, deploy it as a normal
`Deployment` + `Service` and point apps at `http://cdr.<namespace>.svc:8000/sanitise`.

---

## Image facts

- Base: `python:3.12-slim` (matches the Lambda runtime and the pinned `pikepdf`/`Pillow`
  wheels).
- Contents: only `lambda_function.py` + `app.py` and the local-service deps — no tests,
  no AWS tooling, no SAM/Terraform.
- Size: ~420 MB (dominated by `pikepdf`/`Pillow`/`openpyxl` native libs).

---

## See also

- [`local-cdr.md`](local-cdr.md) — API contract, configuration, security model, embedding
- [`../README.md`](../README.md) — project overview and both deployment modes
- [`../docker-compose.yml`](../docker-compose.yml) — runnable sidecar example
- [`../Dockerfile`](../Dockerfile) — the image build
