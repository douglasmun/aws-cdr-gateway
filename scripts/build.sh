#!/usr/bin/env bash
#
# Build the CDR Lambda deployment package (build/lambda.zip).
#
# Installs the pinned dependencies as LINUX (manylinux) wheels for the Lambda's Python
# 3.12 runtime — pikepdf and Pillow are C extensions, so the macOS/host wheels will NOT
# run on Lambda. Then bundles the handler source. Terraform consumes the resulting zip
# via var.lambda_zip_path; this build is intentionally separate from `tofu apply`
# (provisioning should not depend on a flaky native-wheel install).
#
# Usage:  ./scripts/build.sh            # from anywhere (paths are resolved from BASH_SOURCE)
# Output: build/lambda.zip  (reproducible: identical inputs → identical sha256)
#
# Requirements: python3 + pip, and the `zip` CLI. Dependencies are hash-pinned in
# scripts/lambda-requirements.txt and installed with --require-hashes (supply-chain guard).
# boto3 is excluded — it is already in the Lambda runtime — keeping the package small.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build"
STAGE_DIR="${BUILD_DIR}/package"
ZIP_PATH="${BUILD_DIR}/lambda.zip"
REQ_FILE="${REPO_ROOT}/scripts/lambda-requirements.txt"
PY_VERSION="312"               # Lambda runtime: python3.12
# manylinux_2_28 (glibc 2.28): pikepdf 10.x stopped publishing manylinux2014 (glibc 2.17)
# wheels. The Lambda python3.12 runtime is Amazon Linux 2023 (glibc 2.34), so a 2.28 wheel
# runs fine. For arm64, use manylinux_2_28_aarch64.
PLATFORM="manylinux_2_28_x86_64"
# Fixed timestamp for reproducible zips, in touch -t form [[CC]YY]MMDDhhmm — portable
# across BSD (macOS) and GNU touch. 2020-01-01 00:00. (zip stores 2-second resolution.)
TOUCH_STAMP="202001010000"

# Preflight: fail early and clearly if a required tool is missing.
for tool in python3 zip; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "ERROR: '${tool}' not found on PATH" >&2; exit 1; }
done

echo ">> Cleaning ${BUILD_DIR}"
rm -rf "${BUILD_DIR}"
mkdir -p "${STAGE_DIR}"

echo ">> Installing Linux wheels (py${PY_VERSION}, ${PLATFORM}) with hash verification"
# --platform + --only-binary forces prebuilt Linux wheels (never a host-native build).
# --require-hashes makes pip refuse any package whose sha256 is not pinned in REQ_FILE,
# covering transitive deps too — a supply-chain guard.
# --no-compile: do not write .pyc files. pip would byte-compile them for the HOST python
# (e.g. cpython-314), which (a) is the wrong version for the 3.12 runtime — dead weight —
# and (b) embeds non-deterministic content, breaking reproducibility. Lambda compiles on
# cold start anyway.
python3 -m pip install \
  --platform "${PLATFORM}" \
  --python-version "${PY_VERSION}" \
  --implementation cp \
  --only-binary=:all: \
  --require-hashes \
  --no-compile \
  --target "${STAGE_DIR}" \
  -r "${REQ_FILE}"

echo ">> Adding handler source"
cp "${REPO_ROOT}/src/lambda_function.py" "${STAGE_DIR}/"
# rebuilding; the EventBridge target uses lambda_function.handler by default.

# Belt-and-suspenders: drop any __pycache__ that slipped in (non-deterministic + wrong ABI).
find "${STAGE_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +

echo ">> Zipping ${ZIP_PATH} (reproducible)"
# Reproducible build: normalise every file's mtime to a fixed epoch and add entries in a
# stable sorted order with -X (strip extra attributes). This keeps the zip — and thus the
# Lambda source_code_hash — byte-stable across rebuilds of identical inputs.
find "${STAGE_DIR}" -exec touch -h -t "${TOUCH_STAMP}" {} +
( cd "${STAGE_DIR}" && find . \( -type f -o -type l \) | LC_ALL=C sort | zip -qX -@ "${ZIP_PATH}" )

echo ">> Done: ${ZIP_PATH} ($(du -h "${ZIP_PATH}" | cut -f1))"
