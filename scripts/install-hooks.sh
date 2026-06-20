#!/usr/bin/env bash
#
# Install the repo's git hooks (tracked in scripts/hooks/) into this clone's .git/hooks/.
# Run once after cloning:  ./scripts/install-hooks.sh
#
# Hooks live in .git/hooks/ which is NOT version-controlled, so they must be installed per
# clone. This copies them and makes them executable. Re-run to update after a hook changes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/scripts/hooks"
GIT_DIR="$(git -C "${REPO_ROOT}" rev-parse --git-dir)"
DEST_DIR="${GIT_DIR}/hooks"

mkdir -p "${DEST_DIR}"

for hook in "${SRC_DIR}"/*; do
  [ -f "${hook}" ] || continue
  name="$(basename "${hook}")"
  cp "${hook}" "${DEST_DIR}/${name}"
  chmod +x "${DEST_DIR}/${name}"
  echo "installed: ${name} -> ${DEST_DIR}/${name}"
done

echo "Done. The pre-push hook now blocks force-push/deletion of protected branches in this clone."
