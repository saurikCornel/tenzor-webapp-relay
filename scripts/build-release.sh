#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

build_version="${TENZOR_BUILD_VERSION:-}"
if [[ -z "${build_version}" ]]; then
  build_version="$(git describe --always --dirty 2>/dev/null || true)"
  build_version="${build_version:-dev}"
fi
git_commit="${TENZOR_GIT_COMMIT:-}"
if [[ -z "${git_commit}" ]]; then
  git_commit="$(git rev-parse --verify HEAD 2>/dev/null || true)"
  git_commit="${git_commit:-unknown}"
fi
built_at_unix="${TENZOR_BUILT_AT_UNIX:-$(date +%s)}"

TENZOR_BUILD_VERSION="${build_version}" \
TENZOR_GIT_COMMIT="${git_commit}" \
TENZOR_BUILT_AT_UNIX="${built_at_unix}" \
  cargo build --locked --profile deploy

mkdir -p dist
install -m 0755 target/deploy/tenzor-webapp-relay dist/tenzor-webapp-relay
dist/tenzor-webapp-relay --version-json
