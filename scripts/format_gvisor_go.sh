#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GVISOR_DIR="$ROOT_DIR/third_party/gvisor"

docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$GVISOR_DIR:/workspace" \
  -w /workspace \
  golang:1.23 \
  bash -lc 'gofmt -w pkg/sentry/syscalls/linux/approval.go pkg/sentry/syscalls/linux/sys_file.go pkg/sentry/syscalls/linux/sys_thread.go pkg/sentry/syscalls/linux/sys_read_write.go'

