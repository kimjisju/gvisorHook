#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GVISOR_DIR="$ROOT_DIR/third_party/gvisor"
OUT_DIR="$GVISOR_DIR/bin"
BUILD_IMAGE="${BUILD_IMAGE:-ubuntu:22.04}"
BAZELISK_VERSION="${BAZELISK_VERSION:-v1.25.0}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to build the custom runsc binary." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

docker manifest inspect "$BUILD_IMAGE" >/dev/null 2>&1 || {
  echo "Could not access build image: $BUILD_IMAGE" >&2
  exit 1
}

docker run --rm \
  -u 0:0 \
  -e USER="${USER:-kimjisu}" \
  -e HOME="/tmp" \
  -e DEBIAN_FRONTEND=noninteractive \
  -v "$GVISOR_DIR:/workspace" \
  -w /workspace \
  "$BUILD_IMAGE" \
  bash -lc "
    set -euo pipefail
    apt-get update
    apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip zip \
      python3 python3-setuptools python3-pip \
      build-essential crossbuild-essential-arm64 qemu-user-static \
      openjdk-11-jdk-headless \
      apt-transport-https software-properties-common \
      pkg-config libffi-dev patch diffutils libssl-dev \
      clang llvm erofs-utils busybox-static libbpf-dev linux-libc-dev \
      iproute2 netcat-openbsd libnuma-dev \
      gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu libc6-dev-i386
    curl -fsSL -o /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/download/${BAZELISK_VERSION}/bazelisk-linux-amd64
    chmod +x /usr/local/bin/bazel
    bazel version
    bazel build //runsc:runsc
    cp bazel-bin/runsc/runsc_/runsc /workspace/bin/runsc-hook.new
    chmod +x /workspace/bin/runsc-hook.new
    chown $(id -u):$(id -g) /workspace/bin/runsc-hook.new
    mv -f /workspace/bin/runsc-hook.new /workspace/bin/runsc-hook
  "

chmod +x "$OUT_DIR/runsc-hook"
echo "Built custom runsc at $OUT_DIR/runsc-hook"
