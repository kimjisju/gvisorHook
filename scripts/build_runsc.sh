#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GVISOR_DIR="$ROOT_DIR/third_party/gvisor"
OUT_DIR="$GVISOR_DIR/bin"
BUILD_IMAGE="${BUILD_IMAGE:-ubuntu:22.04}"
BAZELISK_VERSION="${BAZELISK_VERSION:-v1.25.0}"

SYSTEM_PACKAGES=(ca-certificates curl gnupg mitmproxy)
PYTHON_PACKAGES=(
  "torch:torch"
  "aiohttp:aiohttp"
  "llama-cpp-python:llama_cpp"
  "huggingface-hub:huggingface_hub"
)

missing_system_packages=()
if ! command -v docker >/dev/null 2>&1; then
  missing_system_packages+=("docker")
fi
for package in "${SYSTEM_PACKAGES[@]}"; do
  if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
    missing_system_packages+=("$package")
  fi
done

if ((${#missing_system_packages[@]})); then
  echo "Missing required system packages: ${missing_system_packages[*]}" >&2
  echo "Install them before running this script, then retry." >&2
  echo "Ubuntu example: sudo apt-get update && sudo apt-get install -y docker.io ca-certificates curl gnupg mitmproxy" >&2
  exit 1
fi

missing_python_packages=()
for package_spec in "${PYTHON_PACKAGES[@]}"; do
  package_name="${package_spec%%:*}"
  import_name="${package_spec#*:}"
  if ! python3 -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('${import_name}') else 1)" >/dev/null 2>&1; then
    missing_python_packages+=("$package_name")
  fi
done

if ((${#missing_python_packages[@]})); then
  echo "Missing required Python packages: ${missing_python_packages[*]}" >&2
  if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    echo "Python packages must be installed inside an active virtual environment." >&2
    echo "Activate a venv first, for example:" >&2
    echo "  python3 -m venv .venv" >&2
    echo "  source .venv/bin/activate" >&2
    echo "Then install the packages and rerun this script:" >&2
  else
    echo "Install the missing packages in the active venv and rerun this script:" >&2
  fi
  echo "  python -m pip install ${missing_python_packages[*]}" >&2
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
