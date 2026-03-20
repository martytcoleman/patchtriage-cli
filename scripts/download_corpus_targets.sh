#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_DIR="${1:-$ROOT_DIR/corpus}"

mkdir -p "$CORPUS_DIR"

uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "$uname_s" in
  Linux) os_name="linux" ;;
  Darwin) os_name="macos" ;;
  *)
    echo "Unsupported OS: $uname_s" >&2
    exit 1
    ;;
esac

case "$uname_m" in
  x86_64|amd64) arch_name="amd64" ;;
  arm64|aarch64) arch_name="arm64" ;;
  *)
    echo "Unsupported architecture: $uname_m" >&2
    exit 1
    ;;
esac

download_jq() {
  local out_dir="$CORPUS_DIR/jq"
  local v1="1.7"
  local v2="1.7.1"
  mkdir -p "$out_dir/results"

  local b1="$out_dir/jq-${v1}-${os_name}-${arch_name}"
  local b2="$out_dir/jq-${v2}-${os_name}-${arch_name}"
  local u1="https://github.com/jqlang/jq/releases/download/jq-${v1}/jq-${os_name}-${arch_name}"
  local u2="https://github.com/jqlang/jq/releases/download/jq-${v2}/jq-${os_name}-${arch_name}"

  echo "[jq] Downloading $v1 -> $b1"
  curl -L --fail -o "$b1" "$u1"
  chmod +x "$b1"

  echo "[jq] Downloading $v2 -> $b2"
  curl -L --fail -o "$b2" "$u2"
  chmod +x "$b2"
}

download_yq() {
  local out_dir="$CORPUS_DIR/yq"
  local v1="v4.48.2"
  local v2="v4.49.1"
  mkdir -p "$out_dir/results"

  local os_part arch_part
  case "$os_name" in
    macos) os_part="darwin" ;;
    linux) os_part="linux" ;;
  esac
  case "$arch_name" in
    amd64) arch_part="amd64" ;;
    arm64) arch_part="arm64" ;;
  esac

  local b1="$out_dir/yq-${v1}-${os_part}-${arch_part}"
  local b2="$out_dir/yq-${v2}-${os_part}-${arch_part}"
  local u1="https://github.com/mikefarah/yq/releases/download/${v1}/yq_${os_part}_${arch_part}"
  local u2="https://github.com/mikefarah/yq/releases/download/${v2}/yq_${os_part}_${arch_part}"

  echo "[yq] Downloading $v1 -> $b1"
  curl -L --fail -o "$b1" "$u1"
  chmod +x "$b1"

  echo "[yq] Downloading $v2 -> $b2"
  curl -L --fail -o "$b2" "$u2"
  chmod +x "$b2"
}

download_build_openssl() {
  local out_dir="$CORPUS_DIR/openssl"
  local v1="3.0.13"
  local v2="3.0.14"
  mkdir -p "$out_dir/results"

  cd "$out_dir"
  curl -L --fail -o "openssl-${v1}.tar.gz" "https://www.openssl.org/source/openssl-${v1}.tar.gz"
  curl -L --fail -o "openssl-${v2}.tar.gz" "https://www.openssl.org/source/openssl-${v2}.tar.gz"

  rm -rf "openssl-${v1}" "openssl-${v2}"
  tar -xzf "openssl-${v1}.tar.gz"
  tar -xzf "openssl-${v2}.tar.gz"

  echo "[openssl] Building ${v1}"
  (
    cd "openssl-${v1}"
    ./Configure no-shared no-tests
    make -j4
    cp "apps/openssl" "$out_dir/openssl-${v1}-${os_name}-${arch_name}"
  )

  echo "[openssl] Building ${v2}"
  (
    cd "openssl-${v2}"
    ./Configure no-shared no-tests
    make -j4
    cp "apps/openssl" "$out_dir/openssl-${v2}-${os_name}-${arch_name}"
  )
}

download_build_openssh() {
  local out_dir="$CORPUS_DIR/openssh"
  local v1="9.7p1"
  local v2="9.8p1"
  mkdir -p "$out_dir/results"

  cd "$out_dir"
  curl -L --fail -o "openssh-${v1}.tar.gz" "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${v1}.tar.gz"
  curl -L --fail -o "openssh-${v2}.tar.gz" "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${v2}.tar.gz"

  rm -rf "openssh-${v1}" "openssh-${v2}"
  tar -xzf "openssh-${v1}.tar.gz"
  tar -xzf "openssh-${v2}.tar.gz"

  # Portable fallback that avoids host OpenSSL version incompatibilities.
  echo "[openssh] Building ${v1} (without OpenSSL)"
  (
    cd "openssh-${v1}"
    ./configure --without-openssl --without-zlib-version-check
    make -j4
    cp "sshd" "$out_dir/sshd-${v1}-${os_name}-${arch_name}"
  )

  echo "[openssh] Building ${v2} (without OpenSSL)"
  (
    cd "openssh-${v2}"
    ./configure --without-openssl --without-zlib-version-check
    make -j4
    cp "sshd" "$out_dir/sshd-${v2}-${os_name}-${arch_name}"
  )
}

echo "Populating corpus in: $CORPUS_DIR"
download_jq
download_yq
download_build_openssl
download_build_openssh
echo "Done."
