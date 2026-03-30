#!/usr/bin/env bash
# run_validation.sh — Automated build, run, and hash collection for Ed25519 verification.
#
# Usage:
#   bash run_validation.sh
#
# This script compiles the source, runs the full verification (including Schoof),
# and collects all artifacts into a timestamped output directory suitable for
# independent publication and PGP signing.
#
# Portable notes:
# - Works on Linux and macOS.
# - Uses GNU sha256sum when available, otherwise shasum -a 256.
# - Uses GNU /usr/bin/time -v when available, otherwise falls back to a portable timing mode.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT_DIR/ed25519_verify.cpp"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$ROOT_DIR/validation_output_${STAMP}"
BIN="$OUT_DIR/ed25519_verify"
SYSTEM_INFO="$OUT_DIR/system_info.txt"
BUILD_LOG="$OUT_DIR/build.log"
RUN_LOG="$OUT_DIR/verification.log"
HASHES="$OUT_DIR/hashes.txt"

mkdir -p "$OUT_DIR"

log_section() {
  printf '\n===== %s =====\n' "$1"
}

collect_cmd() {
  local label="$1"
  shift
  echo
  echo "--- ${label} ---"
  if command -v "$1" >/dev/null 2>&1; then
    "$@" 2>&1 || true
  else
    echo "Command not available: $1"
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

sha256_file() {
  if have_cmd sha256sum; then
    sha256sum "$1"
  elif have_cmd shasum; then
    shasum -a 256 "$1"
  else
    echo "No SHA-256 command available (need sha256sum or shasum)." >&2
    return 1
  fi
}

write_hash_manifest() {
  local outfile="$1"
  shift
  : > "$outfile"
  local f
  for f in "$@"; do
    if [[ -f "$f" ]]; then
      sha256_file "$f" >> "$outfile"
    else
      echo "Missing file for hashing: $f" >&2
      return 1
    fi
  done
}

run_with_timing() {
  local cmd=("$@")

  # Prefer GNU time with verbose output when available.
  if [[ -x /usr/bin/time ]]; then
    if /usr/bin/time -v true >/dev/null 2>&1; then
      /usr/bin/time -v "${cmd[@]}"
      return
    fi
  fi

  # Fallback: portable timing with UTC timestamps.
  local start_epoch end_epoch
  start_epoch="$(date +%s)"
  echo "--- Portable timing mode ---"
  echo "Started epoch:  $start_epoch"
  "${cmd[@]}"
  end_epoch="$(date +%s)"
  echo "Finished epoch: $end_epoch"
  echo "Elapsed seconds: $((end_epoch - start_epoch))"
}

# Collect system information
{
  echo "Validation run timestamp (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "Working directory: $ROOT_DIR"
  echo "Output directory:  $OUT_DIR"
  echo "Source file:       $SRC"

  collect_cmd "uname -a" uname -a

  if [[ -f /etc/os-release ]]; then
    collect_cmd "os-release" bash -lc 'cat /etc/os-release'
  else
    echo
    echo "--- os-release ---"
    echo "/etc/os-release not available"
  fi

  collect_cmd "hostname" hostname
  collect_cmd "hostnamectl" hostnamectl
  collect_cmd "sw_vers" sw_vers
  collect_cmd "lscpu" lscpu
  collect_cmd "sysctl -n machdep.cpu.brand_string" sysctl -n machdep.cpu.brand_string
  collect_cmd "sysctl -n hw.ncpu" sysctl -n hw.ncpu
  collect_cmd "nproc" nproc
  collect_cmd "free -h" free -h
  collect_cmd "vm_stat" vm_stat
  collect_cmd "g++ --version" g++ --version
  collect_cmd "clang++ --version" clang++ --version

  echo
  echo "--- SHA-256 of source ---"
  sha256_file "$SRC" 2>&1 || true
} > "$SYSTEM_INFO"

# Compile
{
  log_section "Compiling"
  echo "Command: g++ -O2 -std=c++17 -Wall -Wextra -pedantic -o $BIN $SRC"
  g++ -O2 -std=c++17 -Wall -Wextra -pedantic -o "$BIN" "$SRC"
  echo "Exit code: $?"
} 2>&1 | tee "$BUILD_LOG"

# Run full verification
{
  log_section "Running verification (full)"
  echo "Command: $BIN"
  echo "Started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo
  run_with_timing "$BIN"
  echo
  echo "Finished: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} 2>&1 | tee "$RUN_LOG"

# Copy source and script into output
cp "$SRC" "$OUT_DIR/ed25519_verify.cpp"
cp "$ROOT_DIR/run_validation.sh" "$OUT_DIR/run_validation.sh"

# Generate hashes
(
  cd "$OUT_DIR"
  write_hash_manifest "hashes.txt" \
    "ed25519_verify.cpp" \
    "ed25519_verify" \
    "build.log" \
    "verification.log" \
    "system_info.txt" \
    "run_validation.sh"
)

echo
echo "================================================================"
echo "  Validation complete."
echo "  Output directory: $OUT_DIR"
echo "================================================================"
echo
echo "Next step: sign the hash manifest with your PGP key:"
echo "  cd $OUT_DIR"
echo "  gpg --armor --detach-sign hashes.txt"
echo
