#!/usr/bin/env bash
# run_validation.sh — Ed25519 verification build & run script
# Version: 2.1.0
#
# Usage:  bash run_validation.sh
#
# Output: validation_output_YYYYMMDDTHHMMSSZ/
#   ed25519_verify_v2.cpp   source used
#   ed25519_v2              compiled binary
#   build.log               compiler output
#   verification.log        full run output
#   system_info.txt         platform/compiler info
#   run_validation.sh       this script (copy)
#   README.txt              usage notes (copy)
#   hashes.txt              SHA-256 of all above
#
# To sign and publish:
#   gpg --armor --detach-sign hashes.txt
#   # then publish the whole directory + hashes.txt.asc
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT_DIR/ed25519_verify_v2.cpp"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$ROOT_DIR/validation_output_${STAMP}"
BIN="$OUT_DIR/ed25519_v2"
SYSTEM_INFO="$OUT_DIR/system_info.txt"
BUILD_LOG="$OUT_DIR/build.log"
RUN_LOG="$OUT_DIR/verification.log"
HASHES="$OUT_DIR/hashes.txt"

mkdir -p "$OUT_DIR"

log_section() { printf '\n===== %s =====\n' "$1"; }

collect_cmd() {
  local label="$1"; shift
  printf '\n--- %s ---\n' "$label"
  if command -v "$1" >/dev/null 2>&1; then "$@" 2>&1 || true
  else echo "Command not available: $1"; fi
}

# ── System information ──────────────────────────────────────────────
{
  echo "Validation run timestamp (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "ed25519_verify version: 2.1.0"
  echo "Working directory: $ROOT_DIR"
  echo "Output directory:  $OUT_DIR"
  echo "Source file:       $SRC"
  collect_cmd "uname -a"        uname -a
  collect_cmd "os-release"      bash -lc 'cat /etc/os-release'
  collect_cmd "hostnamectl"     hostnamectl
  collect_cmd "lscpu"           lscpu
  collect_cmd "nproc"           nproc
  collect_cmd "free -h"         free -h
  collect_cmd "lsblk"           lsblk
  collect_cmd "df -h"           df -h
  collect_cmd "g++ --version"   g++ --version
  collect_cmd "gcc --version"   gcc --version
  collect_cmd "ld --version"    ld --version
  collect_cmd "sha256sum source" sha256sum "$SRC"
} > "$SYSTEM_INFO"

# ── Compile ─────────────────────────────────────────────────────────
{
  log_section "Compiling"
  echo "Command: g++ -O2 -std=c++17 -Wall -Wextra -pedantic -o $BIN $SRC"
  g++ -O2 -std=c++17 -Wall -Wextra -pedantic -o "$BIN" "$SRC"
  echo "Exit code: $?"
} 2>&1 | tee "$BUILD_LOG"

# ── Run full verification ────────────────────────────────────────────
{
  log_section "Running verification (full)"
  echo "Command: $BIN"
  echo "Started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo ""
  if command -v /usr/bin/time >/dev/null 2>&1; then
    /usr/bin/time -v "$BIN" 2>&1
  else
    "$BIN" 2>&1
  fi
  echo ""
  echo "Finished: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} 2>&1 | tee "$RUN_LOG"

# ── Copy source and scripts ──────────────────────────────────────────
cp "$SRC"                             "$OUT_DIR/ed25519_verify_v2.cpp"
cp "$ROOT_DIR/run_validation.sh"      "$OUT_DIR/run_validation.sh"
[ -f "$ROOT_DIR/README.txt" ]    && cp "$ROOT_DIR/README.txt"    "$OUT_DIR/README.txt"
[ -f "$ROOT_DIR/README.md" ]     && cp "$ROOT_DIR/README.md"     "$OUT_DIR/README.md"
[ -f "$ROOT_DIR/README.html" ]   && cp "$ROOT_DIR/README.html"   "$OUT_DIR/README.html"
[ -f "$ROOT_DIR/MATH_CORRECTIONS.md" ] && \
  cp "$ROOT_DIR/MATH_CORRECTIONS.md" "$OUT_DIR/MATH_CORRECTIONS.md"

# ── Hash all artifacts ───────────────────────────────────────────────
(
  cd "$OUT_DIR"
  files=( ed25519_verify_v2.cpp ed25519_v2 build.log verification.log
          system_info.txt run_validation.sh )
  [ -f README.txt ]            && files+=( README.txt )
  [ -f README.md ]             && files+=( README.md )
  [ -f README.html ]           && files+=( README.html )
  [ -f MATH_CORRECTIONS.md ]   && files+=( MATH_CORRECTIONS.md )
  sha256sum "${files[@]}" > hashes.txt
)

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo "  Validation complete."
echo "  Output: $OUT_DIR"
echo ""
echo "  Next steps to publish:"
echo "  1. Review verification.log for PASS/FAIL"
echo "  2. Transfer hashes.txt to your signing machine"
echo "  3. gpg --armor --detach-sign hashes.txt"
echo "  4. Place hashes.txt.asc back in this directory"
echo "  5. Publish the entire output directory"
echo "════════════════════════════════════════════════════"
