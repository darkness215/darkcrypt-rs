#!/usr/bin/env bash
# Linux primary build — cross-compile to x86_64-pc-windows-gnu via mingw-w64.
#
# Expects rustup toolchain `stable` + target `x86_64-pc-windows-gnu`.
# Expects system `x86_64-w64-mingw32-gcc` (already installed for darkcrypt C).
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

echo "=== Build config ==="
rustc --version
cargo --version
echo "cwd: $(pwd)"
echo ""

cargo build --release

EXE_PATH="target/x86_64-pc-windows-gnu/release/darkcrypt-rs.exe"
if [ ! -f "$EXE_PATH" ]; then
    echo "error: $EXE_PATH not found"
    exit 1
fi

mkdir -p artifacts
cp "$EXE_PATH" artifacts/darkcrypt-rs.exe

echo ""
echo "==================== BUILD OK ===================="
ls -la artifacts/darkcrypt-rs.exe
echo "SHA256: $(sha256sum artifacts/darkcrypt-rs.exe | awk '{print $1}')"
file artifacts/darkcrypt-rs.exe
echo "=================================================="
