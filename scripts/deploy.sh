#!/usr/bin/env bash
# deploy.sh — ship artifacts/darkcrypt-rs.exe from the Linux dev box to a
# Windows target over SSH.
set -euo pipefail

TARGET_HOST="${1:?usage: $(basename "$0") <target-host> <target-user>}"
TARGET_USER="${2:?usage: $(basename "$0") <target-host> <target-user>}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_winlab}"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
EXE="$HERE/artifacts/darkcrypt-rs.exe"

if [ ! -f "$EXE" ]; then
    echo "error: $EXE not found. Build first."
    exit 1
fi

echo "=== Local artifact ==="
ls -la "$EXE"
sha256sum "$EXE"

echo
echo "=== Pushing to $TARGET_USER@$TARGET_HOST ==="
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
    "$EXE" "$TARGET_USER@$TARGET_HOST:C:/Users/$TARGET_USER/darkcrypt-rs.exe"

echo
echo "=== Target verification ==="
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$TARGET_USER@$TARGET_HOST" \
    "Get-Item C:\\Users\\$TARGET_USER\\darkcrypt-rs.exe | Select-Object Name,Length | Format-Table -AutoSize; (Get-FileHash C:\\Users\\$TARGET_USER\\darkcrypt-rs.exe -Algorithm SHA256).Hash"
