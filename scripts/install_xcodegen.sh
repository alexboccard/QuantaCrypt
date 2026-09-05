#!/usr/bin/env bash
# Install one known XcodeGen release, verified by SHA-256.
#
# `brew install xcodegen` resolves whatever homebrew-core serves on the day.
# XcodeGen writes the .xcodeproj — every build phase the Release xcodebuild
# then executes — so it sits in the signed-artefact path, and it was the one
# tool there that was not pinned (the python.org installer already is).
#
# Bump XCODEGEN_VERSION and XCODEGEN_SHA256 together:
#   curl -sSL -o xcodegen.zip https://github.com/yonaskolb/XcodeGen/releases/download/<ver>/xcodegen.zip
#   shasum -a 256 xcodegen.zip
#
# Usage: bash scripts/install_xcodegen.sh
#   XCODEGEN_PREFIX  install root (default ~/.local); bin/ goes on GITHUB_PATH in CI
set -euo pipefail

XCODEGEN_VERSION="2.46.0"
XCODEGEN_SHA256="4d9e34b62172d645eed6457cac13fc222569974098ef4ee9c3368bedf0196806"
PREFIX="${XCODEGEN_PREFIX:-$HOME/.local}"

have="$("$PREFIX/bin/xcodegen" --version 2>/dev/null || true)"
if [ "$have" != "Version: $XCODEGEN_VERSION" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -sSL --fail --retry 3 \
    -o "$tmp/xcodegen.zip" \
    "https://github.com/yonaskolb/XcodeGen/releases/download/$XCODEGEN_VERSION/xcodegen.zip"
  echo "$XCODEGEN_SHA256  $tmp/xcodegen.zip" | shasum -a 256 -c -
  unzip -q "$tmp/xcodegen.zip" -d "$tmp"
  # The binary looks for its SettingPresets at ../share/xcodegen relative to
  # itself, so the whole tree has to move together.
  mkdir -p "$PREFIX/bin" "$PREFIX/share"
  rm -rf "$PREFIX/share/xcodegen"
  cp -R "$tmp/xcodegen/share/xcodegen" "$PREFIX/share/xcodegen"
  install -m 0755 "$tmp/xcodegen/bin/xcodegen" "$PREFIX/bin/xcodegen"
  echo "installed xcodegen $XCODEGEN_VERSION to $PREFIX/bin"
else
  echo "xcodegen $XCODEGEN_VERSION already at $PREFIX/bin"
fi

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$PREFIX/bin" >> "$GITHUB_PATH"
fi
