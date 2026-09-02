#!/usr/bin/env bash
#
# Fetch the Windows PDF print helper into dist/windows/.
#
# Windows has no supported way to send a PDF to a *named* printer from the
# command line, so the agent shells out to SumatraPDF's `-print-to`. That
# binary is fetched here rather than committed: a 16 MB third-party executable
# does not belong in the repo, and pinning version + SHA-256 makes the fetch
# reproducible and tamper-evident.
#
# SumatraPDF is GPLv3. It is invoked as a separate program (CreateProcess), so
# it does not affect the agent's own licensing — but shipping it obliges us to
# carry its licence and a source offer. See THIRD-PARTY-NOTICES.md, which the
# installer MUST include.
#
#   ./fetch-helper.sh
set -euo pipefail

cd "$(dirname "$0")"

# Pinned. Bump both together, and re-verify the checksum by hand from the
# vendor's site — never take a new hash from a failed run.
HELPER_VERSION="3.5.2"
HELPER_URL="https://www.sumatrapdfreader.org/dl/rel/${HELPER_VERSION}/SumatraPDF-${HELPER_VERSION}-64.zip"
HELPER_ZIP_SHA256="66ccb395c9184dce6822dfbb9970c877383b3ead6d9417b5106a844aac512989"
HELPER_EXE_SHA256="290e4aa7ed64c728138711c011e89aab7aa48dbc1ae430371dc2be4100b92bf0"

OUT="dist/windows"
TARGET="$OUT/SumatraPDF.exe"

mkdir -p "$OUT"

if [ -f "$TARGET" ]; then
  have="$(sha256sum "$TARGET" | cut -d' ' -f1)"
  if [ "$have" = "$HELPER_EXE_SHA256" ]; then
    echo "helper already present and verified: $TARGET"
    exit 0
  fi
  echo "helper present but checksum differs — refetching"
  rm -f "$TARGET"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "fetching SumatraPDF $HELPER_VERSION"
curl -sSL --fail --max-time 300 -o "$tmp/helper.zip" "$HELPER_URL"

echo "verifying archive"
got="$(sha256sum "$tmp/helper.zip" | cut -d' ' -f1)"
if [ "$got" != "$HELPER_ZIP_SHA256" ]; then
  echo "CHECKSUM MISMATCH for the archive" >&2
  echo "  expected $HELPER_ZIP_SHA256" >&2
  echo "  got      $got" >&2
  echo "Refusing to ship an unverified binary." >&2
  exit 1
fi

unzip -o -q "$tmp/helper.zip" -d "$tmp"
# The archive holds one versioned exe; the agent looks for a stable name.
mv "$tmp/SumatraPDF-${HELPER_VERSION}-64.exe" "$TARGET"

echo "verifying executable"
got="$(sha256sum "$TARGET" | cut -d' ' -f1)"
if [ "$got" != "$HELPER_EXE_SHA256" ]; then
  echo "CHECKSUM MISMATCH for the executable" >&2
  echo "  expected $HELPER_EXE_SHA256" >&2
  echo "  got      $got" >&2
  rm -f "$TARGET"
  exit 1
fi

echo "ok: $TARGET"
echo
echo "The installer must ship THIRD-PARTY-NOTICES.md alongside this binary."
