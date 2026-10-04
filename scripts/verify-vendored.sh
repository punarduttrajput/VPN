#!/usr/bin/env bash
# SEC-008: verify every committed prebuilt binary against its pinned SHA-256
# in vendor/SHA256SUMS, and fail if a binary is committed without a pin.
# Provenance (source URL, version, upstream signature) is documented next to
# each binary — see vendor/README.md for the index. Run from anywhere:
#
#   bash scripts/verify-vendored.sh
set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST=vendor/SHA256SUMS
fail=0

echo "== pinned digests ($MANIFEST)"
sha256sum --check --strict "$MANIFEST" || fail=1

echo "== committed binaries without a pin"
# Executable / archive formats only (images and fonts aren't in scope).
declare -A pinned=()
while read -r _digest path; do
    pinned["$path"]=1
done <"$MANIFEST"
while IFS= read -r f; do
    if [ -z "${pinned[$f]:-}" ]; then
        echo "UNPINNED: $f — add its SHA-256 + provenance (see vendor/README.md)"
        fail=1
    fi
done < <(git ls-files -- '*.dll' '*.exe' '*.so' '*.so.*' '*.dylib' '*.a' '*.lib' \
    '*.o' '*.obj' '*.jar' '*.aar' '*.apk' '*.class' '*.wasm' '*.node' '*.bin' \
    '*.zip' '*.tar' '*.tgz' '*.gz' '*.zst' '*.xz')

echo "== Gradle wrapper distributions pin their SHA-256"
while IFS= read -r props; do
    if ! awk '{ sub(/\r$/, "") } /^distributionSha256Sum=[0-9a-f]+$/ && length($0) == 86 { ok = 1 }
              END { exit !ok }' "$props"; then
        echo "MISSING distributionSha256Sum: $props"
        fail=1
    fi
done < <(git ls-files -- '*gradle-wrapper.properties')

if [ "$fail" -ne 0 ]; then
    echo "vendored-binary verification FAILED" >&2
    exit 1
fi
echo "vendored-binary verification passed"
