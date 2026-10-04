#!/usr/bin/env bash
# SEC-008: install the pinned prebuilt `bpf-linker` (needed to build
# relay-ebpf/) from the aya-rs GitHub release, verifying the asset's SHA-256
# BEFORE extracting it. A digest mismatch aborts without installing anything.
#
#   bash scripts/install-bpf-linker.sh [--dest DIR]   # default: ~/.cargo/bin
#
# Upstream publishes no signatures or build attestations for these assets
# (checked 2026-09-29: the GitHub attestations API returns 404), so the pinned
# digest is the trust anchor. To bump: pick a release from
# https://github.com/aya-rs/bpf-linker/releases, take each asset's digest from
# `https://api.github.com/repos/aya-rs/bpf-linker/releases/tags/<tag>`
# (`assets[].digest`), confirm it against an independent download, and update
# VERSION + the digests below + relay-ebpf/README.md.
set -euo pipefail

VERSION=v0.10.4
dest="${HOME}/.cargo/bin"

while [ $# -gt 0 ]; do
    case "$1" in
        --dest) dest="$2"; shift 2 ;;
        *) echo "usage: $0 [--dest DIR]" >&2; exit 2 ;;
    esac
done

if [ "$(uname -s)" != Linux ]; then
    echo "bpf-linker prebuilt install is Linux-only (relay-ebpf needs a Linux host)" >&2
    exit 1
fi
case "$(uname -m)" in
    x86_64)
        asset=bpf-linker-x86_64-unknown-linux-musl.tar.zst
        sha256=4dda77daab6c5f120a468e6d3ede2498f5bd47ece712172cfb7290176d93d015 ;;
    aarch64 | arm64)
        asset=bpf-linker-aarch64-unknown-linux-musl.tar.zst
        sha256=c3638cd3cb735ff85705905a07e0df61c0f9426480334c8e2efe5cb92fd9d3de ;;
    *)
        echo "no pinned bpf-linker asset for $(uname -m)" >&2
        exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

url="https://github.com/aya-rs/bpf-linker/releases/download/${VERSION}/${asset}"
echo "downloading ${url}"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$asset" "$url"
echo "${sha256}  ${tmp}/${asset}" | sha256sum --check --strict -

tar --zstd -xf "$tmp/$asset" -C "$tmp" bpf-linker
mkdir -p "$dest"
install -m 0755 "$tmp/bpf-linker" "$dest/bpf-linker"
echo "installed bpf-linker ${VERSION} to ${dest}/bpf-linker"
