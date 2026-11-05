#!/bin/sh
# Install Sherlock WAF from a GitHub release on Debian/Ubuntu and RHEL-family systems.
#
#   curl -fsSLO https://github.com/skylarng89/sherlock-waf/releases/latest/download/install.sh
#   sh install.sh [--version v0.5.0]
#
# It downloads the package and the signed checksum file, verifies the cosign
# signature of the checksums (keyless, GitHub OIDC identity of this repository's
# release workflow) and the SHA-256 of the package, and only then installs it.
# Verification failures stop the installation. Read this script before running it.
set -eu

REPO="skylarng89/sherlock-waf"
VERSION=""
ALLOW_UNSIGNED=0

while [ $# -gt 0 ]; do
	case "$1" in
		--version) VERSION="${2:?--version needs a value}"; shift 2 ;;
		--allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
		-h | --help) sed -n '2,12p' "$0"; exit 0 ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo sh install.sh)" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 1; }

case "$(uname -m)" in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	*) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if command -v dpkg >/dev/null; then
	KIND=deb
elif command -v rpm >/dev/null; then
	KIND=rpm
else
	echo "neither dpkg nor rpm found; use the container image or the tarball instead" >&2
	exit 1
fi

if [ -z "$VERSION" ]; then
	VERSION="$(curl --proto =https --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's|.*/tag/||')"
fi
case "$VERSION" in
	v[0-9]*) ;;
	*) echo "could not determine the version to install (got '$VERSION')" >&2; exit 1 ;;
esac
VER="${VERSION#v}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BASE="https://github.com/$REPO/releases/download/$VERSION"
PKG="sherlock_${VER}_linux_${ARCH}.${KIND}"

echo "Downloading $PKG and checksums for $VERSION..."
curl --proto =https --tlsv1.2 -fsSL -o "$WORK/$PKG" "$BASE/$PKG"
curl --proto =https --tlsv1.2 -fsSL -o "$WORK/checksums.txt" "$BASE/checksums.txt"
curl --proto =https --tlsv1.2 -fsSL -o "$WORK/checksums.txt.sigstore.json" "$BASE/checksums.txt.sigstore.json" || true

if command -v cosign >/dev/null; then
	echo "Verifying the checksum signature..."
	cosign verify-blob \
		--bundle "$WORK/checksums.txt.sigstore.json" \
		--certificate-identity-regexp "^https://github.com/$REPO/\.github/workflows/release\.yml@refs/tags/v" \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com \
		"$WORK/checksums.txt"
elif [ "$ALLOW_UNSIGNED" -eq 1 ]; then
	echo "WARNING: cosign is not installed; the signature was NOT verified (--allow-unsigned)." >&2
else
	echo "cosign is required to verify the release signature. Install it (https://docs.sigstore.dev/cosign/) or pass --allow-unsigned to accept the risk." >&2
	exit 1
fi

echo "Verifying the package checksum..."
(cd "$WORK" && awk -v f="$PKG" '$2 == f' checksums.txt | sha256sum -c -) || { echo "checksum mismatch: refusing to install" >&2; exit 1; }

echo "Installing..."
if [ "$KIND" = deb ]; then
	dpkg -i "$WORK/$PKG"
else
	rpm -U "$WORK/$PKG"
fi
