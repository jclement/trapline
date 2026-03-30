#!/bin/sh
# Trapline installer — curl -sSL https://raw.githubusercontent.com/jclement/tripline/main/install.sh | sudo bash
#
# Downloads the latest trapline binary for this architecture and runs `trapline install`.
set -eu

REPO="jclement/tripline"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

# --- helpers ----------------------------------------------------------------

die() { echo "ERROR: $*" >&2; exit 1; }

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "Unsupported architecture: $(uname -m). Trapline supports amd64 and arm64." ;;
  esac
}

# --- preflight --------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || die "Trapline only runs on Linux."
[ "$(id -u)" -eq 0 ]        || die "This installer must be run as root (try: curl ... | sudo bash)."
command -v curl >/dev/null   || die "curl is required but not found."

# --- download ----------------------------------------------------------------

ARCH="$(detect_arch)"
BINARY="trapline_linux_${ARCH}"
URL="${BASE_URL}/${BINARY}"
TMP="$(mktemp /tmp/trapline.XXXXXX)"

echo "Downloading trapline for linux/${ARCH}..."
curl -fsSL "${URL}" -o "${TMP}" || die "Download failed. Check ${URL}"
chmod +x "${TMP}"

# --- verify it runs ----------------------------------------------------------

"${TMP}" version >/dev/null 2>&1 || die "Downloaded binary failed to execute. Possible architecture mismatch."

# --- install -----------------------------------------------------------------

echo ""
"${TMP}" install

# --- cleanup -----------------------------------------------------------------

rm -f "${TMP}"

echo ""
echo "Done. Run 'trapline doctor' to verify the installation."
