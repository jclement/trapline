#!/usr/bin/env bash
# Run trapline e2e tests
# Usage: ./e2e/run.sh
#
# Builds the trapline binary for Linux, then runs the e2e test suite
# which spins up Docker containers and verifies behavior.

set -euo pipefail

cd "$(dirname "$0")/.."

# Detect architecture to match Docker's platform
ARCH="$(go env GOARCH)"
echo "==> Building trapline binary for linux/${ARCH}..."
CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" go build -o e2e/trapline ./cmd/trapline

echo "==> Running e2e tests..."
cd e2e
go test -tags e2e -v -timeout 5m .

echo "==> Cleaning up..."
rm -f trapline
docker rmi trapline-e2e 2>/dev/null || true

echo "==> Done!"
