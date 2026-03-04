#!/usr/bin/env bash
set -euo pipefail
mkdir -p artifacts
VERSION="${1:-latest}"
if [[ "$VERSION" != "latest" ]]; then
  mkdir -p "artifacts/${VERSION}"
fi
GOOS=linux GOARCH=amd64 go build -o artifacts/astrality-agent-linux-amd64 ./cmd/agent
GOOS=linux GOARCH=arm64 go build -o artifacts/astrality-agent-linux-arm64 ./cmd/agent
if [[ "$VERSION" != "latest" ]]; then
  cp artifacts/astrality-agent-linux-amd64 "artifacts/${VERSION}/"
  cp artifacts/astrality-agent-linux-arm64 "artifacts/${VERSION}/"
fi
