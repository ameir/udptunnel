#!/bin/bash
set -euo pipefail

BIN=$(basename "$PWD")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
LDFLAGS="-s -w -X main.buildTime=${BUILD_TIME} -X main.gitCommit=${GIT_COMMIT}"

mkdir -p dist

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="${LDFLAGS}" -o "dist/${BIN}_linux_amd64"
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="${LDFLAGS}" -o "dist/${BIN}_linux_armv7"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="${LDFLAGS}" -o "dist/${BIN}_linux_arm64"
