#!/bin/bash
set -euo pipefail

BIN=$(basename "$PWD")
mkdir -p dist

GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "dist/${BIN}_linux_amd64"
GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="-s -w" -o "dist/${BIN}_linux_armv7"
