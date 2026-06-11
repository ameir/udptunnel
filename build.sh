#!/bin/bash
set -euo pipefail

BIN=$(basename "$PWD")
mkdir -p dist

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "dist/${BIN}_linux_amd64"
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="-s -w" -o "dist/${BIN}_linux_armv7"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "dist/${BIN}_linux_arm64"
