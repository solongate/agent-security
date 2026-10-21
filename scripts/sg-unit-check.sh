#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 the SolonGate contributors

# Checks gofmt, go vet and go test across every Go module in this repository.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

for m in guard policy shared sandbox core cli tui app; do
  echo "== packages/$m =="
  (cd "packages/$m" && gofmt -l . && go vet ./... && go test -count=1 ./...)
done