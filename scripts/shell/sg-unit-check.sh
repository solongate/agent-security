#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# gofmt, go vet and go test across every Go module in this repository.
#
#   ./scripts/shell/sg-unit-check.sh
#
# Each package under packages/ is its own go.mod, so a single `go test ./...`
# at the repo root never reaches the rest. This loops over the ones that
# have Go code and checks each in turn.
set -eu

REPO=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO"

for m in guard policy shared sandbox core cli tui app; do
  echo "== packages/$m =="
  (cd "packages/$m" && gofmt -l . && go vet ./... && go test -count=1 ./...)
done