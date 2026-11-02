#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")"
mkdir -p _build/go-cache
export GOCACHE="$PWD/_build/go-cache"
export GOTOOLCHAIN=local GOWORK=off GOENV=off GOFLAGS='' GOPACKAGESDRIVER=off
export GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOPROXY=off GOSUMDB=off
go mod verify
go test -count=1 ./cmd/source-contracts
go run ./cmd/source-contracts -repo ../..
