# Infrastructure Archaeologist — local validation entrypoints.

.PHONY: build test lint check cross bench benchmark

build:
	go build ./...

test:
	go test ./...

lint:
	golangci-lint run ./...

## check: the three gates CI will run (build, test, lint).
check: build test lint

## bench: correlation quality report on the golden fixture.
bench:
	go run ./cmd/bench --db lab/fixtures/scan.db --gt lab/ground-truth.yaml --out bench-results/history.jsonl

## benchmark: alias of bench (authority docs use this name).
benchmark: bench

## cross: verify linux/amd64 + linux/arm64 binaries compile.
cross:
	GOOS=linux GOARCH=amd64 go build -o /tmp/archaeologist-amd64 ./cmd/archaeologist
	GOOS=linux GOARCH=arm64 go build -o /tmp/archaeologist-arm64 ./cmd/archaeologist
	@echo "cross-compile OK: amd64 + arm64"
