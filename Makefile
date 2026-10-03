# Infrastructure Archaeologist — local validation entrypoints.
# Authority: product-backlog.md US-0.4 (CI runs build+test+lint).

.PHONY: build test lint check cross

build:
	go build ./...

test:
	go test ./...

lint:
	golangci-lint run ./...

## check: the three gates CI will run (build, test, lint).
check: build test lint

## cross: verify linux/amd64 + linux/arm64 binaries compile (US-0.4 AC).
cross:
	GOOS=linux GOARCH=amd64 go build -o /tmp/archaeologist-amd64 ./cmd/archaeologist
	GOOS=linux GOARCH=arm64 go build -o /tmp/archaeologist-arm64 ./cmd/archaeologist
	@echo "cross-compile OK: amd64 + arm64"
