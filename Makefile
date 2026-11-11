IMG ?= ghcr.io/sigeth/opslab-gateway:dev
CONTAINER_TOOL ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

.PHONY: all build run test lint deny image

all: lint test build

build:
	cargo build --release

## run: run locally on :8081 (set OPSLAB_JWKS_URL to a running api)
run:
	cargo run

test:
	cargo test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

deny:
	cargo deny check

image:
	$(CONTAINER_TOOL) build --platform linux/amd64 -t $(IMG) .
