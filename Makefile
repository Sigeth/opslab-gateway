# Contract library, tested at its newest tag by contract-latest.
CORE_RS_GIT := https://github.com/Sigeth/opslab-core-rs
IMG ?= ghcr.io/sigeth/opslab-gateway:dev
CONTAINER_TOOL ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

.PHONY: all build run test lint deny image contract-latest

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

## contract-latest: build and test against the newest opslab-core-rs tag (CI),
## through a Cargo patch so Cargo.toml and Cargo.lock are not changed
contract-latest:
	@set -e; tmp=$$(mktemp -d); cp Cargo.lock "$$tmp/"; \
	trap 'cp "$$tmp/Cargo.lock" Cargo.lock; rm -rf "$$tmp"' EXIT; \
	tag=$$(git ls-remote --tags --refs --sort=-v:refname $(CORE_RS_GIT) 'v*' | head -n1 | sed 's|.*refs/tags/||'); \
	echo "== opslab-core-rs $$tag"; \
	git clone -q --depth 1 --branch "$$tag" $(CORE_RS_GIT) "$$tmp/core-rs"; \
	patch="patch.'$(CORE_RS_GIT)'.opslab-auth.path='$$tmp/core-rs/crates/opslab-auth'"; \
	cargo test --config "$$patch" 2>"$$tmp/err" || { cat "$$tmp/err"; exit 1; }; \
	cat "$$tmp/err"; \
	if grep -q 'was not used in the crate graph' "$$tmp/err"; then \
	  echo "opslab-core-rs $$tag does not match the version requirement in Cargo.toml: bump it"; exit 1; \
	fi
