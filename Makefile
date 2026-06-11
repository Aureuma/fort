.PHONY: build check test

build:
	./scripts/build-guard.sh cargo build --jobs 2

check:
	./scripts/build-guard.sh cargo check --all-targets --all-features --jobs 2

test:
	./scripts/build-guard.sh cargo test --all-features --jobs 2
