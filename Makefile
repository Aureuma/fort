.PHONY: build check test gates gates-check gates-test gates-smoke gates-release

build:
	./scripts/build-guard.sh cargo build --jobs 2

check:
	./scripts/build-guard.sh cargo check --all-targets --all-features --jobs 2

test:
	./scripts/build-guard.sh cargo test --all-features --jobs 2

gates:
	./scripts/local-gates.sh all

gates-check:
	./scripts/local-gates.sh check

gates-test:
	./scripts/local-gates.sh test

gates-smoke:
	./scripts/local-gates.sh smoke

gates-release:
	./scripts/local-gates.sh release
