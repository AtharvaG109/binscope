.PHONY: fmt check test smoke ci

fmt:
	cargo fmt

check:
	cargo check --offline

test:
	cargo test --offline

smoke:
	./scripts/json-smoke.sh

ci: fmt check test smoke
