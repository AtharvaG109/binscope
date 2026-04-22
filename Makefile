.PHONY: fmt check test ci

fmt:
	cargo fmt

check:
	cargo check --offline

test:
	cargo test --offline

ci: fmt check test
