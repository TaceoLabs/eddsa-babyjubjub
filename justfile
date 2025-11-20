[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

lint:
    cargo fmt --all -- --check
    cargo all-features clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    cargo clippy --no-default-features --workspace --tests --examples --benches --bins -q -- -D warnings
    cargo clippy --features="full" --workspace --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo all-features doc --workspace -q --no-deps

test:
    cargo test --workspace --profile ci-dev --all-features --all-targets

check-pr: lint test
