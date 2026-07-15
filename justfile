[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

lint:
    cargo fmt --all -- --check
    # We do these standalone checks to not have wrong passes due to workspace dependencies
    # So we cd into the subcrate and run the checks as if it was standalone
    just lint-subcrate poseidon2
    just lint-subcrate eddsa-babyjubjub
    # ark-babyjubjub intentionally does not opt into the workspace lints
    just lint-subcrate ark-babyjubjub

lint-subcrate SUBCRATE:
    cd {{ SUBCRATE }} && cargo all-features clippy --all-targets -q -- -D warnings
    cd {{ SUBCRATE }} && RUSTDOCFLAGS='-D warnings' cargo doc --all-features -q --no-deps

test:
    cargo test --workspace --all-features --all-targets

check-pr: lint test
