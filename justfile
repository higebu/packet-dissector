# Development tasks for packet-dissector
#
# Release and publish are handled by release-plz (see .github/workflows/publish.yml).
#
# Usage:
#   just          # list available recipes
#   just check    # run all CI checks

# List available recipes
default:
    @just --list

# Run all CI checks (same as .github/workflows/ci.yml)
check:
    cargo test --all-targets
    cargo clippy --all-targets -- -D warnings
    cargo fmt -- --check
    taplo fmt --check
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# Run tests only
test:
    cargo test --all-targets
