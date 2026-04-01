# Development and release tasks for packet-dissector
#
# Usage:
#   just          # list available recipes
#   just check    # run all CI checks
#   just publish  # publish all crates to crates.io (dry-run first)

# Publish delay between crates (seconds) for crates.io index propagation
publish_delay := "10"

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

# Generate CHANGELOG from git history
changelog:
    git-cliff -o CHANGELOG.md

# Publish all crates in dependency order (called from GitHub Actions)
publish:
    #!/usr/bin/env bash
    set -euo pipefail

    mapfile -t crates < <(
        cargo metadata --format-version 1 --no-deps | jq -r '
          (.packages[].name | "\(.) \(.)"),
          (.packages[] |
            .name as $name |
            .dependencies[] |
            select(.path != null) |
            "\(.name) \($name)")
        ' | tsort
    )

    echo "Publishing ${#crates[@]} crates..."
    for crate in "${crates[@]}"; do
        echo "Publishing $crate..."
        if output=$(cargo publish -p "$crate" 2>&1); then
            echo "  Waiting {{publish_delay}}s for index propagation..."
            sleep {{publish_delay}}
        elif echo "$output" | grep -q "already exists"; then
            echo "  Already published, skipping"
        else
            echo "$output"
            exit 1
        fi
    done

    echo "All crates published successfully!"

# Bump version, update README, generate changelog, commit, and tag
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    major_minor=$(echo "{{version}}" | cut -d. -f1-2)
    cargo release version {{version}} --execute --no-confirm
    sed -i "s/packet-dissector = \"[0-9]*\.[0-9]*\"/packet-dissector = \"${major_minor}\"/g" README.md
    sed -i "s/version = \"[0-9]*\.[0-9]*\"/version = \"${major_minor}\"/g" README.md
    git-cliff --tag "v{{version}}" -o CHANGELOG.md
    git add -A
    git commit -m "chore(release): v{{version}}"
    git tag -a "v{{version}}" -m "v{{version}}"
    echo "Review the commit, then run: git push --follow-tags"
