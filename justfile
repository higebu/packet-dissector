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

# Publish all crates to crates.io in dependency order.
# Runs dry-run first, then prompts for confirmation.
publish: check
    #!/usr/bin/env bash
    set -euo pipefail

    # Build crate list dynamically from workspace metadata in dependency order:
    #   1. core  2. reassembly, test-alloc  3. protocol crates (sorted)  4. facade
    core="packet-dissector-core"
    last="packet-dissector"
    early=("packet-dissector-reassembly" "packet-dissector-test-alloc")

    all_crates=$(cargo metadata --format-version 1 --no-deps \
        | jq -r '.packages[].name' \
        | sort)

    crates=("$core")
    for e in "${early[@]}"; do
        if echo "$all_crates" | grep -qx "$e"; then
            crates+=("$e")
        fi
    done
    while IFS= read -r c; do
        [[ "$c" == "$core" || "$c" == "$last" ]] && continue
        [[ " ${early[*]} " == *" $c "* ]] && continue
        crates+=("$c")
    done <<< "$all_crates"
    crates+=("$last")

    echo "=== Dry run ==="
    for crate in "${crates[@]}"; do
        echo "  Checking $crate..."
        cargo publish --dry-run -p "$crate" 2>&1 | tail -1
    done

    echo ""
    read -rp "Publish all ${#crates[@]} crates to crates.io? [y/N] " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Aborted."
        exit 1
    fi

    echo ""
    echo "=== Publishing ==="
    for crate in "${crates[@]}"; do
        echo "Publishing $crate..."
        cargo publish -p "$crate"
        echo "  Waiting {{publish_delay}}s for index propagation..."
        sleep {{publish_delay}}
    done

    echo ""
    echo "All crates published successfully!"

# Publish a single crate (for retrying after a failure)
publish-one crate:
    cargo publish -p {{crate}}

# Bump version, generate changelog, and commit
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo release version {{version}} --execute --no-confirm
    version=$(cargo metadata --format-version 1 --no-deps | python3 -c "import sys,json; print(json.load(sys.stdin)['packages'][0]['version'])")
    git-cliff --tag "v${version}" -o CHANGELOG.md
    git add -A
    git commit -m "chore(release): v${version}"
    git tag -a "v${version}" -m "v${version}"
    echo "Review the commit, then run: git push --follow-tags"
