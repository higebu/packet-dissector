#!/usr/bin/env bash
# release-plz shares one git tag across the whole workspace (see
# release-plz.toml) and treats a package as "already published" once that
# tag exists, even if the package itself was never `cargo publish`ed - e.g.
# a new crate added to the workspace after the last release tag, whose
# version therefore matches an already-tagged version it was never actually
# part of. This step runs before release-plz and force-publishes any
# workspace crate that crates.io doesn't actually have yet, so newly added
# crates don't require a manual `cargo publish` outside CI.
set -euo pipefail

# crates.io rejects requests with no descriptive User-Agent (returns 403),
# per https://crates.io/data-access.
user_agent="packet-dissector-ci (+https://github.com/higebu/packet-dissector)"

metadata=$(cargo metadata --format-version 1 --no-deps)

mapfile -t candidates < <(jq -r '
  .packages[]
  | select(.publish == null or (.publish | length) > 0)
  | "\(.name)\t\(.version)"
' <<<"$metadata")

missing=()
for entry in "${candidates[@]}"; do
  name=${entry%%$'\t'*}
  version=${entry#*$'\t'}
  status=$(curl -s -o /dev/null -w '%{http_code}' -A "$user_agent" \
    "https://crates.io/api/v1/crates/${name}/${version}")
  if [ "$status" != "200" ]; then
    missing+=("$name")
  fi
done

if [ "${#missing[@]}" -eq 0 ]; then
  echo "All workspace crates already published at their current version."
  exit 0
fi

echo "Not yet on crates.io: ${missing[*]}"

# Retry until a full pass makes no progress, so crates that depend on
# another crate in this same batch get published in the right order
# without having to compute the dependency graph up front.
remaining=("${missing[@]}")
while [ "${#remaining[@]}" -gt 0 ]; do
  next_remaining=()
  progressed=0
  for name in "${remaining[@]}"; do
    echo "::group::cargo publish -p ${name}"
    if cargo publish -p "$name" --no-verify; then
      progressed=1
    else
      echo "::warning::${name} did not publish this pass, will retry"
      next_remaining+=("$name")
    fi
    echo "::endgroup::"
  done
  if [ "$progressed" -eq 0 ]; then
    echo "::error::Could not publish: ${next_remaining[*]}"
    exit 1
  fi
  remaining=("${next_remaining[@]}")
done
