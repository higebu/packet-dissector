#!/usr/bin/env bash
# release-plz shares one git tag across the whole workspace (see
# release-plz.toml) and treats a package as "already published" once that
# tag exists, even if the package itself was never `cargo publish`ed - e.g.
# a new crate added to the workspace after the last release tag, whose
# version therefore matches an already-tagged version it was never actually
# part of. This step runs before release-plz and force-publishes any
# workspace crate that crates.io doesn't actually have yet, so newly added
# crates don't require a manual `cargo publish` outside CI.
#
# Trusted Publishing tokens cannot create a crate that does not exist on
# crates.io yet (crates.io answers 403 "Trusted Publishing tokens do not
# support creating new crates"). Crates that are new to crates.io are
# therefore published with NEW_CRATE_TOKEN, a regular API token with the
# `publish-new` and `trusted-publishing` scopes, and a GitHub Trusted
# Publishing config for this workflow is registered right after, so later
# releases of that crate go through Trusted Publishing like every other
# crate. New versions of existing crates keep using CARGO_REGISTRY_TOKEN
# (the Trusted Publishing token).
set -euo pipefail

# Where the Trusted Publishing config for new crates points. These must
# match the workflow that runs this script.
trustpub_owner="${TRUSTPUB_REPOSITORY_OWNER:-higebu}"
trustpub_repo="${TRUSTPUB_REPOSITORY_NAME:-packet-dissector}"
trustpub_workflow="${TRUSTPUB_WORKFLOW_FILENAME:-publish.yml}"
trustpub_environment="${TRUSTPUB_ENVIRONMENT:-release}"

# crates.io rejects requests with no descriptive User-Agent (returns 403),
# per https://crates.io/data-access.
user_agent="packet-dissector-ci (+https://github.com/higebu/packet-dissector)"

metadata=$(cargo metadata --format-version 1 --no-deps)

mapfile -t candidates < <(jq -r '
  .packages[]
  | select(.publish == null or (.publish | length) > 0)
  | "\(.name)\t\(.version)"
' <<<"$metadata")

# Only 404 means "not on crates.io yet". A 429/5xx is a registry hiccup, not
# proof of absence - treating it as "missing" would start an irreversible
# publish pass on bad information, so retry it a few times and abort the
# whole run rather than guess.
lookup_status() {
  local name="$1" version="$2" attempt status
  for attempt in 1 2 3; do
    status=$(curl -s -o /dev/null -w '%{http_code}' -A "$user_agent" \
      "https://crates.io/api/v1/crates/${name}${version:+/${version}}")
    case "$status" in
      200 | 404)
        echo "$status"
        return 0
        ;;
    esac
    sleep 5
  done
  echo "::error::crates.io returned HTTP ${status} for ${name} ${version} after ${attempt} attempts" >&2
  exit 1
}

missing=()
new_crates=()
for entry in "${candidates[@]}"; do
  name=${entry%%$'\t'*}
  version=${entry#*$'\t'}
  # Assign first so a lookup that gives up aborts the script under `set -e`
  # instead of being swallowed by the `[` test.
  version_status=$(lookup_status "$name" "$version")
  if [ "$version_status" = "404" ]; then
    missing+=("$name")
    # The version is missing; a 404 for the crate itself means the crate
    # was never published, so it has to be created.
    crate_status=$(lookup_status "$name" "")
    if [ "$crate_status" = "404" ]; then
      new_crates+=("$name")
    fi
  fi
done

is_new_crate() {
  local name="$1" c
  for c in "${new_crates[@]}"; do
    [ "$c" = "$name" ] && return 0
  done
  return 1
}

# Registers a GitHub Trusted Publishing config for a crate that was just
# created, so its next release can use the Trusted Publishing token.
register_trusted_publishing() {
  local name="$1" body status response
  response=$(mktemp)
  body=$(jq -n \
    --arg krate "$name" \
    --arg owner "$trustpub_owner" \
    --arg repo "$trustpub_repo" \
    --arg workflow "$trustpub_workflow" \
    --arg environment "$trustpub_environment" \
    '{github_config: {crate: $krate, repository_owner: $owner, repository_name: $repo, workflow_filename: $workflow, environment: $environment}}')
  status=$(curl -s -o "$response" -w '%{http_code}' -A "$user_agent" \
    -X POST "https://crates.io/api/v1/trusted_publishing/github_configs" \
    -H "Authorization: ${NEW_CRATE_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "$body")
  if [ "$status" != "200" ]; then
    echo "::error::Published new crate ${name}, but registering its Trusted Publishing config failed (HTTP ${status}): $(cat "$response"). Add it at https://crates.io/crates/${name}/settings before the next release."
    rm -f "$response"
    return 1
  fi
  rm -f "$response"
  echo "Registered Trusted Publishing config for ${name} (${trustpub_owner}/${trustpub_repo}, ${trustpub_workflow}, environment ${trustpub_environment})."
}

if [ "${#missing[@]}" -eq 0 ]; then
  echo "All workspace crates already published at their current version."
  exit 0
fi

echo "Not yet on crates.io: ${missing[*]}"

if [ "${#new_crates[@]}" -gt 0 ]; then
  echo "New crates (not on crates.io at all): ${new_crates[*]}"
  if [ -z "${NEW_CRATE_TOKEN:-}" ]; then
    echo "::error::Trusted Publishing cannot create new crates. Set NEW_CRATE_TOKEN (an API token with the publish-new and trusted-publishing scopes) or publish these crates manually once: ${new_crates[*]}"
    exit 1
  fi
fi

trustpub_failed=()

# Retry until a full pass makes no progress, so crates that depend on
# another crate in this same batch get published in the right order
# without having to compute the dependency graph up front. A pass can also
# stall because crates.io hasn't finished propagating a just-published
# dependency to its index yet, so tolerate a few stalled passes with a
# backoff before giving up, instead of failing on the first one.
remaining=("${missing[@]}")
stalls=0
max_stalls=5
while [ "${#remaining[@]}" -gt 0 ]; do
  next_remaining=()
  progressed=0
  for name in "${remaining[@]}"; do
    echo "::group::cargo publish -p ${name}"
    if is_new_crate "$name"; then
      if CARGO_REGISTRY_TOKEN="$NEW_CRATE_TOKEN" cargo publish -p "$name" --no-verify; then
        progressed=1
        register_trusted_publishing "$name" || trustpub_failed+=("$name")
      else
        echo "::warning::${name} did not publish this pass, will retry"
        next_remaining+=("$name")
      fi
    elif cargo publish -p "$name" --no-verify; then
      progressed=1
    else
      echo "::warning::${name} did not publish this pass, will retry"
      next_remaining+=("$name")
    fi
    echo "::endgroup::"
  done
  remaining=("${next_remaining[@]}")
  if [ "${#remaining[@]}" -eq 0 ]; then
    break
  fi
  if [ "$progressed" -eq 0 ]; then
    stalls=$((stalls + 1))
    if [ "$stalls" -ge "$max_stalls" ]; then
      echo "::error::Could not publish after ${max_stalls} stalled passes: ${remaining[*]}"
      exit 1
    fi
    echo "No progress this pass (stall ${stalls}/${max_stalls}), waiting for crates.io index propagation..."
    sleep 15
  else
    stalls=0
  fi
done

if [ "${#trustpub_failed[@]}" -gt 0 ]; then
  echo "::error::Trusted Publishing config missing for: ${trustpub_failed[*]}"
  exit 1
fi
