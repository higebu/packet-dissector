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
#
# `--detect-new` only looks up which crates are new and writes them to
# $GITHUB_OUTPUT as `new_crates`, so the workflow can hand NEW_CRATE_TOKEN
# to the publish step only in runs that actually create a crate.
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

# Escapes text for a GitHub Actions workflow command such as `::error::`,
# so a multi-line message is not cut at the first newline.
gh_escape() {
  local s="$1"
  s=${s//%/%25}
  s=${s//$'\r'/%0D}
  s=${s//$'\n'/%0A}
  printf '%s' "$s"
}

missing=()
declare -A is_new=()
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
      is_new[$name]=1
      new_crates+=("$name")
    fi
  fi
done

if [ "${1:-}" = "--detect-new" ]; then
  echo "New crates (not on crates.io at all): ${new_crates[*]:-none}"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "new_crates=${new_crates[*]}" >>"$GITHUB_OUTPUT"
  fi
  exit 0
fi

# Where the Trusted Publishing config for new crates points: the workflow
# that is running this script (GITHUB_WORKFLOW_REF is
# "owner/repo/.github/workflows/file.yml@ref"). The job's environment is not
# exposed to steps, so the workflow passes it as TRUSTPUB_ENVIRONMENT.
trustpub_repository="${GITHUB_REPOSITORY:-}"
trustpub_workflow="${GITHUB_WORKFLOW_REF:-}"
trustpub_workflow="${trustpub_workflow%%@*}"
trustpub_workflow="${trustpub_workflow##*/}"
trustpub_environment="${TRUSTPUB_ENVIRONMENT:-}"

# Calls the crates.io API with NEW_CRATE_TOKEN. The token is passed through
# a header file so it never appears in curl's argument list. Prints the
# HTTP status; the response body goes to the file named by $2.
api_call() {
  local method="$1" out="$2" url="$3" data="${4:-}" header status
  header=$(umask 077 && mktemp)
  printf 'Authorization: %s\n' "$NEW_CRATE_TOKEN" >"$header"
  if [ -n "$data" ]; then
    status=$(curl -s -o "$out" -w '%{http_code}' -A "$user_agent" -X "$method" \
      -H @"$header" -H "Content-Type: application/json" --data "$data" "$url") || status=000
  else
    status=$(curl -s -o "$out" -w '%{http_code}' -A "$user_agent" -X "$method" \
      -H @"$header" "$url") || status=000
  fi
  rm -f "$header"
  echo "$status"
}

# Makes sure a crate has a GitHub Trusted Publishing config for this
# workflow, so its next release can use the Trusted Publishing token. It
# looks for an existing config first, so a retry after a lost response does
# not create a duplicate.
ensure_trusted_publishing() {
  local name="$1" response status body attempt
  if [ -z "$trustpub_repository" ] || [ -z "$trustpub_workflow" ] || [ -z "$trustpub_environment" ]; then
    echo "::error::$(gh_escape "Cannot register Trusted Publishing for ${name}: GITHUB_REPOSITORY, GITHUB_WORKFLOW_REF and TRUSTPUB_ENVIRONMENT must be set.")"
    return 1
  fi
  response=$(mktemp)
  body=$(jq -n \
    --arg krate "$name" \
    --arg owner "${trustpub_repository%%/*}" \
    --arg repo "${trustpub_repository#*/}" \
    --arg workflow "$trustpub_workflow" \
    --arg environment "$trustpub_environment" \
    '{github_config: {crate: $krate, repository_owner: $owner, repository_name: $repo, workflow_filename: $workflow, environment: $environment}}')
  for attempt in 1 2 3; do
    status=$(api_call GET "$response" "https://crates.io/api/v1/trusted_publishing/github_configs?crate=${name}")
    if [ "$status" = "200" ] && jq -e --argjson want "$body" '
        any(.github_configs[];
          .repository_owner == $want.github_config.repository_owner
          and .repository_name == $want.github_config.repository_name
          and .workflow_filename == $want.github_config.workflow_filename
          and .environment == $want.github_config.environment)' "$response" >/dev/null; then
      echo "Trusted Publishing config for ${name} is in place (${trustpub_repository}, ${trustpub_workflow}, environment ${trustpub_environment})."
      rm -f "$response"
      return 0
    fi
    status=$(api_call POST "$response" "https://crates.io/api/v1/trusted_publishing/github_configs" "$body")
    case "$status" in
      200)
        echo "Registered Trusted Publishing config for ${name} (${trustpub_repository}, ${trustpub_workflow}, environment ${trustpub_environment})."
        rm -f "$response"
        return 0
        ;;
      000 | 429 | 5??)
        sleep 5
        ;;
      *)
        break
        ;;
    esac
  done
  echo "::error::$(gh_escape "Published new crate ${name}, but registering its Trusted Publishing config failed (HTTP ${status}): $(cat "$response")
Add it at https://crates.io/crates/${name}/settings before the next release.")"
  rm -f "$response"
  return 1
}

if [ "${#missing[@]}" -eq 0 ]; then
  echo "All workspace crates already published at their current version."
  exit 0
fi

echo "Not yet on crates.io: ${missing[*]}"

failed=()
remaining=()
for name in "${missing[@]}"; do
  if [ -n "${is_new[$name]:-}" ] && [ -z "${NEW_CRATE_TOKEN:-}" ]; then
    # Keep publishing the other crates; this one needs the API token.
    echo "::error::$(gh_escape "${name} is a new crate and Trusted Publishing cannot create crates. Set NEW_CRATE_TOKEN (an API token with the publish-new and trusted-publishing scopes) or publish it manually once.")"
    failed+=("$name")
  else
    remaining+=("$name")
  fi
done

# Retry until a full pass makes no progress, so crates that depend on
# another crate in this same batch get published in the right order
# without having to compute the dependency graph up front. A pass can also
# stall because crates.io hasn't finished propagating a just-published
# dependency to its index yet, so tolerate a few stalled passes with a
# backoff before giving up, instead of failing on the first one.
#
# crates.io allows only a few new crates per user in a burst and then one
# per 10 minutes. Waiting that out would burn Actions minutes, so once it
# answers 429 for a new crate, the remaining new crates are deferred to the
# next run of this workflow (the next push to main) instead of retried here.
stalls=0
max_stalls=5
deferred=()
new_crate_limited=0
while [ "${#remaining[@]}" -gt 0 ]; do
  next_remaining=()
  progressed=0
  for name in "${remaining[@]}"; do
    if [ -n "${is_new[$name]:-}" ] && [ "$new_crate_limited" -eq 1 ]; then
      deferred+=("$name")
      continue
    fi
    echo "::group::cargo publish -p ${name}"
    token="$CARGO_REGISTRY_TOKEN"
    if [ -n "${is_new[$name]:-}" ]; then
      token="$NEW_CRATE_TOKEN"
    fi
    published=0
    publish_log=$(mktemp)
    if CARGO_REGISTRY_TOKEN="$token" cargo publish -p "$name" --no-verify 2>&1 | tee "$publish_log"; then
      published=1
    elif [ -n "${is_new[$name]:-}" ] && grep -q "published too many new crates" "$publish_log"; then
      new_crate_limited=1
      echo "::warning::$(gh_escape "crates.io rate-limited new crates: $(sed -n 's/.*\(Please try again after [^G]*GMT\).*/\1/p' "$publish_log" | head -n 1). Deferring the remaining new crates to the next run.")"
      deferred+=("$name")
      rm -f "$publish_log"
      echo "::endgroup::"
      continue
    elif [ -n "${is_new[$name]:-}" ]; then
      # The upload may have reached crates.io even though cargo failed
      # afterwards; retrying would then only hit "already exists" and the
      # crate would never get its Trusted Publishing config.
      version=$(jq -r --arg n "$name" '.packages[] | select(.name == $n) | .version' <<<"$metadata")
      recheck=$(lookup_status "$name" "$version")
      if [ "$recheck" = "200" ]; then
        published=1
      fi
    fi
    if [ "$published" -eq 1 ]; then
      progressed=1
      if [ -n "${is_new[$name]:-}" ]; then
        ensure_trusted_publishing "$name" || failed+=("$name")
      fi
    else
      echo "::warning::${name} did not publish this pass, will retry"
      next_remaining+=("$name")
    fi
    rm -f "$publish_log"
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
      failed+=("${remaining[@]}")
      break
    fi
    echo "No progress this pass (stall ${stalls}/${max_stalls}), waiting for crates.io index propagation..."
    sleep 15
  else
    stalls=0
  fi
done

if [ "${#deferred[@]}" -gt 0 ]; then
  echo "::warning::$(gh_escape "Deferred by the crates.io new-crate rate limit, retried on the next push to main (or re-run this workflow later): ${deferred[*]}")"
fi

if [ "${#failed[@]}" -gt 0 ]; then
  echo "::error::Not published or missing a Trusted Publishing config: ${failed[*]}"
  exit 1
fi
