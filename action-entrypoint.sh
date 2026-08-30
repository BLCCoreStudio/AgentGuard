#!/usr/bin/env bash
set -euo pipefail

policy="${AGENTGUARD_INPUT_POLICY:-privacy}"
format="${AGENTGUARD_INPUT_FORMAT:-text}"
workspace="${AGENTGUARD_INPUT_PATH:-.}"

case "$policy" in
  privacy|clean) ;;
  *)
    echo "ERROR: policy must be 'privacy' or 'clean'" >&2
    exit 2
    ;;
esac

case "$format" in
  text|json) ;;
  *)
    echo "ERROR: format must be 'text' or 'json'" >&2
    exit 2
    ;;
esac

manifest="$GITHUB_ACTION_PATH/Cargo.toml"
cargo build --release --locked --manifest-path "$manifest"
binary="$GITHUB_ACTION_PATH/target/release/agentguard"
test -x "$binary"

revision="${AGENTGUARD_INPUT_REVISION:-}"
if [[ -z "$revision" && -n "${AGENTGUARD_PR_BASE_SHA:-}" && -n "${AGENTGUARD_PR_HEAD_SHA:-}" ]]; then
  revision="${AGENTGUARD_PR_BASE_SHA}..${AGENTGUARD_PR_HEAD_SHA}"
fi

args=(scan-git "$workspace" --policy "$policy" --format "$format")
if [[ -n "$revision" ]]; then
  args+=(--rev "$revision")
fi

"$binary" "${args[@]}"
