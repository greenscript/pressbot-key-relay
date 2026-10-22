#!/usr/bin/env bash
# Creates a relay token for PressBot. Prints nothing secret to the terminal.
#
#   scripts/new-token.sh                                  # token -> clipboard (or a 0600 file), prints the hash
#   scripts/new-token.sh --apply --existing "hash1,hash2" # also runs `wrangler secret put RELAY_TOKEN_HASHES`
#   scripts/new-token.sh --apply                          # --apply alone REPLACES the list (revokes all other tokens)
#
# Wrangler cannot read an existing secret, so to keep older tokens working pass their hashes in --existing.
set -euo pipefail

APPLY=0
EXISTING=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --existing) shift; EXISTING="${1:-}" ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

TOKEN="pbr_$(openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
HASH="$(printf '%s' "$TOKEN" | openssl dgst -sha256 | awk '{print $NF}')"

if command -v pbcopy >/dev/null 2>&1; then
  printf '%s' "$TOKEN" | pbcopy
  echo "Token copied to your clipboard. Paste it into PressBot now, then clear your clipboard."
else
  FILE="./relay-token-$(date +%Y%m%d-%H%M%S).token"
  ( umask 077; printf '%s' "$TOKEN" > "$FILE" )
  chmod 600 "$FILE"
  echo "pbcopy not found. Token written to: $FILE (chmod 600). Paste it into PressBot, then delete the file."
fi

echo "Token hash (safe to share): $HASH"

if [ "$APPLY" -eq 1 ]; then
  LIST="$HASH"
  [ -n "$EXISTING" ] && LIST="$EXISTING,$HASH"
  printf '%s' "$LIST" | npx wrangler secret put RELAY_TOKEN_HASHES
  echo "RELAY_TOKEN_HASHES updated ($(echo "$LIST" | tr ',' '\n' | wc -l | tr -d ' ') hash(es))."
else
  echo "Add it to the relay: set RELAY_TOKEN_HASHES to a comma-separated list that includes this hash,"
  echo "then run: npx wrangler secret put RELAY_TOKEN_HASHES"
fi
