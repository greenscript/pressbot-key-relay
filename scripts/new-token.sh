#!/usr/bin/env bash
# Creates a relay token for PressBot. Prints nothing secret to the terminal.
#
#   scripts/new-token.sh                                  # token -> clipboard (or a 0600 file), prints the hash
#   scripts/new-token.sh --file                           # write the token to a 0600 file instead of the clipboard
#   scripts/new-token.sh --apply --existing "hash1,hash2" # also runs `wrangler secret put RELAY_TOKEN_HASHES`
#   scripts/new-token.sh --apply                          # --apply alone REPLACES the list (revokes all other tokens)
#
# Wrangler cannot read an existing secret, so to keep older tokens working pass their hashes in --existing.
set -euo pipefail

APPLY=0
USE_FILE=0
EXISTING=""
HAVE_EXISTING=0
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --file) USE_FILE=1 ;;
    --existing)
      if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
        echo "--existing needs a value: a comma-separated list of 64-character hex hashes." >&2; exit 1
      fi
      shift; EXISTING="$1"; HAVE_EXISTING=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

# Validate before generating anything, so a typo never reaches wrangler.
if [ "$HAVE_EXISTING" -eq 1 ]; then
  IFS=',' read -r -a EXISTING_ARR <<< "$EXISTING"
  for h in "${EXISTING_ARR[@]}"; do
    if ! [[ "$h" =~ ^[0-9a-f]{64}$ ]]; then
      echo "Invalid hash in --existing (each must be 64 lowercase hex characters): '${h:0:12}...'" >&2; exit 1
    fi
  done
fi

TOKEN="pbr_$(openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
HASH="$(printf '%s' "$TOKEN" | openssl dgst -sha256 | awk '{print $NF}')"

if [ "$USE_FILE" -eq 0 ] && command -v pbcopy >/dev/null 2>&1; then
  printf '%s' "$TOKEN" | pbcopy
  echo "Token copied to your clipboard. Paste it into PressBot now, then clear your clipboard."
else
  FILE="./relay-token-$(date +%Y%m%d-%H%M%S).token"
  ( umask 077; printf '%s' "$TOKEN" > "$FILE" )
  chmod 600 "$FILE"
  echo "Token written to: $FILE (chmod 600). Paste it into PressBot, then delete the file."
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
