# pressbot-key-relay

A tiny Cloudflare Worker that holds your AI provider key so your WordPress site never stores it. The real key lives as a secret in **your own Cloudflare account** (the free plan is enough). PressBot only gets a limited **relay token**: it works only through this relay, only from your server's IP, only for the models you allow, and you can revoke it in one step without touching your provider key. Release R1 supports Anthropic only.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/greenscript/pressbot-key-relay)

```
WordPress (PressBot)             Your Cloudflare account              Anthropic
  relay URL + relay token  --->  Worker: check token, IP, model,  --->  api.anthropic.com
  (no provider key)              limits; add the real key               (real key only here)
```

## Setup

1. Deploy: click the button above, or `npm install && npx wrangler deploy`.
2. Store your Anthropic key (it is never written to any file):
   `npx wrangler secret put ANTHROPIC_API_KEY`
3. Create a token: `scripts/new-token.sh`. It copies the token to your clipboard (or writes a `chmod 600` file if `pbcopy` is missing) and prints only the SHA-256 hash. Paste the token into PressBot.
4. Store the hash: `npx wrangler secret put RELAY_TOKEN_HASHES` (comma-separated, several allowed for rotation). Or run `scripts/new-token.sh --apply --existing "<hash1,hash2>"` to do steps 3 and 4 together. Wrangler cannot read an existing secret, so `--existing` is how you keep older tokens; `--apply` alone replaces the list.
5. Lock to your server: call `GET /health` with the token (PressBot does this for you); `your_ip` is the address your server connects from. Set it in `wrangler.toml` as `ALLOWED_IPS = "203.0.113.7"` (comma-separated IPv4/IPv6, IPv4 CIDRs also work) and redeploy. Empty means the lock is off.
6. Revoke a token: remove its hash from the list and run `npx wrangler secret put RELAY_TOKEN_HASHES` again. The token stops working immediately. Your provider key does not change.

## Interface

- `POST /anthropic/v1/messages` and `POST /anthropic/v1/messages/count_tokens`: same body as Anthropic's API, with `Authorization: Bearer <relay token>`. Streaming (SSE) passes through unbuffered.
- `GET /health` (token required, does not call Anthropic): returns the relay version, allowed models, caps, whether the IP lock is on, and `your_ip`.
- Errors use Anthropic's shape: `{"type":"error","error":{"type":"relay_error","code":"...","message":"..."}}`. Codes: `token_missing`, `token_invalid`, `ip_not_allowed`, `model_not_allowed`, `max_tokens_exceeded`, `bad_request`, `rate_limited`, `not_found`, `method_not_allowed`, `relay_misconfigured`, `upstream_unreachable`.

## Settings (`wrangler.toml`)

| Variable | Default | Meaning |
|---|---|---|
| `ALLOWED_MODELS` | `claude-haiku-5-5,claude-sonnet-5-5` | Exact model names the token may use |
| `MAX_TOKENS_CAP` | `16000` | Requests above this `max_tokens` are rejected |
| `ALLOWED_IPS` | empty (off) | Only these callers are accepted |
| `RATE_LIMIT_PER_MINUTE` | `60` | Shown by `/health`; the real limit is `[ratelimits.simple]` in the same file, so keep them equal |

Requests are limited per token (60 per 60 seconds) with Cloudflare's rate limiting binding; limits are approximate and counted per Cloudflare location. If the binding is removed, rate limiting is skipped. Request bodies over 2 MB are rejected.

## What it protects, and what it doesn't

| If an attacker... | Result |
|---|---|
| Runs code on your WordPress server | Gets the relay token, not your key. The token is useless from other IPs, limited to allowed models, rate limited, and revocable |
| Reads a database dump | Nothing usable |
| Controls the server for a while | Can still send requests through the relay from that server, within its limits. The relay prevents theft of the key, not all abuse (a daily spend cap and alerts are planned for R2) |
| Breaks into your Cloudflare account | Can read the Worker secret. Use Cloudflare 2FA |

The relay forwards only to fixed Anthropic URLs. It is not an open proxy.

## Privacy

Logs contain metadata only: time, path, model, status, and token counts for non-streaming responses. Never prompts, answers, relay tokens or keys.

## Development

`npm test` (vitest), `npx tsc`, `npx wrangler deploy --dry-run`. MIT licensed, copyright GreenScript.
