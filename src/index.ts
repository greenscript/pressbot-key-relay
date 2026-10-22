// pressbot-key-relay: holds an AI provider key so a WordPress site never stores it.
// R1: Anthropic only. See README.md and the PressBot Key Security spec (section 6b).

import pkg from "../package.json";

export interface Env {
  ANTHROPIC_API_KEY?: string;
  RELAY_TOKEN_HASHES?: string;
  ALLOWED_IPS?: string;
  ALLOWED_MODELS?: string;
  MAX_TOKENS_CAP?: string;
  RATE_LIMIT_PER_MINUTE?: string;
  RATE_LIMITER?: { limit(opts: { key: string }): Promise<{ success: boolean }> };
}

export const DEFAULT_MODELS = "claude-haiku-5-5,claude-sonnet-5-5";
export const DEFAULT_MAX_TOKENS_CAP = 16000;
export const DEFAULT_RATE_LIMIT = 60;
export const MAX_BODY_BYTES = 2 * 1024 * 1024;

const UPSTREAM = {
  "/anthropic/v1/messages": "https://api.anthropic.com/v1/messages",
  "/anthropic/v1/messages/count_tokens": "https://api.anthropic.com/v1/messages/count_tokens",
} as const;

const FORWARD_REQUEST_HEADERS = ["anthropic-version", "anthropic-beta", "content-type", "accept"];
const PASS_RESPONSE_HEADERS = ["content-type", "request-id"];

export type RelayCode =
  | "token_missing" | "token_invalid" | "ip_not_allowed" | "model_not_allowed"
  | "max_tokens_exceeded" | "bad_request" | "rate_limited" | "not_found"
  | "method_not_allowed" | "relay_misconfigured" | "upstream_unreachable";

const STATUS: Record<RelayCode, number> = {
  token_missing: 401, token_invalid: 401, ip_not_allowed: 403, model_not_allowed: 400,
  max_tokens_exceeded: 400, bad_request: 400, rate_limited: 429, not_found: 404,
  method_not_allowed: 405, relay_misconfigured: 500, upstream_unreachable: 502,
};

export function errorResponse(code: RelayCode, message: string, extra: Record<string, string> = {}): Response {
  return new Response(
    JSON.stringify({ type: "error", error: { type: "relay_error", code, message } }),
    { status: STATUS[code], headers: { "content-type": "application/json", ...extra } },
  );
}

export function splitList(value: string | undefined): string[] {
  return (value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

export function allowedModels(env: Env): string[] {
  const list = splitList(env.ALLOWED_MODELS);
  return list.length ? list : splitList(DEFAULT_MODELS);
}

export function maxTokensCap(env: Env): number {
  const n = Number(env.MAX_TOKENS_CAP);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_MAX_TOKENS_CAP;
}

export function rateLimitPerMinute(env: Env): number {
  const n = Number(env.RATE_LIMIT_PER_MINUTE);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_RATE_LIMIT;
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Constant-time string comparison (length is not secret: both are 64-char hex digests). */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function bearerToken(request: Request): string | null {
  const header = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return match ? match[1] : null;
}

/** Returns the matching hash (used as the rate limit key), or null if the token is not valid. */
export async function matchToken(token: string, hashes: string[]): Promise<string | null> {
  const presented = await sha256Hex(token);
  let found: string | null = null;
  for (const h of hashes) {
    // No early exit, so timing does not reveal which entry matched.
    if (timingSafeEqual(presented, h.toLowerCase())) found = h.toLowerCase();
  }
  return found;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

export function ipAllowed(ip: string, allowed: string[]): boolean {
  if (!allowed.length) return true;
  const normalized = ip.toLowerCase();
  for (const entry of allowed) {
    if (entry.includes("/")) {
      const [base, bitsStr] = entry.split("/");
      const bits = Number(bitsStr);
      const a = ipv4ToInt(ip);
      const b = ipv4ToInt(base);
      if (a === null || b === null || !Number.isInteger(bits) || bits < 0 || bits > 32) continue;
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      if (((a & mask) >>> 0) === ((b & mask) >>> 0)) return true;
    } else if (entry.toLowerCase() === normalized) {
      return true;
    }
  }
  return false;
}

export function filterRequestHeaders(inbound: Headers, apiKey: string): Headers {
  const out = new Headers();
  for (const name of FORWARD_REQUEST_HEADERS) {
    const v = inbound.get(name);
    if (v !== null) out.set(name, v);
  }
  out.set("x-api-key", apiKey);
  return out;
}

export function filterResponseHeaders(upstream: Headers): Headers {
  const out = new Headers();
  upstream.forEach((value, name) => {
    const n = name.toLowerCase();
    if (PASS_RESPONSE_HEADERS.includes(n) || n.startsWith("anthropic-ratelimit-")) out.set(name, value);
  });
  return out;
}

export type BodyCheck =
  | { ok: true; model: string | null; body: string }
  | { ok: false; response: Response };

export function validateBody(raw: string, isCount: boolean, env: Env): BodyCheck {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, response: errorResponse("bad_request", "Request body must be valid JSON.") };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, response: errorResponse("bad_request", "Request body must be a JSON object.") };
  }
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.model !== "string" || !obj.model) {
    return { ok: false, response: errorResponse("bad_request", "Request body must include a model.") };
  }
  const models = allowedModels(env);
  if (!models.includes(obj.model)) {
    return {
      ok: false,
      response: errorResponse("model_not_allowed", `Model "${obj.model}" is not allowed by this relay. Allowed models: ${models.join(", ")}.`),
    };
  }
  const cap = maxTokensCap(env);
  if (obj.max_tokens === undefined || obj.max_tokens === null) {
    if (!isCount) {
      return { ok: false, response: errorResponse("bad_request", "Request body must include max_tokens.") };
    }
  } else if (typeof obj.max_tokens !== "number" || !Number.isFinite(obj.max_tokens)) {
    return { ok: false, response: errorResponse("bad_request", "max_tokens must be a number.") };
  } else if (obj.max_tokens > cap) {
    return {
      ok: false,
      response: errorResponse("max_tokens_exceeded", `max_tokens ${obj.max_tokens} is above this relay's cap of ${cap}.`),
    };
  }
  return { ok: true, model: obj.model, body: raw };
}

function log(path: string, model: string | null, status: number, usage?: { in?: number; out?: number }): void {
  // Metadata only. Never prompts, answers, tokens or keys.
  console.log(JSON.stringify({
    t: new Date().toISOString(), path, model, status,
    input_tokens: usage?.in ?? null, output_tokens: usage?.out ?? null,
  }));
}

function logged(path: string, model: string | null, res: Response): Response {
  log(path, model, res.status);
  return res;
}

async function readBody(request: Request): Promise<string | Response> {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    return errorResponse("bad_request", `Request body is larger than the ${MAX_BODY_BYTES / 1024 / 1024} MB limit.`);
  }
  const buf = await request.arrayBuffer();
  if (buf.byteLength > MAX_BODY_BYTES) {
    return errorResponse("bad_request", `Request body is larger than the ${MAX_BODY_BYTES / 1024 / 1024} MB limit.`);
  }
  return new TextDecoder().decode(buf);
}

export async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const isHealth = path === "/health";
  const upstreamUrl = (UPSTREAM as Record<string, string>)[path];

  if (!isHealth && !upstreamUrl) {
    return logged(path, null, errorResponse("not_found", "Unknown path. This relay only serves /anthropic/v1/messages, /anthropic/v1/messages/count_tokens and /health."));
  }
  const wantedMethod = isHealth ? "GET" : "POST";
  if (request.method !== wantedMethod) {
    return logged(path, null, errorResponse("method_not_allowed", `Use ${wantedMethod} for this path.`, { allow: wantedMethod }));
  }

  const hashes = splitList(env.RELAY_TOKEN_HASHES);
  if (!hashes.length) {
    return logged(path, null, errorResponse("relay_misconfigured", "No token hashes are set on this relay. Set the RELAY_TOKEN_HASHES secret."));
  }
  if (!isHealth && !env.ANTHROPIC_API_KEY) {
    return logged(path, null, errorResponse("relay_misconfigured", "No provider key is set on this relay. Set the ANTHROPIC_API_KEY secret."));
  }

  const token = bearerToken(request);
  if (!token) {
    return logged(path, null, errorResponse("token_missing", "Missing relay token. Send an Authorization: Bearer header."));
  }
  const matched = await matchToken(token, hashes);
  if (!matched) {
    return logged(path, null, errorResponse("token_invalid", "The relay token is not valid. It may have been revoked."));
  }

  const callerIp = request.headers.get("cf-connecting-ip") ?? "";

  if (isHealth) {
    const allowedIps = splitList(env.ALLOWED_IPS);
    const res = new Response(JSON.stringify({
      ok: true,
      relay: "pressbot-key-relay",
      version: pkg.version,
      providers: ["anthropic"],
      allowed_models: allowedModels(env),
      max_tokens_cap: maxTokensCap(env),
      ip_lock: allowedIps.length > 0,
      your_ip: callerIp,
      rate_limit_per_minute: rateLimitPerMinute(env),
    }), { status: 200, headers: { "content-type": "application/json" } });
    return logged(path, null, res);
  }

  const allowedIps = splitList(env.ALLOWED_IPS);
  if (allowedIps.length && !ipAllowed(callerIp, allowedIps)) {
    return logged(path, null, errorResponse("ip_not_allowed", `Requests from ${callerIp || "an unknown IP"} are not allowed by this relay. Add this address to ALLOWED_IPS if it is your server.`));
  }

  const raw = await readBody(request);
  if (raw instanceof Response) return logged(path, null, raw);

  const checked = validateBody(raw, path.endsWith("/count_tokens"), env);
  if (!checked.ok) return logged(path, null, checked.response);

  if (env.RATE_LIMITER) {
    const { success } = await env.RATE_LIMITER.limit({ key: matched.slice(0, 16) });
    if (!success) {
      return logged(path, checked.model, errorResponse("rate_limited", "Too many requests for this relay token. Wait a minute and try again.", { "retry-after": "60" }));
    }
  }

  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl, {
      method: "POST",
      headers: filterRequestHeaders(request.headers, env.ANTHROPIC_API_KEY as string),
      body: checked.body,
    });
  } catch {
    return logged(path, checked.model, errorResponse("upstream_unreachable", "The relay could not reach api.anthropic.com."));
  }

  const headers = filterResponseHeaders(upstream.headers);
  const isEventStream = (upstream.headers.get("content-type") ?? "").includes("text/event-stream");

  if (isEventStream || !upstream.body) {
    // Stream straight through, unbuffered.
    // TODO(R2): parse usage from the final SSE events for the daily spend cap.
    log(path, checked.model, upstream.status);
    return new Response(upstream.body, { status: upstream.status, headers });
  }

  // Non-streaming: small JSON, safe to read so we can log token counts.
  const text = await upstream.text();
  let usage: { in?: number; out?: number } | undefined;
  try {
    const j = JSON.parse(text);
    usage = { in: j?.usage?.input_tokens ?? j?.input_tokens, out: j?.usage?.output_tokens };
  } catch { /* not JSON: log without usage */ }
  // TODO(R2): add usage to the per-token daily spend counter and enforce the cap.
  log(path, checked.model, upstream.status, usage);
  return new Response(text, { status: upstream.status, headers });
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handle(request, env);
  },
};
