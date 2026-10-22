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
  ALLOW_BROAD_CIDR?: string;
  ALLOWED_BETAS?: string;
  ALLOWED_SERVER_TOOLS?: string;
  MAX_WEB_SEARCH_USES?: string;
  RATE_LIMITER?: { limit(opts: { key: string }): Promise<{ success: boolean }> };
}

export const DEFAULT_MODELS = "claude-haiku-5-5,claude-sonnet-5-5";
export const DEFAULT_MAX_TOKENS_CAP = 16000;
export const DEFAULT_RATE_LIMIT = 60;
export const DEFAULT_SERVER_TOOLS = "web_search_20250305,web_search_20260209";
export const DEFAULT_MAX_WEB_SEARCH_USES = 5;
export const MAX_BODY_BYTES = 2 * 1024 * 1024;

const UPSTREAM = {
  "/anthropic/v1/messages": "https://api.anthropic.com/v1/messages",
  "/anthropic/v1/messages/count_tokens": "https://api.anthropic.com/v1/messages/count_tokens",
} as const;

const FORWARD_REQUEST_HEADERS = ["anthropic-version", "anthropic-beta", "content-type", "accept"];
const PASS_RESPONSE_HEADERS = ["content-type", "request-id"];

export type RelayCode =
  | "token_missing" | "token_invalid" | "tool_not_allowed" | "ip_not_allowed" | "model_not_allowed"
  | "max_tokens_exceeded" | "bad_request" | "rate_limited" | "not_found"
  | "method_not_allowed" | "relay_misconfigured" | "upstream_unreachable";

const STATUS: Record<RelayCode, number> = {
  token_missing: 401, token_invalid: 401, ip_not_allowed: 403, model_not_allowed: 400,
  max_tokens_exceeded: 400, bad_request: 400, rate_limited: 429, not_found: 404,
  method_not_allowed: 405, tool_not_allowed: 400, relay_misconfigured: 500, upstream_unreachable: 502,
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

export function maxWebSearchUses(env: Env): number {
  const n = Number(env.MAX_WEB_SEARCH_USES);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_MAX_WEB_SEARCH_USES;
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

type ParsedIp = { v: 4 | 6; b: number[] };
type AllowedEntry = { v: 4 | 6; b: number[]; bits: number };

function parseV4(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    out.push(Number(p));
  }
  return out;
}

function parseV6(ip: string): number[] | null {
  if (!/^[0-9a-f:.]+$/i.test(ip)) return null; // also rejects zone ids (%eth0)
  let s = ip.toLowerCase();
  // Embedded IPv4 tail (::ffff:1.2.3.4) becomes two hextets.
  const lastColon = s.lastIndexOf(":");
  if (s.includes(".")) {
    const v4 = parseV4(s.slice(lastColon + 1));
    if (!v4) return null;
    s = s.slice(0, lastColon + 1) + ((v4[0] << 8) | v4[1]).toString(16) + ":" + ((v4[2] << 8) | v4[3]).toString(16);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const toGroups = (h: string) => (h === "" ? [] : h.split(":"));
  const head = toGroups(halves[0]);
  const tail = halves.length === 2 ? toGroups(halves[1]) : [];
  let groups: string[];
  if (halves.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = [...head, ...Array(missing).fill("0"), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const out: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    const n = parseInt(g, 16);
    out.push(n >> 8, n & 255);
  }
  return out;
}

/** Parses an IPv4 or IPv6 address. IPv4-mapped IPv6 (::ffff:a.b.c.d) is returned as IPv4. */
export function parseIp(ip: string): ParsedIp | null {
  const t = ip.trim();
  if (t.includes(":")) {
    const b = parseV6(t);
    if (!b) return null;
    const mapped = b.slice(0, 10).every((x) => x === 0) && b[10] === 255 && b[11] === 255;
    return mapped ? { v: 4, b: b.slice(12) } : { v: 6, b };
  }
  const b = parseV4(t);
  return b ? { v: 4, b } : null;
}

/** Parses one ALLOWED_IPS entry. Returns an error string for anything malformed or too broad. */
export function parseAllowedEntry(entry: string, allowBroad: boolean): AllowedEntry | string {
  const slash = entry.indexOf("/");
  const addr = slash === -1 ? entry : entry.slice(0, slash);
  const ip = parseIp(addr);
  if (!ip) return "not a valid IP address";
  const isMappedV6 = addr.includes(":") && ip.v === 4;
  if (slash === -1) return { v: ip.v, b: ip.b, bits: ip.v === 4 ? 32 : 128 };
  const bitsStr = entry.slice(slash + 1);
  if (!/^\d{1,3}$/.test(bitsStr)) return "prefix length must be a number";
  const bits = Number(bitsStr);
  if (isMappedV6) return "use a plain IPv4 CIDR instead of an IPv4-mapped IPv6 CIDR";
  const max = ip.v === 4 ? 32 : 128;
  if (bits > max) return `prefix length must be at most ${max}`;
  const minSafe = ip.v === 4 ? 16 : 32;
  if (bits < minSafe && !allowBroad) {
    return `/${bits} is very broad (smaller than /${minSafe}); set ALLOW_BROAD_CIDR="true" if you really mean it`;
  }
  return { v: ip.v, b: ip.b, bits };
}

function prefixMatch(a: number[], b: number[], bits: number): boolean {
  for (let i = 0; i < a.length && bits > 0; i++, bits -= 8) {
    const mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
    if ((a[i] & mask) !== (b[i] & mask)) return false;
  }
  return true;
}

/** Checks ALLOWED_IPS. Returns the parsed entries and the malformed ones (config errors). */
export function compileAllowedIps(list: string[], allowBroad: boolean): { entries: AllowedEntry[]; invalid: { entry: string; reason: string }[] } {
  const entries: AllowedEntry[] = [];
  const invalid: { entry: string; reason: string }[] = [];
  for (const e of list) {
    const r = parseAllowedEntry(e, allowBroad);
    if (typeof r === "string") invalid.push({ entry: e, reason: r });
    else entries.push(r);
  }
  return { entries, invalid };
}

/** Empty list = lock off = allowed. Malformed entries never match (fail closed). */
export function ipAllowed(ip: string, allowed: string[], allowBroad = false): boolean {
  if (!allowed.length) return true;
  const caller = parseIp(ip);
  if (!caller) return false;
  return compileAllowedIps(allowed, allowBroad).entries.some((e) => e.v === caller.v && prefixMatch(caller.b, e.b, e.bits));
}

export function filterRequestHeaders(inbound: Headers, apiKey: string, allowedBetas: string[] = []): Headers {
  const out = new Headers();
  for (const name of FORWARD_REQUEST_HEADERS) {
    const v = inbound.get(name);
    if (v === null) continue;
    if (name === "anthropic-beta") {
      // Beta features can change what a request does: forward only the ones the owner listed.
      const kept = v.split(",").map((x) => x.trim()).filter((x) => allowedBetas.includes(x));
      if (kept.length) out.set(name, kept.join(","));
      continue;
    }
    out.set(name, v);
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
  for (const key of ["mcp_servers", "container"]) {
    if (key in obj) {
      return { ok: false, response: errorResponse("bad_request", `"${key}" is not allowed by this relay.`) };
    }
  }
  if (obj.tools !== undefined) {
    if (!Array.isArray(obj.tools)) {
      return { ok: false, response: errorResponse("bad_request", "tools must be an array.") };
    }
    const serverTools = splitList(env.ALLOWED_SERVER_TOOLS ?? DEFAULT_SERVER_TOOLS);
    const maxUses = maxWebSearchUses(env);
    for (const tool of obj.tools) {
      if (!tool || typeof tool !== "object" || Array.isArray(tool)) {
        return { ok: false, response: errorResponse("bad_request", "Each tool must be an object.") };
      }
      const t = tool as Record<string, unknown>;
      if (t.type !== undefined && t.type !== "custom") {
        if (typeof t.type !== "string") {
          return { ok: false, response: errorResponse("tool_not_allowed", "Tool type must be a string.") };
        }
        const type = t.type;
        if (!serverTools.includes(type)) {
          return { ok: false, response: errorResponse("tool_not_allowed", `Tool type "${type.slice(0, 80)}" is not allowed by this relay. Allowed server tools: ${serverTools.join(", ") || "none"}.`) };
        }
        if (t.max_uses !== undefined && (typeof t.max_uses !== "number" || !(t.max_uses <= maxUses))) {
          return { ok: false, response: errorResponse("tool_not_allowed", `max_uses for ${type} must be a number no higher than ${maxUses}.`) };
        }
        // Leaving max_uses out must not lift the cap: fill it in (the parsed body is what gets forwarded).
        if (t.max_uses === undefined) t.max_uses = maxUses;
      }
    }
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
  // Forward exactly what was validated. Forwarding the raw text would let duplicate JSON keys
  // ("model" twice) show the relay one value and Anthropic another.
  return { ok: true, model: obj.model, body: JSON.stringify(obj) };
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

const TOO_BIG = () => errorResponse("bad_request", `Request body is larger than the ${MAX_BODY_BYTES / 1024 / 1024} MB limit.`);

/** Reads the body with a running byte count and stops as soon as the limit is passed. */
export async function readBody(request: Request): Promise<string | Response> {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return TOO_BIG();
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => {});
      return TOO_BIG();
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { all.set(c, off); off += c.byteLength; }
  return new TextDecoder().decode(all);
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

  // Auth first: unauthenticated callers must not learn what is or is not configured.
  const hashes = splitList(env.RELAY_TOKEN_HASHES);
  if (!hashes.length) {
    return logged(path, null, errorResponse("token_invalid", "The relay token is not valid. It may have been revoked."));
  }
  const token = bearerToken(request);
  if (!token) {
    return logged(path, null, errorResponse("token_missing", "Missing relay token. Send an Authorization: Bearer header."));
  }
  const matched = await matchToken(token, hashes);
  if (!matched) {
    return logged(path, null, errorResponse("token_invalid", "The relay token is not valid. It may have been revoked."));
  }

  // Authenticated from here on, so configuration problems can be reported.
  const allowedIps = splitList(env.ALLOWED_IPS);
  const ipConfig = compileAllowedIps(allowedIps, env.ALLOW_BROAD_CIDR === "true");
  if (ipConfig.invalid.length) {
    // Details go to the Worker logs only: the caller's IP hasn't been checked yet, and the
    // invalid entries are likely near-copies of the server's real address.
    const list = ipConfig.invalid.map((i) => `"${i.entry}" (${i.reason})`).join("; ");
    console.log(JSON.stringify({ relay_config_error: "ALLOWED_IPS", invalid: list }));
    return logged(path, null, errorResponse("relay_misconfigured", `ALLOWED_IPS has ${ipConfig.invalid.length} invalid entr${ipConfig.invalid.length === 1 ? "y" : "ies"}, so the relay refuses requests until it is fixed. Details are in the Worker logs.`));
  }
  const callerIp = request.headers.get("cf-connecting-ip") ?? "";
  const lockOn = allowedIps.length > 0;
  const ipOk = !lockOn || ipAllowed(callerIp, allowedIps, env.ALLOW_BROAD_CIDR === "true");
  const ipMessage = `Requests from ${callerIp || "an unknown IP"} are not allowed by this relay. Add this address to ALLOWED_IPS if it is your server.`;

  if (isHealth) {
    if (!ipOk) {
      const res = new Response(JSON.stringify({
        ok: false, your_ip: callerIp, ip_lock: true,
        error: { type: "relay_error", code: "ip_not_allowed", message: ipMessage },
      }), { status: 403, headers: { "content-type": "application/json" } });
      return logged(path, null, res);
    }
    const warnings: string[] = [];
    if (!lockOn) warnings.push("ip_lock_off");
    if (!env.RATE_LIMITER) warnings.push("rate_limit_off");
    if (!env.ANTHROPIC_API_KEY) warnings.push("provider_key_missing");
    const res = new Response(JSON.stringify({
      ok: true,
      relay: "pressbot-key-relay",
      version: pkg.version,
      providers: ["anthropic"],
      allowed_models: allowedModels(env),
      allowed_server_tools: splitList(env.ALLOWED_SERVER_TOOLS ?? DEFAULT_SERVER_TOOLS),
      allowed_betas: splitList(env.ALLOWED_BETAS),
      max_tokens_cap: maxTokensCap(env),
      ip_lock: lockOn,
      your_ip: callerIp,
      rate_limit_per_minute: rateLimitPerMinute(env),
      warnings,
    }), { status: 200, headers: { "content-type": "application/json" } });
    return logged(path, null, res);
  }

  if (!ipOk) return logged(path, null, errorResponse("ip_not_allowed", ipMessage));
  if (!env.ANTHROPIC_API_KEY) {
    return logged(path, null, errorResponse("relay_misconfigured", "No provider key is set on this relay. Set the ANTHROPIC_API_KEY secret."));
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
      headers: filterRequestHeaders(request.headers, env.ANTHROPIC_API_KEY as string, splitList(env.ALLOWED_BETAS)),
      body: checked.body,
      redirect: "manual", // never follow: a redirect could carry the key to another host
    });
  } catch {
    return logged(path, checked.model, errorResponse("upstream_unreachable", "The relay could not reach api.anthropic.com."));
  }

  if (upstream.status >= 300 && upstream.status < 400) {
    await upstream.body?.cancel().catch(() => {});
    return logged(path, checked.model, errorResponse("upstream_unreachable", "Anthropic answered with a redirect, which the relay does not follow."));
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
