import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  handle, sha256Hex, ipAllowed, filterRequestHeaders, filterResponseHeaders,
  timingSafeEqual, validateBody, parseIp, compileAllowedIps, readBody, type Env,
} from "../src/index";

const TOKEN = "pbr_testtoken";
let env: Env;

beforeEach(async () => {
  env = {
    ANTHROPIC_API_KEY: "sk-ant-REALKEY",
    RELAY_TOKEN_HASHES: `${"0".repeat(64)},${await sha256Hex(TOKEN)}`,
  };
  vi.spyOn(console, "log").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

const body = (o: object) => JSON.stringify(o);
const good = { model: "claude-haiku-5-5", max_tokens: 100, messages: [{ role: "user", content: "SECRET PROMPT" }] };

function req(path: string, init: RequestInit & { ip?: string; token?: string | null } = {}) {
  const headers = new Headers(init.headers);
  if (init.token !== null) headers.set("authorization", `Bearer ${init.token ?? TOKEN}`);
  if (init.ip) headers.set("cf-connecting-ip", init.ip);
  return new Request(`https://relay.test${path}`, { method: "POST", ...init, headers });
}
const err = async (r: Response) => (await r.json()) as any;

describe("pure helpers", () => {
  it("timingSafeEqual", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "ab")).toBe(false);
  });
  it("ipAllowed exact, v6, cidr, empty", () => {
    expect(ipAllowed("1.2.3.4", [])).toBe(true);
    expect(ipAllowed("1.2.3.4", ["1.2.3.4"])).toBe(true);
    expect(ipAllowed("1.2.3.5", ["1.2.3.4"])).toBe(false);
    expect(ipAllowed("2001:DB8::1", ["2001:db8::1"])).toBe(true);
    expect(ipAllowed("10.0.5.9", ["10.0.0.0/16"])).toBe(true);
    expect(ipAllowed("10.1.5.9", ["10.0.0.0/16"])).toBe(false);
  });
  it("filters request headers to the allowlist and adds the key", () => {
    const h = filterRequestHeaders(new Headers({
      authorization: "Bearer x", cookie: "c", "x-api-key": "evil", "anthropic-version": "2023-06-01",
      "anthropic-beta": "b", "content-type": "application/json", accept: "text/event-stream", "user-agent": "u",
    }), "KEY", ["b"]);
    expect([...h.keys()].sort()).toEqual(["accept", "anthropic-beta", "anthropic-version", "content-type", "x-api-key"]);
    expect(h.get("x-api-key")).toBe("KEY");
  });
  it("drops anthropic-beta unless allowed", () => {
    const inb = new Headers({ "anthropic-beta": "a-1, b-2" });
    expect(filterRequestHeaders(inb, "K").get("anthropic-beta")).toBeNull();
    expect(filterRequestHeaders(inb, "K", ["b-2"]).get("anthropic-beta")).toBe("b-2");
  });
  it("CIDR with empty or malformed prefix is rejected, not /0", () => {
    expect(ipAllowed("8.8.8.8", ["203.0.113.7/"])).toBe(false);
    expect(ipAllowed("8.8.8.8", ["203.0.113.7/ "])).toBe(false);
    expect(ipAllowed("8.8.8.8", ["203.0.113.7/abc"])).toBe(false);
    expect(ipAllowed("8.8.8.8", ["203.0.113.7/33"])).toBe(false);
    expect(compileAllowedIps(["203.0.113.7/"], false).invalid).toHaveLength(1);
    expect(compileAllowedIps(["2001:db8::/129"], false).invalid).toHaveLength(1);
  });
  it("broad CIDRs need ALLOW_BROAD_CIDR", () => {
    expect(compileAllowedIps(["10.0.0.0/8"], false).invalid).toHaveLength(1);
    expect(compileAllowedIps(["10.0.0.0/8"], true).invalid).toHaveLength(0);
    expect(compileAllowedIps(["2001:db8::/16"], false).invalid).toHaveLength(1);
    expect(compileAllowedIps(["2001:db8::/32"], false).invalid).toHaveLength(0);
    expect(ipAllowed("10.9.9.9", ["10.0.0.0/8"], true)).toBe(true);
  });
  it("normalizes IPv6 and maps IPv4-mapped addresses", () => {
    expect(parseIp("2001:0DB8:0:0:0:0:0:0001")).toEqual(parseIp("2001:db8::1"));
    expect(parseIp("::ffff:203.0.113.7")).toEqual({ v: 4, b: [203, 0, 113, 7] });
    expect(parseIp("::ffff:cb00:7107")).toEqual({ v: 4, b: [203, 0, 113, 7] });
    expect(parseIp("fe80::1%eth0")).toBeNull();
    expect(parseIp("1::2::3")).toBeNull();
    expect(ipAllowed("::ffff:203.0.113.7", ["203.0.113.7"])).toBe(true);
    expect(ipAllowed("203.0.113.7", ["::ffff:203.0.113.7"])).toBe(true);
    expect(ipAllowed("2001:db8:0:0:0:0:0:1", ["2001:DB8::1"])).toBe(true);
    expect(ipAllowed("2001:db8::2", ["2001:DB8::1"])).toBe(false);
  });
  it("IPv6 CIDR", () => {
    expect(ipAllowed("2001:db8:abcd::5", ["2001:db8::/32"])).toBe(true);
    expect(ipAllowed("2001:db9::5", ["2001:db8::/32"])).toBe(false);
    expect(ipAllowed("2001:db8:1:2::9", ["2001:db8:1:2::/64"])).toBe(true);
    expect(ipAllowed("2001:db8:1:3::9", ["2001:db8:1:2::/64"])).toBe(false);
    expect(ipAllowed("10.1.2.3", ["2001:db8::/32"])).toBe(false);
  });
  it("filters response headers", () => {
    const h = filterResponseHeaders(new Headers({
      "content-type": "application/json", "request-id": "r1", "anthropic-ratelimit-requests-limit": "5",
      "set-cookie": "a=b", "x-other": "1",
    }));
    expect([...h.keys()].sort()).toEqual(["anthropic-ratelimit-requests-limit", "content-type", "request-id"]);
  });
  it("validateBody", async () => {
    expect((validateBody("nope", false, env) as any).response.status).toBe(400);
    expect((validateBody("{}", false, env) as any).response.status).toBe(400);
    expect(validateBody(body({ model: "claude-haiku-5-5" }), true, env).ok).toBe(true);
    expect(validateBody(body({ model: "claude-haiku-5-5" }), false, env).ok).toBe(false);
  });
});

describe("request flow", () => {
  it("404 and 405", async () => {
    expect((await handle(req("/nope"), env)).status).toBe(404);
    expect((await err(await handle(req("/openai/v1/messages"), env))).error.code).toBe("not_found");
    const r = await handle(req("/anthropic/v1/messages", { method: "GET" }), env);
    expect(r.status).toBe(405);
    expect((await err(r)).error.code).toBe("method_not_allowed");
  });
  it("misconfigured", async () => {
    const r = await handle(req("/anthropic/v1/messages", { body: body(good) }), { ...env, ANTHROPIC_API_KEY: "" });
    expect(r.status).toBe(500);
    expect((await err(r)).error.code).toBe("relay_misconfigured");
    const r2 = await handle(req("/anthropic/v1/messages", { body: body(good) }), { ...env, RELAY_TOKEN_HASHES: "" });
    // Empty hash list: even unauthenticated callers just see token_invalid.
    expect(r2.status).toBe(401);
    expect((await err(r2)).error.code).toBe("token_invalid");
  });
  it("auth comes before config errors", async () => {
    const noKey = { ...env, ANTHROPIC_API_KEY: "" };
    const a = await handle(req("/anthropic/v1/messages", { token: null, body: body(good) }), noKey);
    expect((await err(a)).error.code).toBe("token_missing");
    const b = await handle(req("/anthropic/v1/messages", { token: "bad", body: body(good) }), noKey);
    expect((await err(b)).error.code).toBe("token_invalid");
    const c = await handle(req("/anthropic/v1/messages", { token: null, body: body(good) }), { ...env, ALLOWED_IPS: "nonsense" });
    expect((await err(c)).error.code).toBe("token_missing");
  });
  it("token missing / invalid", async () => {
    const a = await handle(req("/anthropic/v1/messages", { token: null, body: body(good) }), env);
    expect(a.status).toBe(401);
    expect((await err(a)).error.code).toBe("token_missing");
    const b = await handle(req("/anthropic/v1/messages", { token: "wrong", body: body(good) }), env);
    expect((await err(b)).error.code).toBe("token_invalid");
  });
  it("ip lock includes caller ip", async () => {
    const r = await handle(req("/anthropic/v1/messages", { ip: "9.9.9.9", body: body(good) }), { ...env, ALLOWED_IPS: "1.1.1.1" });
    expect(r.status).toBe(403);
    const e = await err(r);
    expect(e.error.code).toBe("ip_not_allowed");
    expect(e.error.message).toContain("9.9.9.9");
  });
  it("model / max_tokens / bad body / size", async () => {
    const m = await handle(req("/anthropic/v1/messages", { body: body({ ...good, model: "claude-opus-5" }) }), env);
    expect((await err(m)).error.code).toBe("model_not_allowed");
    const t = await handle(req("/anthropic/v1/messages", { body: body({ ...good, max_tokens: 16001 }) }), env);
    expect((await err(t)).error.code).toBe("max_tokens_exceeded");
    const j = await handle(req("/anthropic/v1/messages", { body: "{{" }), env);
    expect((await err(j)).error.code).toBe("bad_request");
    const big = await handle(req("/anthropic/v1/messages", { body: "x".repeat(2 * 1024 * 1024 + 1) }), env);
    expect(big.status).toBe(400);
  });
  it("rate limited, and skipped when binding is missing", async () => {
    const limit = vi.fn().mockResolvedValue({ success: false });
    const r = await handle(req("/anthropic/v1/messages", { body: body(good) }), { ...env, RATE_LIMITER: { limit } });
    expect(r.status).toBe(429);
    expect((await err(r)).error.code).toBe("rate_limited");
    expect(limit.mock.calls[0][0].key).toHaveLength(16);
  });

  it("forwards to Anthropic with filtered headers and logs usage only", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ usage: { input_tokens: 7, output_tokens: 3 }, content: "ANSWER" }),
      { status: 200, headers: { "content-type": "application/json", "request-id": "req_1", "anthropic-ratelimit-tokens-remaining": "9", "set-cookie": "x=y" } },
    ));
    vi.stubGlobal("fetch", fetchMock);
    const r = await handle(req("/anthropic/v1/messages", {
      body: body(good), headers: { "anthropic-version": "2023-06-01", cookie: "zzz", "content-type": "application/json" },
    }), env);
    expect(r.status).toBe(200);
    expect(r.headers.get("request-id")).toBe("req_1");
    expect(r.headers.get("anthropic-ratelimit-tokens-remaining")).toBe("9");
    expect(r.headers.get("set-cookie")).toBeNull();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.anthropic.com/v1/messages");
    const h = init.headers as Headers;
    expect(h.get("x-api-key")).toBe("sk-ant-REALKEY");
    expect(h.get("authorization")).toBeNull();
    expect(h.get("cookie")).toBeNull();
    expect(h.get("anthropic-version")).toBe("2023-06-01");
    const logs = (console.log as any).mock.calls.map((c: any[]) => c[0]).join("\n");
    expect(logs).toContain('"input_tokens":7');
    expect(logs).not.toContain("SECRET PROMPT");
    expect(logs).not.toContain("ANSWER");
    expect(logs).not.toContain("REALKEY");
    expect(logs).not.toContain(TOKEN);
    vi.unstubAllGlobals();
  });

  it("count_tokens goes to the count_tokens URL and allows missing max_tokens", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{"input_tokens":5}', { headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    const r = await handle(req("/anthropic/v1/messages/count_tokens", { body: body({ model: "claude-sonnet-5-5", messages: [] }) }), env);
    expect(r.status).toBe(200);
    expect(fetchMock.mock.calls[0][0]).toBe("https://api.anthropic.com/v1/messages/count_tokens");
    vi.unstubAllGlobals();
  });

  it("streams SSE through unbuffered", async () => {
    const enc = new TextEncoder();
    let release!: () => void;
    const gate = new Promise<void>((res) => (release = res));
    const stream = new ReadableStream({
      async start(c) {
        c.enqueue(enc.encode("event: a\ndata: 1\n\n"));
        await gate;
        c.enqueue(enc.encode("event: b\ndata: 2\n\n"));
        c.close();
      },
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(stream, { status: 200, headers: { "content-type": "text/event-stream" } })));
    const r = await handle(req("/anthropic/v1/messages", { body: body({ ...good, stream: true }) }), env);
    expect(r.headers.get("content-type")).toBe("text/event-stream");
    const reader = r.body!.getReader();
    const first = await reader.read(); // arrives before upstream finishes => not buffered
    expect(new TextDecoder().decode(first.value)).toContain("data: 1");
    release();
    let rest = "";
    for (;;) { const { done, value } = await reader.read(); if (done) break; rest += new TextDecoder().decode(value); }
    expect(rest).toContain("data: 2");
    vi.unstubAllGlobals();
  });

  it("upstream unreachable -> 502", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("boom")));
    const r = await handle(req("/anthropic/v1/messages", { body: body(good) }), env);
    expect(r.status).toBe(502);
    expect((await err(r)).error.code).toBe("upstream_unreachable");
    vi.unstubAllGlobals();
  });
});

describe("body hardening", () => {
  it("forwards the validated JSON, so duplicate keys cannot smuggle values", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    const raw = '{"model":"claude-opus-5","max_tokens":999999,"model":"claude-haiku-5-5","max_tokens":10,"messages":[]}';
    // JSON.parse keeps the last value, so this passes validation as haiku/10...
    const r = await handle(req("/anthropic/v1/messages", { body: raw }), env);
    expect(r.status).toBe(200);
    const sent = fetchMock.mock.calls[0][1].body as string;
    expect(sent).not.toContain("opus");
    expect(sent).not.toContain("999999");
    expect(JSON.parse(sent)).toMatchObject({ model: "claude-haiku-5-5", max_tokens: 10 });
    // ...and the reverse order is rejected on the value the relay actually sees.
    const r2 = await handle(req("/anthropic/v1/messages", { body: '{"model":"claude-haiku-5-5","model":"claude-opus-5","max_tokens":1}' }), env);
    expect(r2.status).toBe(400);
    vi.unstubAllGlobals();
  });
  it("rejects mcp_servers and container", async () => {
    for (const k of ["mcp_servers", "container"]) {
      const r = await handle(req("/anthropic/v1/messages", { body: body({ ...good, [k]: [] }) }), env);
      expect(r.status).toBe(400);
      expect((await err(r)).error.message).toContain(k);
    }
  });
  it("tool allowlist", async () => {
    const send = (tools: unknown[], e: Env = env) => handle(req("/anthropic/v1/messages", { body: body({ ...good, tools }) }), e);
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => new Response("{}", { headers: { "content-type": "application/json" } })));
    expect((await send([{ name: "x", input_schema: {} }, { type: "custom", name: "y" }])).status).toBe(200);
    expect((await send([{ type: "web_search_20250305", name: "web_search", max_uses: 5 }])).status).toBe(200);
    expect((await send([{ type: "web_search_20250305", name: "web_search" }])).status).toBe(200);
    const bad = await send([{ type: "bash_20250124", name: "bash" }]);
    expect(bad.status).toBe(400);
    const e = await err(bad);
    expect(e.error.code).toBe("tool_not_allowed");
    expect(e.error.message).toContain("bash_20250124");
    expect((await send([{ type: "web_search_20250305", name: "w", max_uses: 6 }])).status).toBe(400);
    expect((await send([{ type: "web_search_20250305", name: "w", max_uses: "5" }])).status).toBe(400);
    expect((await send([{ type: "web_search_20250305", name: "w" }], { ...env, ALLOWED_SERVER_TOOLS: "x" })).status).toBe(400);
    vi.unstubAllGlobals();
  });
  it("enforces the size limit while streaming, cancelling early", async () => {
    let pulled = 0;
    let cancelled = false;
    const chunk = new Uint8Array(512 * 1024);
    const stream = new ReadableStream<Uint8Array>({
      pull(c) { pulled++; c.enqueue(chunk); if (pulled > 100) c.close(); },
      cancel() { cancelled = true; },
    });
    const r = new Request("https://relay.test/x", { method: "POST", body: stream, duplex: "half" } as RequestInit);
    const out = await readBody(r);
    expect(out).toBeInstanceOf(Response);
    expect((out as Response).status).toBe(400);
    expect(cancelled).toBe(true);
    expect(pulled).toBeLessThan(20);
  });
  it("does not follow redirects", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 307, headers: { location: "https://evil.test/" } }));
    vi.stubGlobal("fetch", fetchMock);
    const r = await handle(req("/anthropic/v1/messages", { body: body(good) }), env);
    expect(fetchMock.mock.calls[0][1].redirect).toBe("manual");
    expect(r.status).toBe(502);
    expect((await err(r)).error.code).toBe("upstream_unreachable");
    expect(r.headers.get("location")).toBeNull();
    vi.unstubAllGlobals();
  });
  it("invalid ALLOWED_IPS fails closed for authenticated callers and /health names the entry", async () => {
    const bad = { ...env, ALLOWED_IPS: "203.0.113.7/" };
    const r = await handle(req("/anthropic/v1/messages", { ip: "8.8.8.8", body: body(good) }), bad);
    expect(r.status).toBe(500);
    const e = await err(r);
    expect(e.error.code).toBe("relay_misconfigured");
    expect(e.error.message).toContain("203.0.113.7/");
    const h = await handle(req("/health", { method: "GET", ip: "8.8.8.8" }), bad);
    expect(h.status).toBe(500);
    expect((await err(h)).error.message).toContain("203.0.113.7/");
  });
});

describe("/health", () => {
  it("is minimal when the lock is on and the caller is not allowed", async () => {
    const r = await handle(req("/health", { method: "GET", ip: "9.9.9.9" }), { ...env, ALLOWED_IPS: "1.1.1.1" });
    expect(r.status).toBe(403);
    const j = await err(r);
    expect(j).toMatchObject({ ok: false, your_ip: "9.9.9.9", ip_lock: true });
    expect(j.error.code).toBe("ip_not_allowed");
    expect(j.allowed_models).toBeUndefined();
  });
  it("full payload for an allowed IP, with warnings", async () => {
    const r = await handle(req("/health", { method: "GET", ip: "1.1.1.1" }), { ...env, ALLOWED_IPS: "1.1.1.1" });
    const j = await err(r);
    expect(j.warnings).toEqual(["rate_limit_off"]);
    expect(j.allowed_server_tools).toEqual(["web_search_20250305", "web_search_20260209"]);
    expect(j.allowed_betas).toEqual([]);
    const off = await err(await handle(req("/health", { method: "GET", ip: "1.1.1.1" }), env));
    expect(off.warnings).toContain("ip_lock_off");
  });
  it("reports config without secrets and never calls upstream", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const r = await handle(req("/health", { method: "GET", ip: "5.6.7.8" }), { ...env, ALLOWED_IPS: "5.6.7.8" });
    expect(r.status).toBe(200);
    const text = await r.text();
    const j = JSON.parse(text);
    expect(j).toMatchObject({ ok: true, relay: "pressbot-key-relay", providers: ["anthropic"], ip_lock: true, your_ip: "5.6.7.8", max_tokens_cap: 16000, rate_limit_per_minute: 60 });
    expect(j.allowed_models).toEqual(["claude-haiku-5-5", "claude-sonnet-5-5"]);
    expect(typeof j.version).toBe("string");
    expect(text).not.toContain("REALKEY");
    expect(text).not.toContain("0".repeat(64));
    expect(fetchMock).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
  it("requires the token", async () => {
    const r = await handle(req("/health", { method: "GET", token: "bad" }), env);
    expect(r.status).toBe(401);
  });
});
