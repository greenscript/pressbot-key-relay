import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  handle, sha256Hex, ipAllowed, filterRequestHeaders, filterResponseHeaders,
  timingSafeEqual, validateBody, type Env,
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
    }), "KEY");
    expect([...h.keys()].sort()).toEqual(["accept", "anthropic-beta", "anthropic-version", "content-type", "x-api-key"]);
    expect(h.get("x-api-key")).toBe("KEY");
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
    expect(r2.status).toBe(500);
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

describe("/health", () => {
  it("reports config without secrets and never calls upstream", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const r = await handle(req("/health", { method: "GET", ip: "5.6.7.8" }), { ...env, ALLOWED_IPS: "1.1.1.1" });
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
