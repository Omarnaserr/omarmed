// ميدزون - Cloudflare Pages (Advanced mode). كل الـ API هنا، والباقي ملفات ثابتة.
const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast"; // غيّره لأي موديل Workers AI تاني
const enc = new TextEncoder(), dec = new TextDecoder();
const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const json = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store", ...h } });

async function sign(data, secret) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}
async function readSession(req, env) {
  const m = /(?:^|; )mz=([^;]+)/.exec(req.headers.get("cookie") || "");
  if (!m || !env.SESSION_SECRET) return null;
  const [p, s] = m[1].split(".");
  if (!p || s !== (await sign(p, env.SESSION_SECRET))) return null;
  try { const u = JSON.parse(dec.decode(unb64u(p))); return u.exp > Date.now() ? u : null; } catch { return null; }
}
function sseToText(stream) {
  let buf = "";
  return stream.pipeThrough(new TransformStream({
    transform(chunk, ctl) {
      buf += dec.decode(chunk, { stream: true });
      const lines = buf.split("\n"); buf = lines.pop();
      for (const l of lines) {
        if (!l.startsWith("data:")) continue;
        const d = l.slice(5).trim(); if (d === "[DONE]") continue;
        try { const t = JSON.parse(d).response; if (t) ctl.enqueue(enc.encode(t)); } catch {}
      }
    },
  }));
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url), path = url.pathname;
    if (!path.startsWith("/api/")) return env.ASSETS.fetch(req);

    if (path === "/api/config") return json({ clientId: env.GOOGLE_CLIENT_ID || "" });
    if (path === "/api/me") return json({ user: await readSession(req, env) });

    if (path === "/api/logout") return json({ ok: true }, 200, { "set-cookie": "mz=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" });

    if (path === "/api/auth/google" && req.method === "POST") {
      if (!env.SESSION_SECRET || !env.GOOGLE_CLIENT_ID) return json({ error: "not_configured" }, 500);
      const { credential } = await req.json().catch(() => ({}));
      if (!credential) return json({ error: "no_credential" }, 400);
      const r = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(credential));
      const g = await r.json().catch(() => ({}));
      if (!r.ok || g.aud !== env.GOOGLE_CLIENT_ID || !(g.email_verified === true || g.email_verified === "true"))
        return json({ error: "invalid_token" }, 401);
      const user = { name: g.name || g.email.split("@")[0], email: g.email, pic: g.picture || "" };
      const p = b64u(enc.encode(JSON.stringify({ ...user, exp: Date.now() + 30 * 864e5 })));
      const cookie = `mz=${p}.${await sign(p, env.SESSION_SECRET)}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`;
      return json({ user }, 200, { "set-cookie": cookie });
    }

    if (path === "/api/ai" && req.method === "POST") {
      if (!env.AI) return json({ error: "ai_not_bound" }, 500);
      const b = await req.json().catch(() => ({}));
      const messages = (b.messages || []).slice(-12).map((m) => ({ role: m.role === "assistant" ? "assistant" : "user", content: String(m.content || "").slice(0, 12000) }));
      if (!messages.length) return json({ error: "empty" }, 400);
      if (b.lang === "en") messages[messages.length - 1].content += "\n\n(Write everything in English only.)";
      const opts = { messages, max_tokens: Math.min(+b.max || 1200, 4000) };
      try {
        if (b.stream) {
          const s = await env.AI.run(env.AI_MODEL || MODEL, { ...opts, stream: true });
          return new Response(sseToText(s), { headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
        }
        const r = await env.AI.run(env.AI_MODEL || MODEL, opts);
        return json({ text: typeof r.response === "string" ? r.response : JSON.stringify(r.response) });
      } catch (e) { return json({ error: "ai_failed" }, 502); }
    }
    return json({ error: "not_found" }, 404);
  },
};
