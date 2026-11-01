import { getStore } from "@netlify/blobs";
import { createHash, randomBytes } from "node:crypto";
export const config = { path: "/api/*" };
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const hash = (p, salt) => createHash("sha256").update(salt + ":" + p).digest("hex");
const okId = (x) => typeof x === "string" && /^[\w-]{4,64}$/.test(x);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export default async (req) => {
  const st = getStore("tahlil");
  const path = new URL(req.url).pathname.replace(/^\/api/, "").replace(/\/$/, "");
  const q = new URL(req.url).searchParams;
  const auth = await st.get("auth", { type: "json" });
  const pw = req.headers.get("x-pw") || "";
  const isSup = () => !!auth && hash(pw, auth.salt) === auth.hash;
  const body = req.method === "GET" || req.method === "DELETE" ? {} : await req.json().catch(() => ({}));
  const index = (await st.get("index", { type: "json" })) || {};
  const needSup = async () => { if (isSup()) return null; await sleep(700); return J({ error: "unauthorized" }, 401); };

  if (path === "/status") return J({ configured: !!auth });
  if (path === "/summary") {
    const v = Object.values(index), pms = v.filter((x) => x.pm != null).map((x) => x.pm);
    return J({ n: v.length, sh: v.filter((x) => x.type === "اختبار قصير").length, fi: v.filter((x) => x.type === "اختبار نهائي").length,
      st: v.reduce((s, x) => s + (x.n || 0), 0), pm: pms.length ? pms.reduce((a, b) => a + b, 0) / pms.length : null });
  }
  if (path === "/auth" && req.method === "POST") {
    if (body.action === "setup") {
      if (auth || typeof body.pw !== "string" || body.pw.length < 6) return J({ error: "bad" }, 400);
      const salt = randomBytes(16).toString("hex");
      await st.setJSON("auth", { salt, hash: hash(body.pw, salt) }); return J({ ok: 1 });
    }
    const d = await needSup(); if (d) return d;
    if (body.action === "change") {
      if (typeof body.new !== "string" || body.new.length < 6) return J({ error: "bad" }, 400);
      const salt = randomBytes(16).toString("hex");
      await st.setJSON("auth", { salt, hash: hash(body.new, salt) });
    }
    return J({ ok: 1 });
  }
  if (path === "/analyses" && req.method === "GET") {
    const d = await needSup(); if (d) return d;
    const all = await Promise.all(Object.keys(index).map((id) => st.get("a/" + id, { type: "json" })));
    return J(all.filter(Boolean));
  }
  if (path === "/analysis" && req.method === "PUT") {
    const a = body;
    if (!okId(a.id) || !Array.isArray(a.qs) || !Array.isArray(a.students) || JSON.stringify(a).length > 2e6) return J({ error: "bad" }, 400);
    const old = await st.get("a/" + a.id, { type: "json" });
    if (old && !isSup() && !(a.tk && a.tk === old.tk)) { await sleep(500); return J({ error: "forbidden" }, 403); }
    await st.setJSON("a/" + a.id, a);
    index[a.id] = { type: a.type, n: a.students.length, pm: a.pm ?? null };
    await st.setJSON("index", index); return J({ ok: 1 });
  }
  if (path === "/analysis" && req.method === "DELETE") {
    const d = await needSup(); if (d) return d;
    const id = q.get("id"); if (!okId(id)) return J({ error: "bad" }, 400);
    await st.delete("a/" + id); delete index[id]; await st.setJSON("index", index); return J({ ok: 1 });
  }
  if (path === "/restore" && req.method === "POST") {
    const d = await needSup(); if (d) return d;
    if (!Array.isArray(body.db)) return J({ error: "bad" }, 400);
    await Promise.all(Object.keys(index).map((id) => st.delete("a/" + id)));
    const idx = {};
    for (const a of body.db) { if (!okId(a.id)) continue; await st.setJSON("a/" + a.id, a); idx[a.id] = { type: a.type, n: (a.students || []).length, pm: a.pm ?? null }; }
    await st.setJSON("index", idx); return J({ ok: 1 });
  }
  return J({ error: "not_found" }, 404);
};
