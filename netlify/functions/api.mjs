import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const sha = t => crypto.createHash("sha256").update(t).digest("hex");
const eq = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const norm = c => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const newCode = () => { const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; let s = ""; for (let i = 0; i < 8; i++) s += A[crypto.randomInt(A.length)]; return s.slice(0, 4) + "-" + s.slice(4); };

const FIRST_PASSWORD = "z3QBvb2obzoE"; // first login password; change it in the site after logging in
const expected = () => process.env.ADMIN_PASSWORD || FIRST_PASSWORD;

async function secretOf(st) {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  let s = await st.get("secret", { type: "json" });
  if (!s) { s = crypto.randomBytes(32).toString("hex"); await st.setJSON("secret", s); }
  return s;
}
const sign = (p, sec) => crypto.createHmac("sha256", sec).update(p).digest("base64url");
const mint = (sec, r, extra = {}) => { const p = Buffer.from(JSON.stringify({ exp: Date.now() + 2 * 3600e3, r, ...extra })).toString("base64url"); return p + "." + sign(p, sec); };
function valid(req, role, sec) {
  const [p, s] = (req.headers.get("authorization") || "").replace("Bearer ", "").split(".");
  if (!p || !s || !eq(s, sign(p, sec))) return null;
  try { const d = JSON.parse(Buffer.from(p, "base64url")); return d.exp > Date.now() && d.r === role ? d : null; } catch { return null; }
}
async function pwOk(st, pw) {
  if (typeof pw !== "string" || !pw) return false;
  const rec = await st.get("pw", { type: "json" });
  if (rec) return eq(crypto.scryptSync(pw, rec.salt, 32).toString("hex"), rec.hash);
  return eq(sha(pw), sha(expected()));
}

export default async (req) => {
  const st = getStore("site");
  const route = new URL(req.url).pathname.replace(/^\/api\//, "");
  if (route === "health") return J({ function: true, ADMIN_PASSWORD: !!process.env.ADMIN_PASSWORD, passwordChangedInApp: !!(await st.get("pw", { type: "json" })) });

  if (process.env.RESET_ID && (await st.get("resetid", { type: "json" })) !== process.env.RESET_ID) {
    await st.delete("pw"); await st.setJSON("resetid", process.env.RESET_ID); await st.setJSON("lf", { n: 0, until: 0 });
  }
  const sec = await secretOf(st);
  const body = req.method === "POST" ? await req.json().catch(() => ({})) : {};
  const owner = () => valid(req, "o", sec);
  const NO = () => J({ error: "Session expired. Log in again." }, 401);

  if (route === "content" && req.method === "GET") {
    const c = (await st.get("content", { type: "json" })) || {};
    const customerReviews = (await st.get("creviews", { type: "json" })) || [];
    return J({ ...c, customerReviews });
  }

  /* ---------- owner login (password only) ---------- */
  if (route === "login") {
    const lf = (await st.get("lf", { type: "json" })) || { n: 0, until: 0 };
    if (lf.until > Date.now()) return J({ error: "Too many wrong attempts. Try again in 15 minutes." }, 429);
    if (!(await pwOk(st, body.password))) {
      lf.n++; if (lf.n >= 5) { lf.until = Date.now() + 900e3; lf.n = 0; }
      await st.setJSON("lf", lf);
      return J({ error: "Wrong password." }, 401);
    }
    await st.setJSON("lf", { n: 0, until: 0 });
    return J({ token: mint(sec, "o") });
  }

  /* ---------- owner: content + password ---------- */
  if (route === "save") {
    if (!owner()) return NO();
    const { customerReviews, ...c } = body.content || {};
    if (!c.profile || !Array.isArray(c.pricing) || !Array.isArray(c.portfolio) || !Array.isArray(c.reviews)) return J({ error: "Invalid content." }, 400);
    if (c.portfolio.length > 5 || (c.videos || []).length > 3) return J({ error: "Too many portfolio items or videos." }, 400);
    await st.setJSON("content", c);
    return J({ ok: true });
  }
  if (route === "change-password") {
    if (!owner()) return NO();
    if (!(await pwOk(st, body.current))) return J({ error: "Current password is wrong." }, 401);
    if (typeof body.next !== "string" || body.next.length < 8) return J({ error: "New password must be at least 8 characters." }, 400);
    const salt = crypto.randomBytes(16).toString("hex");
    await st.setJSON("pw", { salt, hash: crypto.scryptSync(body.next, salt, 32).toString("hex") });
    return J({ ok: true });
  }

  /* ---------- owner: customers ---------- */
  if (route === "customers") {
    if (!owner()) return NO();
    return J({ customers: (await st.get("customers", { type: "json" })) || [] });
  }
  if (route === "customer-add") {
    if (!owner()) return NO();
    const name = String(body.name || "").trim().slice(0, 80), email = String(body.email || "").trim().slice(0, 120);
    if (!name || !/^\S+@\S+\.\S+$/.test(email)) return J({ error: "Enter a name and a valid email." }, 400);
    const list = (await st.get("customers", { type: "json" })) || [];
    const code = newCode();
    const customer = { id: sha(norm(code)).slice(0, 12), name, email, code, created: new Date().toISOString().slice(0, 10) };
    list.unshift(customer);
    await st.setJSON("customers", list);
    return J({ customer });
  }
  if (route === "customer-remove") {
    if (!owner()) return NO();
    await st.setJSON("customers", ((await st.get("customers", { type: "json" })) || []).filter(c => c.id !== body.id));
    return J({ ok: true });
  }
  if (route === "review-remove") {
    if (!owner()) return NO();
    await st.setJSON("creviews", ((await st.get("creviews", { type: "json" })) || []).filter(r => r.id !== body.id));
    return J({ ok: true });
  }

  /* ---------- customer ---------- */
  if (route === "customer-login") {
    await new Promise(r => setTimeout(r, 400));
    const n = norm(body.code);
    const list = (await st.get("customers", { type: "json" })) || [];
    const cu = n.length === 8 ? list.find(c => eq(norm(c.code), n)) : null;
    if (!cu) return J({ error: "That code is not valid. Check it and try again." }, 401);
    const mine = ((await st.get("creviews", { type: "json" })) || []).find(r => r.id === cu.id);
    return J({ token: mint(sec, "c", { id: cu.id }), customer: { name: cu.name, review: mine ? { stars: mine.stars, text: mine.text } : null } });
  }
  if (route === "review-post") {
    const p = valid(req, "c", sec);
    if (!p) return NO();
    const cu = ((await st.get("customers", { type: "json" })) || []).find(c => c.id === p.id);
    if (!cu) return J({ error: "Your code is no longer active." }, 401);
    const stars = Math.round(Number(body.stars)), text = String(body.text || "").trim().slice(0, 1000);
    if (!(stars >= 1 && stars <= 5)) return J({ error: "Choose a star rating." }, 400);
    if (!text) return J({ error: "Write a few words about your experience." }, 400);
    const list = (await st.get("creviews", { type: "json" })) || [];
    const rev = { id: cu.id, name: cu.name, stars, text, date: new Date().toISOString().slice(0, 10) };
    const i = list.findIndex(r => r.id === cu.id);
    if (i >= 0) list[i] = rev; else list.unshift(rev);
    await st.setJSON("creviews", list);
    return J({ review: { stars, text } });
  }

  return J({ error: "Not found." }, 404);
};
