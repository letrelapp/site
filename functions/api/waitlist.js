/**
 * Letrel — endpoint waitlist (Cloudflare Pages Function)
 * Route : POST /api/waitlist
 *
 * Défenses anti-spam, dans l'ordre :
 *  1. Honeypot : le champ "website" doit être vide (les bots le remplissent)
 *  2. Temps de soumission : un humain met plus de 3 secondes
 *  3. Turnstile : vérification serveur du token (siteverify)
 *  4. Validation d'email + dédoublonnage en base (UNIQUE)
 *
 * Bindings requis (dashboard Pages → Settings) :
 *  - D1 database binding : nom "DB"
 *  - Variable d'environnement (secret) : TURNSTILE_SECRET
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export async function onRequestPost(context) {
  const { request, env } = context;

  let data;
  try {
    data = await request.json();
  } catch {
    return json({ ok: false }, 400);
  }

  // 1. Honeypot : on répond "succès" pour ne pas éduquer le bot
  if (data.website && data.website.trim() !== "") {
    return json({ ok: true });
  }

  // 2. Soumission trop rapide (< 3 s) : même traitement silencieux
  if (typeof data.t !== "number" || data.t < 3000) {
    return json({ ok: true });
  }

  // 3. Vérification Turnstile côté serveur
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const verify = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      secret: env.TURNSTILE_SECRET,
      response: data.token || "",
      remoteip: ip,
    }),
  });
  const outcome = await verify.json();
  if (!outcome.success) {
    return json({ ok: false, reason: "challenge", debug: outcome["error-codes"] }, 403);
  }

  // 4. Validation d'email
  const email = String(data.email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 254) {
    return json({ ok: false, reason: "email" }, 400);
  }

  const lang = data.lang === "en" ? "en" : "fr";
  const country = request.cf?.country || null;

  // Insertion ; UNIQUE(email) rend l'opération idempotente
  try {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO waitlist (email, lang, country, created_at) VALUES (?1, ?2, ?3, datetime('now'))"
    ).bind(email, lang, country).run();
  } catch (e) {
    return json({ ok: false }, 500);
  }

  return json({ ok: true });
}

// Toute autre méthode : 405
export async function onRequest(context) {
  if (context.request.method === "POST") return onRequestPost(context);
  return json({ ok: false }, 405);
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
