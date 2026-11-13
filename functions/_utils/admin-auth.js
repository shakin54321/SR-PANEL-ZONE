const COOKIE_NAME = "sr_admin_session";

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store, max-age=0", "Pragma": "no-cache", ...extraHeaders }
  });
}

export async function sha256Hex(value) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
}

export function getCookie(request, name) {
  const prefix = name + "=";
  return (request.headers.get("Cookie") || "").split(";").map(v => v.trim()).find(v => v.startsWith(prefix))?.slice(prefix.length) || "";
}

export async function readAdminSession(request, env) {
  const token = getCookie(request, COOKIE_NAME);
  if (!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return null;
  const tokenHash = await sha256Hex(token);
  const now = Math.floor(Date.now() / 1000);
  const row = await env.VERIFY_DB.prepare("SELECT token_hash FROM admin_sessions WHERE token_hash = ? AND expires_at > ?").bind(tokenHash, now).first();
  return row ? { tokenHash } : null;
}

export function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return false;
  try { return new URL(origin).origin === new URL(request.url).origin; } catch { return false; }
}

export function sessionCookie(token, maxAge) {
  return COOKIE_NAME + "=" + token + "; Path=/; Max-Age=" + maxAge + "; HttpOnly; Secure; SameSite=Strict";
}
