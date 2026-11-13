import { json, sha256Hex, sameOrigin, sessionCookie } from "../../_utils/admin-auth.js";

const PASSWORD_SALT = "v4HFS0QinGkya2bWffLWmQ==";
const PASSWORD_HASH = "DH6H8QqfB59Uih20Gc7ijBSh468Q1S8MqGA4kU+7iVg=";
const PASSWORD_ITERATIONS = 310000;

function decodeBase64(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function encodeBase64(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function constantTimeEqual(a, b) {
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

async function verifyPassword(password) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: decodeBase64(PASSWORD_SALT),
    iterations: PASSWORD_ITERATIONS,
    hash: "SHA-256"
  }, key, 256);
  return constantTimeEqual(encodeBase64(bits), PASSWORD_HASH);
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function onRequestPost({ request, env }) {
  if (!sameOrigin(request)) return json({ ok: false, error: "Request rejected" }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: "Invalid request" }, 400); }
  const password = typeof body.password === "string" ? body.password : "";
  if (!password || password.length > 256) return json({ ok: false, error: "Incorrect password" }, 401);

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipHash = await sha256Hex(ip);
  const now = Math.floor(Date.now() / 1000);
  const attempts = await env.VERIFY_DB.prepare(
    "SELECT COUNT(*) AS total FROM admin_login_attempts WHERE ip_hash = ? AND created_at > ?"
  ).bind(ipHash, now - 900).first();

  if ((attempts?.total || 0) >= 5) {
    return json({ ok: false, error: "Too many attempts. Try again in 15 minutes." }, 429, { "Retry-After": "900" });
  }

  let valid = false;
  try { valid = await verifyPassword(password); } catch {}
  if (!valid) {
    await env.VERIFY_DB.prepare("INSERT INTO admin_login_attempts (ip_hash, created_at) VALUES (?, ?)").bind(ipHash, now).run();
    return json({ ok: false, error: "Incorrect password" }, 401);
  }

  await env.VERIFY_DB.prepare("DELETE FROM admin_login_attempts WHERE ip_hash = ?").bind(ipHash).run();
  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  await env.VERIFY_DB.prepare("INSERT INTO admin_sessions (token_hash, created_at, expires_at) VALUES (?, ?, ?)")
    .bind(tokenHash, now, now + 21600).run();

  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(token, 21600) });
}
