import { json, readAdminSession, sessionCookie } from "../../_utils/admin-auth.js";

export async function onRequestPost({ request, env }) {
  const session = await readAdminSession(request, env);
  if (session) await env.VERIFY_DB.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").bind(session.tokenHash).run();
  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
}
