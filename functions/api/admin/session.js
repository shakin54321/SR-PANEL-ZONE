import { json, readAdminSession } from "../../_utils/admin-auth.js";

export async function onRequestGet({ request, env }) {
  const session = await readAdminSession(request, env);
  return json({ ok: !!session });
}
