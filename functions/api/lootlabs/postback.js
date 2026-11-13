export async function onRequestGet({ request, env }) {
  const u = new URL(request.url);
  const clickId = u.searchParams.get("click_id") || "";
  const uniqueId = u.searchParams.get("unique_id") || "";
  const ip = u.searchParams.get("ip") || "";
  if (!/^[0-9a-f-]{36}$/i.test(clickId) || !uniqueId || uniqueId.length > 200) {
    return new Response("invalid", {status:400});
  }
  const now = Math.floor(Date.now()/1000);
  const session = await env.VERIFY_DB.prepare(
    "SELECT id, expires_at, verified_at FROM sessions WHERE id=? AND provider='ll'"
  ).bind(clickId).first();
  if (!session || session.expires_at < now) return new Response("ignored",{status:404});
  const inserted = await env.VERIFY_DB.prepare(
    "INSERT OR IGNORE INTO lootlabs_events (unique_id, click_id, ip, created_at) VALUES (?, ?, ?, ?)"
  ).bind(uniqueId,clickId,ip,now).run();
  if (!inserted.meta?.changes) return new Response("duplicate",{status:200});
  await env.VERIFY_DB.prepare(
    "UPDATE sessions SET verified_at=? WHERE id=? AND provider='ll' AND verified_at IS NULL AND expires_at>=?"
  ).bind(now,clickId,now).run();
  return new Response("ok",{status:200});
}