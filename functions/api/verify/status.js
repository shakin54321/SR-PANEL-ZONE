export async function onRequestGet({ request, env }) {
  const cookies = (request.headers.get("Cookie") || "").split(";").map(x=>x.trim());
  const sid = cookies.find(x=>x.startsWith("ll_sid="))?.slice(7);
  if (!sid) return Response.json({ok:true,verified:false},{headers:{"Cache-Control":"no-store"}});
  const row = await env.VERIFY_DB.prepare(
    "SELECT step, expires_at, verified_at FROM sessions WHERE id=? AND provider='ll'"
  ).bind(sid).first();
  const now = Math.floor(Date.now()/1000);
  const verified = !!row && row.expires_at >= now && !!row.verified_at;
  return Response.json({ok:true,verified,step:row?.step || null},{headers:{"Cache-Control":"no-store"}});
}