export async function onRequestPost({ request, env }) {
  const sid = (request.headers.get("Cookie") || "").split(";").map(x=>x.trim()).find(x=>x.startsWith("lv_sid="))?.slice(7);
  if (!sid || !env.LINKVERTISE_AUTH_TOKEN) return Response.json({ok:false,error:"Verification unavailable"},{status:503});
  let body;
  try { body = await request.json(); } catch { return Response.json({ok:false},{status:400}); }
  const step = Number(body.step), hash = String(body.hash || "");
  if (!Number.isInteger(step) || step < 2 || step > 5 || !/^[a-f0-9]{64}$/i.test(hash)) return Response.json({ok:false},{status:400});
  const session = await env.VERIFY_DB.prepare(
    "SELECT id, step, expires_at, verified_at FROM sessions WHERE id=? AND provider='lv'"
  ).bind(sid).first();
  const now = Math.floor(Date.now()/1000);
  if (!session || session.step !== step-1 || session.expires_at < now || session.verified_at) {
    return Response.json({ok:false,error:"No matching pending task"},{status:403});
  }
  let result;
  try {
    const u = new URL("https://publisher.linkvertise.com/api/v1/anti_bypassing");
    u.searchParams.set("token", env.LINKVERTISE_AUTH_TOKEN);
    u.searchParams.set("hash", hash);
    const upstream = await fetch(u.toString(), { method:"POST" });
    result = (await upstream.text()).trim();
  } catch {
    return Response.json({ok:false,error:"Provider verification failed"},{status:502});
  }
  if (result !== "TRUE") return Response.json({ok:false,error:"Task was not confirmed"},{status:403});
  const changed = await env.VERIFY_DB.prepare(
    "UPDATE sessions SET verified_at=? WHERE id=? AND provider='lv' AND verified_at IS NULL AND expires_at>=?"
  ).bind(now,sid,now).run();
  if (!changed.meta?.changes) return Response.json({ok:false,error:"Already used"},{status:409});
  return Response.json({ok:true,step},{headers:{"Cache-Control":"no-store"}});
}