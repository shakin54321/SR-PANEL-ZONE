export async function onRequestGet({request,env}){
 const u=new URL(request.url),click=u.searchParams.get("click_id")||"",unique=u.searchParams.get("unique_id")||"",ip=u.searchParams.get("ip")||"";
 if(!/^[0-9a-f-]{36}$/i.test(click)||!unique||unique.length>200)return new Response("invalid",{status:400});
 const now=Math.floor(Date.now()/1000);
 const s=await env.VERIFY_DB.prepare("SELECT visitor_id,step,expires_at,verified_at FROM sessions WHERE id=? AND provider='ll'").bind(click).first();
 if(!s||s.expires_at<now)return new Response("ignored",{status:404});
 const inserted=await env.VERIFY_DB.prepare("INSERT OR IGNORE INTO lootlabs_events (unique_id,click_id,ip,created_at) VALUES (?,?,?,?)").bind(unique,click,ip,now).run();
 if(!inserted.meta?.changes)return new Response("duplicate",{status:200});
 await env.VERIFY_DB.prepare("UPDATE progress SET current_step=?,updated_at=? WHERE visitor_id=? AND provider='ll' AND current_step=?").bind(s.step+1,now,s.visitor_id,s.step).run();
 await env.VERIFY_DB.prepare("UPDATE sessions SET verified_at=? WHERE id=? AND verified_at IS NULL").bind(now,click).run();
 return new Response("ok",{status:200});
}