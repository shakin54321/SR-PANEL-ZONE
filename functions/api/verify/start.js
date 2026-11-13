export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json();
    const provider = body.provider, step = Number(body.step);
    if (!["lv","ll"].includes(provider) || !Number.isInteger(step) || step < 1 || step > 4) return Response.json({ok:false,error:"Invalid request"},{status:400});
    const cookies = (request.headers.get("Cookie")||"").split(";").map(x=>x.trim());
    const visitorName = provider+"_visitor";
    let visitor = cookies.find(x=>x.startsWith(visitorName+"="))?.slice(visitorName.length+1);
    if (!visitor || !/^[0-9a-f-]{36}$/i.test(visitor)) visitor = crypto.randomUUID();
    const id=crypto.randomUUID(), now=Math.floor(Date.now()/1000);
    await env.VERIFY_DB.prepare("INSERT OR IGNORE INTO progress (visitor_id,provider,current_step,updated_at) VALUES (?,?,1,?)").bind(visitor,provider,now).run();
    const p=await env.VERIFY_DB.prepare("SELECT current_step FROM progress WHERE visitor_id=? AND provider=?").bind(visitor,provider).first();
    if (!p || p.current_step!==step) return Response.json({ok:false,error:"Complete the current step first",step:p?.current_step||1},{status:409});
    await env.VERIFY_DB.prepare("INSERT INTO sessions (id,provider,step,created_at,expires_at,verified_at,visitor_id) VALUES (?,?,?,?,?,NULL,?)").bind(id,provider,step,now,now+900,visitor).run();
    const cookieName=provider+"_sid";
    const headers=new Headers({"Content-Type":"application/json","Cache-Control":"no-store","Set-Cookie":cookieName+"="+id+"; Path=/; Max-Age=900; HttpOnly; Secure; SameSite=Lax"});
    headers.append("Set-Cookie",visitorName+"="+visitor+"; Path=/; Max-Age=2592000; Secure; SameSite=Lax");
    if(provider==="lv"){
      const targets={1:"https://link-center.net/8767038/pOulHrcpE6Ff",2:"https://link-center.net/8767038/U21ecnaPJsIr",3:"https://link-target.net/8767038/mdoSczwAg8BK",4:"https://direct-link.net/8767038/I0zvMow6WLdz"};
      return new Response(JSON.stringify({ok:true,url:targets[step]}),{headers});
    }
    const links={1:"https://loot-link.com/s?L9DIc2Pi&data=l7PWPQslxgrZO77DRHkU%2BogNPRofh9Q1NYbkK36fO0Eic7Pf1odPUijeSam6m5b6",2:"https://loot-link.com/s?L9DIc2Pi&data=l7PWPQslxgrZO77DRHkU%2BogNPRofh9Q1NYbkK36fO0Fa0H5lszLyTGOZVajr6QhJ",3:"https://loot-link.com/s?L9DIc2Pi&data=l7PWPQslxgrZO77DRHkU%2BogNPRofh9Q1NYbkK36fO0Gt%2BCS9lrdvLdc355MOqyE1",4:"https://loot-link.com/s?L9DIc2Pi&data=l7PWPQslxgrZO77DRHkU%2BogNPRofh9Q1NYbkK36fO0GxZNckuHXdoETXuWVzZRGI"};
    const url=new URL(links[step]);url.searchParams.set("puid",id);
    return new Response(JSON.stringify({ok:true,url:url.toString()}),{headers});
  }catch{return Response.json({ok:false,error:"Could not start verification"},{status:500});}
}