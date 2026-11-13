export async function onRequestPost({request,env}){
 const cookies=(request.headers.get("Cookie")||"").split(";").map(x=>x.trim());
 const sid=cookies.find(x=>x.startsWith("lv_sid="))?.slice(7);
 const visitor=cookies.find(x=>x.startsWith("lv_visitor="))?.slice(11);
 if(!sid||!visitor)return Response.json({ok:false,error:"Verification session missing. Start the Linkvertise step again."},{status:401});
 if(!env.LINKVERTISE_AUTH_TOKEN)return Response.json({ok:false,error:"Server token is not available in this deployment."},{status:503});
 let body;try{body=await request.json()}catch{return Response.json({ok:false,error:"Invalid verification request body."},{status:400})}
 const step=Number(body.step),hash=String(body.hash||"");
 if(!Number.isInteger(step)||step<2||step>5)return Response.json({ok:false,error:"Invalid callback step. Restart this Linkvertise step."},{status:400});
 if(!/^[a-f0-9]{64}$/i.test(hash))return Response.json({ok:false,error:"Linkvertise returned an invalid hash format. Check that Anti-Bypass is enabled and the destination is a Target Link, not a Paste Link."},{status:400});
 const now=Math.floor(Date.now()/1000);
 const s=await env.VERIFY_DB.prepare("SELECT step,expires_at,verified_at,visitor_id FROM sessions WHERE id=? AND provider='lv'").bind(sid).first();
 const p=await env.VERIFY_DB.prepare("SELECT current_step FROM progress WHERE visitor_id=? AND provider='lv'").bind(visitor).first();
 if(!s||s.visitor_id!==visitor||s.step!==step-1||s.expires_at<now||s.verified_at||!p||p.current_step!==step-1)return Response.json({ok:false,error:"No matching pending task"},{status:403});
 let answer;try{const u=new URL("https://publisher.linkvertise.com/api/v1/anti_bypassing");u.searchParams.set("token",env.LINKVERTISE_AUTH_TOKEN);u.searchParams.set("hash",hash);const r=await fetch(u,{method:"POST"});answer=(await r.text()).trim()}catch{return Response.json({ok:false,error:"Provider verification failed"},{status:502})}
 if(answer!=="TRUE")return Response.json({ok:false,error:"Task was not confirmed"},{status:403});
 const result=await env.VERIFY_DB.prepare("UPDATE progress SET current_step=?,updated_at=? WHERE visitor_id=? AND provider='lv' AND current_step=?").bind(step,now,visitor,step-1).run();
 if(!result.meta?.changes)return Response.json({ok:false,error:"Already processed"},{status:409});
 await env.VERIFY_DB.prepare("UPDATE sessions SET verified_at=? WHERE id=? AND verified_at IS NULL").bind(now,sid).run();
 return Response.json({ok:true,step},{headers:{"Cache-Control":"no-store"}});
}