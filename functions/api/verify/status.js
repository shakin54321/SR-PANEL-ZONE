export async function onRequestGet({request,env}){
 const u=new URL(request.url),provider=u.searchParams.get("provider")==="lv"?"lv":"ll";
 const cookies=(request.headers.get("Cookie")||"").split(";").map(x=>x.trim());
 const visitor=cookies.find(x=>x.startsWith(provider+"_visitor="))?.slice((provider+"_visitor=").length);
 if(!visitor)return Response.json({ok:true,step:1},{headers:{"Cache-Control":"no-store"}});
 const p=await env.VERIFY_DB.prepare("SELECT current_step FROM progress WHERE visitor_id=? AND provider=?").bind(visitor,provider).first();
 return Response.json({ok:true,step:p?.current_step||1},{headers:{"Cache-Control":"no-store"}});
}