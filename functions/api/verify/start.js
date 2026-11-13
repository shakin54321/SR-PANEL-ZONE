export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json();
    const provider = body.provider;
    const step = Number(body.step);
    if (!["lv", "ll"].includes(provider) || !Number.isInteger(step) || step < 1 || step > 4) {
      return Response.json({ ok:false, error:"Invalid request" }, { status:400 });
    }
    const id = crypto.randomUUID();
    const now = Math.floor(Date.now()/1000);
    await env.VERIFY_DB.prepare(
      "INSERT INTO sessions (id, provider, step, created_at, expires_at, verified_at) VALUES (?, ?, ?, ?, ?, NULL)"
    ).bind(id, provider, step, now, now + 900).run();
    const cookieName = provider === "lv" ? "lv_sid" : "ll_sid";
    const headers = new Headers({
      "Content-Type":"application/json",
      "Cache-Control":"no-store",
      "Set-Cookie": cookieName + "=" + id + "; Path=/; Max-Age=900; HttpOnly; Secure; SameSite=Lax"
    });
    if (provider === "lv") {
      const targets = {
        1:"https://link-center.net/8767038/pOulHrcpE6Ff",
        2:"https://link-center.net/8767038/U21ecnaPJsIr",
        3:"https://link-target.net/8767038/mdoSczwAg8BK",
        4:"https://direct-link.net/8767038/I0zvMow6WLdz"
      };
      return new Response(JSON.stringify({ok:true,url:targets[step]}),{headers});
    }
    const links = {
      1:"https://loot-link.com/s?L9DIc2Pi&data=l7PWPQslxgrZO77DRHkU%2BogNPRofh9Q1NYbkK36fO0Eic7Pf1odPUijeSam6m5b6",
      2:"https://loot-link.com/s?L9DIc2Pi&data=l7PWPQslxgrZO77DRHkU%2BogNPRofh9Q1NYbkK36fO0Fa0H5lszLyTGOZVajr6QhJ",
      3:"https://loot-link.com/s?L9DIc2Pi&data=l7PWPQslxgrZO77DRHkU%2BogNPRofh9Q1NYbkK36fO0Gt%2BCS9lrdvLdc355MOqyE1",
      4:"https://loot-link.com/s?L9DIc2Pi&data=l7PWPQslxgrZO77DRHkU%2BogNPRofh9Q1NYbkK36fO0GxZNckuHXdoETXuWVzZRGI"
    };
    const url = new URL(links[step]);
    url.searchParams.set("puid", id);
    return new Response(JSON.stringify({ok:true,url:url.toString()}),{headers});
  } catch (e) {
    return Response.json({ok:false,error:"Could not start verification"},{status:500});
  }
}