import { readAdminSession } from "../../_utils/admin-auth.js";

export async function onRequest(context) {
  const session = await readAdminSession(context.request, context.env);
  if (!session) return Response.redirect(new URL("/sr-control/", context.request.url), 302);
  return context.next();
}
