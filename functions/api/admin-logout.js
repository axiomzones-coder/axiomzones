// functions/api/admin-logout.js
// POST /api/admin-logout — يمسح جلسة المدير

export async function onRequestPost(context) {
  const headers = new Headers({ 'content-type': 'application/json' });
  headers.append('Set-Cookie', 'az_admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}
