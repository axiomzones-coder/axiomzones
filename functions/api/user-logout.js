// functions/api/user-logout.js
export async function onRequestPost() {
  const headers = new Headers({ 'content-type': 'application/json' });
  headers.append('Set-Cookie', 'az_user_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}
