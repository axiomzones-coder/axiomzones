// functions/api/user-login.js
// POST /api/user-login — Body: { email, password }

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  const email = String((body && body.email) || '').trim().toLowerCase();
  const password = String((body && body.password) || '');

  if (!email || !password) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_fields' }), { status: 400, headers });
  }

  const raw = await env.AZ_USERS_KV.get('user:' + email);
  if (!raw) {
    // نفس رسالة الخطأ لبريد غير موجود أو كلمة مرور خاطئة — يمنع اكتشاف أي بريد مسجَّل فعلاً
    return new Response(JSON.stringify({ ok: false, error: 'invalid_credentials' }), { status: 401, headers });
  }

  const record = JSON.parse(raw);
  const salt = base64urlDecode(record.salt);
  const computedHash = await hashPassword(password, salt);
  const match = base64url(computedHash) === record.passwordHash;

  if (!match) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_credentials' }), { status: 401, headers });
  }

  const token = await makeSessionToken(email, env.OWNER_SECRET || 'fallback-secret-change-me');
  headers.append('Set-Cookie', `az_user_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000`);

  return new Response(JSON.stringify({
    ok: true,
    user: { email: record.email, name: record.name, plan: record.plan }
  }), { status: 200, headers });
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

async function makeSessionToken(email, secret) {
  const exp = Date.now() + 30 * 24 * 60 * 60 * 1000;
  const payload = `user.${btoa(email)}.${exp}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return `${payload}.${base64url(new Uint8Array(sigBuf))}`;
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
