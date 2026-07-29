// functions/api/user-signup.js
// POST /api/user-signup — Body: { email, password, name }
// يخزّن المستخدم في KV (AZ_USERS_KV) بكلمة مرور مُشفَّرة (PBKDF2 + salt) — أبداً نصاً صريحاً

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
  const name = String((body && body.name) || email.split('@')[0]);

  if (!email || !email.includes('@')) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_email' }), { status: 400, headers });
  }
  if (password.length < 8) {
    return new Response(JSON.stringify({ ok: false, error: 'password_too_short' }), { status: 400, headers });
  }

  const existing = await env.AZ_USERS_KV.get('user:' + email);
  if (existing) {
    return new Response(JSON.stringify({ ok: false, error: 'email_exists' }), { status: 409, headers });
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);

  const record = {
    email,
    name,
    passwordHash: base64url(hash),
    salt: base64url(salt),
    plan: 'free',
    createdAt: new Date().toISOString(),
  };

  await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(record));

  const token = await makeSessionToken(email, env.OWNER_SECRET || 'fallback-secret-change-me');
  headers.append('Set-Cookie', `az_user_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000`); // 30 يوماً

  return new Response(JSON.stringify({ ok: true, user: { email, name, plan: 'free' } }), { status: 200, headers });
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
  const exp = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 يوماً
  const payload = `user.${btoa(email)}.${exp}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return `${payload}.${base64url(new Uint8Array(sigBuf))}`;
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
