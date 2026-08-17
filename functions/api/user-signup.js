// functions/api/user-signup.js
// POST /api/user-signup — Body: { email, password }
// ينشئ حساب مستخدم جديد، يضبط جلسة (az_user_session) بنفس صيغة HMAC
// المُستخدَمة في platform-access.js/review-submit.js بالضبط.

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

  if (!email || !email.includes('@') || password.length < 6) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_fields' }), { status: 400, headers });
  }

  const existing = await env.AZ_USERS_KV.get('user:' + email);
  if (existing) {
    return new Response(JSON.stringify({ ok: false, error: 'email_exists' }), { status: 409, headers });
  }

  // ── تشفير كلمة المرور (PBKDF2 عبر Web Crypto — لا مكتبات خارجية) ──
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const passKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const hashBuf = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, passKey, 256);
  const passwordHash = base64url(new Uint8Array(hashBuf));
  const saltB64 = base64url(salt);

  const userRecord = {
    email, passwordHash, salt: saltB64,
    name: email.split('@')[0],
    plan: 'free',
    createdAt: new Date().toISOString(),
    platformTrials: {},
  };

  await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(userRecord));

  // ── إنشاء جلسة فورية بعد التسجيل (نفس صيغة التحقق في platform-access.js) ──
  const secret = env.OWNER_SECRET || 'fallback-secret-change-me';
  const emailB64 = btoa(email);
  const exp = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 يوماً
  const payload = `user.${emailB64}.${exp}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const sig = base64url(new Uint8Array(sigBuf));
  const token = `${payload}.${sig}`;

  headers.append('Set-Cookie', `az_user_session=${encodeURIComponent(token)}; Path=/; Max-Age=2592000; Secure; HttpOnly; SameSite=Lax`);

  return new Response(JSON.stringify({ ok: true, user: { email, name: userRecord.name, plan: userRecord.plan || 'free' } }), { headers });
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
