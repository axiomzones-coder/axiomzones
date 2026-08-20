// functions/api/user-login.js
// POST /api/user-login — Body: { email, password }
// يتحقق من بيانات عضو موجود، يضبط جلسة (az_user_session) بنفس صيغة
// HMAC المُستخدَمة في platform-access.js/review-submit.js بالضبط.

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
    return new Response(JSON.stringify({ ok: false, error: 'invalid_fields' }), { status: 400, headers });
  }

  /* ══ Rate Limiting صريح: 5 محاولات كل 15 دقيقة — لكل (بريد + IP) معاً،
     يمنع هجمات القوة العمياء (Brute Force) بلا حجب مستخدم شرعي بسبب IP
     مشترك (شبكة عامة/شركة) ══ */
  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlKey = `ratelimit:login:${email}:${clientIp}`;
  const rlRaw = env.AZ_CONFIG_KV ? await env.AZ_CONFIG_KV.get(rlKey) : null;
  const rlCount = rlRaw ? (JSON.parse(rlRaw).count || 0) : 0;
  if (rlCount >= 5) {
    return new Response(JSON.stringify({ ok: false, error: 'rate_limited' }), { status: 429, headers });
  }

  const raw = await env.AZ_USERS_KV.get('user:' + email);
  if (!raw) {
    if (env.AZ_CONFIG_KV) await env.AZ_CONFIG_KV.put(rlKey, JSON.stringify({ count: rlCount + 1 }), { expirationTtl: 900 });
    return new Response(JSON.stringify({ ok: false, error: 'invalid_credentials' }), { status: 401, headers });
  }
  const userRecord = JSON.parse(raw);

  // ── تحقق كلمة المرور بنفس ملح PBKDF2 المُخزَّن وقت التسجيل ──
  const salt = base64urlDecode(userRecord.salt);
  const passKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const hashBuf = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, passKey, 256);
  const passwordHash = base64url(new Uint8Array(hashBuf));

  if (passwordHash !== userRecord.passwordHash) {
    if (env.AZ_CONFIG_KV) await env.AZ_CONFIG_KV.put(rlKey, JSON.stringify({ count: rlCount + 1 }), { expirationTtl: 900 });
    return new Response(JSON.stringify({ ok: false, error: 'invalid_credentials' }), { status: 401, headers });
  }

  /* ══ دخول ناجح — نصفّر العدَّاد فوراً، لا داعي لبقاء أثر محاولات فاشلة
     قديمة بعد دخول شرعي مؤكَّد ══ */
  if (env.AZ_CONFIG_KV) await env.AZ_CONFIG_KV.delete(rlKey);

  const secret = env.OWNER_SECRET || 'fallback-secret-change-me';
  const emailB64 = btoa(email);
  const exp = Date.now() + 30 * 24 * 60 * 60 * 1000;
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
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
