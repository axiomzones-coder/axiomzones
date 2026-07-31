// functions/api/admin-login.js
// POST /api/admin-login — Body: { email, password }
// يتحقق من حساب مدير في AZ_ADMINS_KV، ويصدر جلسة موقّعة (az_admin_session)
// الصلاحيات تُقرأ دائماً من KV وقت كل طلب لاحق (admin-verify.js)، وليست مخزَّنة داخل التوكن نفسه —
// هذا يضمن أن أي تعديل صلاحيات من المالك يسري فوراً، دون انتظار انتهاء الجلسة القديمة

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_ADMINS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  const email = String((body && body.email) || '').trim().toLowerCase();
  const password = String((body && body.password) || '');

  // ── تحديد معدل المحاولات لكل IP — نفس مبدأ حماية owner-login ──
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (env.AZ_CONFIG_KV) {
    const rlKey = `ratelimit:admin:${ip}`;
    const raw = await env.AZ_CONFIG_KV.get(rlKey);
    const count = raw ? (JSON.parse(raw).count || 0) : 0;
    if (count >= 5) {
      return new Response(JSON.stringify({ ok: false, error: 'too_many_attempts' }), { status: 429, headers });
    }
  }

  if (!email || !password) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_credentials' }), { status: 400, headers });
  }

  const raw = await env.AZ_ADMINS_KV.get('admin:' + email);
  if (!raw) {
    await registerFailure(env, ip);
    return new Response(JSON.stringify({ ok: false, error: 'invalid_credentials' }), { status: 401, headers });
  }

  const rec = JSON.parse(raw);
  if (rec.disabled) {
    return new Response(JSON.stringify({ ok: false, error: 'account_disabled' }), { status: 403, headers });
  }

  const match = await verifyPassword(password, rec.salt, rec.passwordHash);
  if (!match) {
    await registerFailure(env, ip);
    return new Response(JSON.stringify({ ok: false, error: 'invalid_credentials' }), { status: 401, headers });
  }

  if (env.AZ_CONFIG_KV) { try { await env.AZ_CONFIG_KV.delete(`ratelimit:admin:${ip}`); } catch (e) {} }

  const token = await makeAdminToken(email, env.OWNER_SECRET || 'fallback-secret-change-me');
  headers.append('Set-Cookie', `az_admin_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`); // 8 ساعات

  return new Response(JSON.stringify({
    ok: true,
    admin: { email: rec.email, name: rec.name || email.split('@')[0], permissions: rec.permissions || {} },
  }), { status: 200, headers });
}

async function registerFailure(env, ip) {
  if (!env.AZ_CONFIG_KV) return;
  const key = `ratelimit:admin:${ip}`;
  const raw = await env.AZ_CONFIG_KV.get(key);
  const data = raw ? JSON.parse(raw) : { count: 0 };
  data.count = (data.count || 0) + 1;
  await env.AZ_CONFIG_KV.put(key, JSON.stringify(data), { expirationTtl: 900 });
}

async function verifyPassword(password, saltB64, expectedHashB64) {
  const enc = new TextEncoder();
  const salt = fromBase64url(saltB64);
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const hashB64 = base64url(new Uint8Array(bits));
  return timingSafeEqualStr(hashB64, expectedHashB64);
}

function timingSafeEqualStr(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function makeAdminToken(email, secret) {
  const exp = Date.now() + 8 * 60 * 60 * 1000; // 8 ساعات
  const payload = `admin.${btoa(email)}.${exp}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return `${payload}.${base64url(new Uint8Array(sigBuf))}`;
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromBase64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
