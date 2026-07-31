// functions/api/admin-verify.js
// GET /api/admin-verify — يتحقق من جلسة المدير الموقّعة، ويعيد صلاحياته الحالية (مقروءة من KV مباشرة)
// قراءة الصلاحيات من KV في كل طلب (وليس من داخل التوكن) تضمن أن أي تعديل صلاحيات من المالك يسري فوراً

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  const result = await verifyAdminSession(request, env);
  if (!result.valid) {
    return new Response(JSON.stringify({ valid: false }), { status: 401, headers });
  }

  return new Response(JSON.stringify({
    valid: true,
    admin: { email: result.email, name: result.record.name || result.email.split('@')[0], permissions: result.record.permissions || {} },
  }), { status: 200, headers });
}

export async function verifyAdminSession(request, env) {
  if (!env.AZ_ADMINS_KV) return { valid: false };

  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_admin_session=([^;]+)/);
  if (!match) return { valid: false };

  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 4) return { valid: false }; // admin.<emailB64>.<exp>.<sig>

  const [tag, emailB64, expStr, sig] = parts;
  if (tag !== 'admin') return { valid: false };

  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) return { valid: false };

  const secret = env.OWNER_SECRET || 'fallback-secret-change-me';
  const payload = `${tag}.${emailB64}.${expStr}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const expectedSig = base64url(new Uint8Array(sigBuf));
  if (expectedSig !== sig) return { valid: false };

  let email;
  try { email = atob(emailB64); } catch (e) { return { valid: false }; }

  const raw = await env.AZ_ADMINS_KV.get('admin:' + email);
  if (!raw) return { valid: false };
  const record = JSON.parse(raw);
  if (record.disabled) return { valid: false };

  return { valid: true, email, record };
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
