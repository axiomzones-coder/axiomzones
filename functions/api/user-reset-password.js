// functions/api/user-reset-password.js
// POST /api/user-reset-password — Body: { email, token, newPassword }
// يتحقق من صلاحية رمز الاسترجاع، يحدّث كلمة المرور، يبطل الرمز فوراً
// (استخدام واحد فقط)، ويلغي كل الجلسات القديمة للمستخدم كإجراء أمني.

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
  const token = String((body && body.token) || '').trim();
  const newPassword = String((body && body.newPassword) || '');

  if (!email || !token || newPassword.length < 6) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_fields' }), { status: 400, headers });
  }

  const tokenHash = await sha256Hex(token);
  const resetRaw = await env.AZ_USERS_KV.get('pwreset:' + tokenHash);
  if (!resetRaw) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_or_expired_token' }), { status: 401, headers });
  }
  const resetData = JSON.parse(resetRaw);
  if (resetData.email !== email || Date.now() > resetData.expiresAt) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_or_expired_token' }), { status: 401, headers });
  }

  const userRaw = await env.AZ_USERS_KV.get('user:' + email);
  if (!userRaw) {
    return new Response(JSON.stringify({ ok: false, error: 'user_not_found' }), { status: 404, headers });
  }
  const userRecord = JSON.parse(userRaw);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const passKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(newPassword), 'PBKDF2', false, ['deriveBits']);
  const hashBuf = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, passKey, 256);
  userRecord.passwordHash = base64url(new Uint8Array(hashBuf));
  userRecord.salt = base64url(salt);
  await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(userRecord));

  /* ══ إبطال الرمز فوراً — استخدام واحد فقط، لا يمكن إعادة استخدامه ══ */
  await env.AZ_USERS_KV.delete('pwreset:' + tokenHash);

  /* ══ ملاحظة: الجلسات القديمة (az_user_session) تفضل صالحة تقنياً حتى
     انتهاء صلاحيتها الطبيعية (30 يوم) — نظام الجلسات الحالي بلا قائمة
     إبطال مركزية (Refresh Token dorollable)، هذا بند مؤجَّل موثَّق مسبقاً
     في خارطة الطريق (المرحلة د) ══ */

  headers.append('Set-Cookie', 'az_user_session=; Path=/; Max-Age=0'); // تسجيل خروج من الجلسة الحالية على الأقل

  return new Response(JSON.stringify({ ok: true, message: 'تم تحديث كلمة المرور بنجاح' }), { headers });
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
