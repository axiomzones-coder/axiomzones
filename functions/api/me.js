// functions/api/me.js
// GET /api/me — يتطلب جلسة مستخدم صالحة
// نقطة موحَّدة واحدة تُرجِع: بيانات الحساب + حالة الوصول لكل منصة مفعَّلة
// دفعة واحدة — بدل نداءات متفرقة (/user-verify ثم /platform-access لكل
// منصة على حدة) من الواجهة الأمامية.

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_user_session=([^;]+)/);
  if (!match) {
    return new Response(JSON.stringify({ ok: false, error: 'login_required' }), { status: 401, headers });
  }
  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 4) {
    return new Response(JSON.stringify({ ok: false, error: 'login_required' }), { status: 401, headers });
  }
  const [tag, emailB64, expStr, sig] = parts;
  if (tag !== 'user') {
    return new Response(JSON.stringify({ ok: false, error: 'login_required' }), { status: 401, headers });
  }
  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) {
    return new Response(JSON.stringify({ ok: false, error: 'login_required' }), { status: 401, headers });
  }
  const secret = env.OWNER_SECRET || 'fallback-secret-change-me';
  const payload = `${tag}.${emailB64}.${expStr}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const expectedSig = base64url(new Uint8Array(sigBuf));
  if (expectedSig !== sig) {
    return new Response(JSON.stringify({ ok: false, error: 'login_required' }), { status: 401, headers });
  }
  const email = atob(emailB64);

  const userRaw = await env.AZ_USERS_KV.get('user:' + email);
  if (!userRaw) {
    return new Response(JSON.stringify({ ok: false, error: 'user_not_found' }), { status: 404, headers });
  }
  const userRecord = JSON.parse(userRaw);

  /* ══ لا نُرجِع أبداً: passwordHash, salt — بيانات داخلية حساسة، ممنوع
     تسريبها للواجهة الأمامية مهما كان السياق (مطلب أمني صريح) ══ */
  const safeUser = {
    email: userRecord.email,
    name: userRecord.name,
    plan: userRecord.plan || 'free',
    createdAt: userRecord.createdAt,
  };

  /* ══ حالة الوصول لكل منصة موجودة في platformAccess/platformTrials/
     giftedAccess — ملخَّصة بصيغة واحدة موحَّدة سهلة الاستهلاك من الواجهة ══ */
  const access = {};
  const platformAccess = userRecord.platformAccess || { all: false, platforms: [] };
  const trials = userRecord.platformTrials || {};
  const gifts = userRecord.giftedAccess || {};

  const allPlatformKeys = new Set([
    ...(Array.isArray(platformAccess.platforms) ? platformAccess.platforms : []),
    ...Object.keys(trials),
    ...Object.keys(gifts),
  ]);

  allPlatformKeys.forEach(function (p) {
    if (platformAccess.all || (Array.isArray(platformAccess.platforms) && platformAccess.platforms.includes(p))) {
      access[p] = { status: 'full' };
    } else if (gifts[p] !== undefined) {
      access[p] = { status: 'full', gifted: true, expiresAt: gifts[p] };
    } else if (trials[p]) {
      access[p] = { status: 'trial', startedAt: trials[p] };
    }
  });

  return new Response(JSON.stringify({ ok: true, user: safeUser, access: access }), { headers });
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
