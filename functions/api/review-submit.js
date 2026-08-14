// functions/api/review-submit.js
// POST /api/review-submit — Body: { platform: 'kashf', rating: 5, comment: '...' }
// يتطلب جلسة مستخدم حقيقية صالحة (az_user_session) — لا يُقبل من زائر مجهول.
// الرأي يظهر فوراً بدون موافقة مسبقة (قرار محمد صراحة) — المالك يملك صلاحية
// إخفاء/حذف بعد النشر من الداشبورد، لا موافقة قبله.

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_CONFIG_KV || !env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  // ── تحقق من جلسة المستخدم (نفس منطق platform-access.js/user-verify.js بالضبط) ──
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
  const rawUser = await env.AZ_USERS_KV.get('user:' + email);
  if (!rawUser) {
    return new Response(JSON.stringify({ ok: false, error: 'login_required' }), { status: 401, headers });
  }
  const userRecord = JSON.parse(rawUser);

  // ── Rate limiting: 10 آراء/يوم لكل مستخدم — يمنع إساءة الاستخدام دون تقييد الاستخدام الطبيعي ──
  const rlKey = `ratelimit:review:${email}`;
  const rlRaw = await env.AZ_CONFIG_KV.get(rlKey);
  const rlCount = rlRaw ? (JSON.parse(rlRaw).count || 0) : 0;
  if (rlCount >= 10) {
    return new Response(JSON.stringify({ ok: false, error: 'rate_limited' }), { status: 429, headers });
  }
  await env.AZ_CONFIG_KV.put(rlKey, JSON.stringify({ count: rlCount + 1 }), { expirationTtl: 86400 });

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  const platform = String((body && body.platform) || '').slice(0, 40);
  const rating = parseInt((body && body.rating) || 0, 10);
  const comment = String((body && body.comment) || '').slice(0, 1000);

  if (!platform || rating < 1 || rating > 5) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_fields' }), { status: 400, headers });
  }

  const review = {
    id: 'rev_' + crypto.randomUUID(),
    platform, rating, comment,
    userEmail: email,
    userName: userRecord.name || email.split('@')[0],
    status: 'visible',
    createdAt: new Date().toISOString(),
  };

  try {
    const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
    const config = configRaw ? JSON.parse(configRaw) : {};
    config.reviews = config.reviews || [];
    config.reviews.unshift(review);
    config.reviews = config.reviews.slice(0, 1000); // الاحتفاظ بآخر 1000 رأي
    await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'save_failed' }), { status: 500, headers });
  }

  return new Response(JSON.stringify({ ok: true, review }), { headers });
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
