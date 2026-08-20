// functions/api/gift-claim.js
// POST /api/gift-claim — يتطلب جلسة مستخدم حقيقية صالحة
// Body: { giftId }
// يفعّل الهدية على حساب المستخدم الحالي، ويقفل الرابط نهائياً لأي شخص آخر.

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_CONFIG_KV || !env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  // ── تحقق من جلسة المستخدم (نفس منطق platform-access.js بالضبط) ──
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

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }
  const giftId = String((body && body.giftId) || '').trim();
  if (!giftId) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_gift_id' }), { status: 400, headers });
  }

  try {
    /* ══ آلية قفل مؤقت (Claim Lock) — تقليل نافذة السباق بين شخصين يطالبان
       بنفس الرابط في نفس اللحظة تقريباً. Cloudflare KV لا يوفر "compare-
       and-swap" أصيلاً، فهذا تخفيف عملي (Best-Effort) لا ضمان رياضي
       مطلق 100%، لكنه يُغلق الثغرة العملية الواقعية بدرجة كبيرة جداً:
       نكتب مفتاحاً مستقلاً بريدنا، نقرأه فوراً، ولا نكمل إلا لو كنا
       فعلاً من كتبه (لا شخص آخر سبقنا في نفس اللحظة) ══ */
    const lockKey = 'gift_lock:' + giftId;
    await env.AZ_CONFIG_KV.put(lockKey, email, { expirationTtl: 20 });
    const lockCheck = await env.AZ_CONFIG_KV.get(lockKey);
    if (lockCheck !== email) {
      return new Response(JSON.stringify({ ok: false, error: 'already_claimed' }), { status: 409, headers });
    }

    const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
    const config = configRaw ? JSON.parse(configRaw) : {};
    const gifts = config.gifts || [];
    const gift = gifts.find(g => g.id === giftId);

    if (!gift) {
      return new Response(JSON.stringify({ ok: false, error: 'gift_not_found' }), { status: 404, headers });
    }
    if (gift.claimed) {
      return new Response(JSON.stringify({ ok: false, error: 'already_claimed' }), { status: 409, headers });
    }

    // ── تفعيل الهدية على حساب المستخدم ──
    const userRaw = await env.AZ_USERS_KV.get('user:' + email);
    if (!userRaw) {
      return new Response(JSON.stringify({ ok: false, error: 'user_not_found' }), { status: 404, headers });
    }
    const userRecord = JSON.parse(userRaw);
    userRecord.giftedAccess = userRecord.giftedAccess || {};
    /* ══ فحص صريح 100%: "دائم" فقط لو durationDays رقم NULL بالضبط —
       أي قيمة رقمية صحيحة موجبة أخرى تُحسَب كأيام فعلية، لا اعتماد على
       truthy/falsy (كان durationDays=0 سيُعامَل خطأً كـ"دائم" سابقًا) ══ */
    const isPermanent = (gift.durationDays === null || gift.durationDays === undefined);
    const expiryDate = isPermanent
      ? null
      : new Date(Date.now() + Number(gift.durationDays) * 24 * 60 * 60 * 1000).toISOString();
    userRecord.giftedAccess[gift.platform] = expiryDate;
    await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(userRecord));

    // ── قفل الرابط نهائياً — لا يمكن لأي شخص آخر استخدامه ──
    gift.claimed = true;
    gift.claimedBy = email;
    gift.claimedAt = new Date().toISOString();
    await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));

    return new Response(JSON.stringify({ ok: true, platform: gift.platform, expiresAt: expiryDate, purpose: gift.purpose }), { headers });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'claim_failed' }), { status: 500, headers });
  }
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
