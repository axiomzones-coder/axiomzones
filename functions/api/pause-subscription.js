// functions/api/pause-subscription.js
// POST /api/pause-subscription — يتطلب جلسة مستخدم صالحة
// Body: { subscriptionId: 'sub_...' }
//
// ⚠️ قرار تصميم مقصود: نستخدم pause_collection[behavior]=void (إيقاف
// تحصيل الفوترة فقط — الفواتير تُلغى تلقائياً، لا تتراكم ديون) —
// **وليس** الـ"Pause subscription" endpoint الأحدث (/subscriptions/:id/pause)
// لأنه في حالة "Private Preview" رسمياً حتى الآن (غير مستقر للاستخدام
// الإنتاجي، قد يتغيّر أو يُسحب بلا إشعار). pause_collection مستقر
// ومُوثَّق كميزة عامة منذ سنوات.
//
// السلوك: الفوترة تتوقف مؤقتاً، لكن الوصول للمنصات **يبقى ممنوحاً**
// أثناء الإيقاف (نية "إيقاف حسن النية" لا "عقاب فوري") — قرار عمل
// واضح، قابل للمراجعة لاحقاً لو الاستخدام الفعلي أظهر حاجة مختلفة.

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  const email = await verifyUserSession(request, env);
  if (!email) {
    return new Response(JSON.stringify({ ok: false, error: 'login_required' }), { status: 401, headers });
  }

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }
  const subscriptionId = String((body && body.subscriptionId) || '').trim();
  if (!subscriptionId) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_subscription_id' }), { status: 400, headers });
  }

  const userRaw = await env.AZ_USERS_KV.get('user:' + email);
  if (!userRaw) {
    return new Response(JSON.stringify({ ok: false, error: 'user_not_found' }), { status: 404, headers });
  }
  const userRecord = JSON.parse(userRaw);
  const sub = (userRecord.subscriptions || []).find(function (s) { return s.id === subscriptionId; });

  // ── تحقق ملكية إلزامي — نفس مبدأ cancel-subscription.js بالضبط ──
  if (!sub) {
    return new Response(JSON.stringify({ ok: false, error: 'subscription_not_found' }), { status: 404, headers });
  }
  if (sub.status !== 'active') {
    return new Response(JSON.stringify({ ok: false, error: 'subscription_not_active' }), { status: 409, headers });
  }
  if (sub.paused) {
    return new Response(JSON.stringify({ ok: false, error: 'already_paused' }), { status: 409, headers });
  }

  if (sub.provider === 'stripe') {
    if (!env.STRIPE_SECRET_KEY) {
      return new Response(JSON.stringify({ ok: false, error: 'payment_not_configured' }), { status: 503, headers });
    }
    const res = await fetch('https://api.stripe.com/v1/subscriptions/' + encodeURIComponent(subscriptionId), {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + env.STRIPE_SECRET_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'pause_collection[behavior]=void',
    });
    const data = await res.json();
    if (!res.ok) {
      return new Response(JSON.stringify({ ok: false, error: 'stripe_error', detail: data.error && data.error.message }), { status: 502, headers });
    }
    sub.paused = true;
    sub.pausedAt = new Date().toISOString();
    await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(userRecord));
    return new Response(JSON.stringify({ ok: true, paused: true }), { headers });
  }

  return new Response(JSON.stringify({ ok: false, error: 'provider_not_supported' }), { status: 501, headers });
}

/* ══ تحقق جلسة المستخدم — نفس منطق cancel-subscription.js وcheckout.js حرفياً ══ */
async function verifyUserSession(request, env) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_user_session=([^;]+)/);
  if (!match) return null;
  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 4) return null;
  const [tag, emailB64, expStr, sig] = parts;
  if (tag !== 'user') return null;
  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) return null;
  const secret = env.OWNER_SECRET || 'fallback-secret-change-me';
  const payload = `${tag}.${emailB64}.${expStr}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const expectedSig = base64url(new Uint8Array(sigBuf));
  if (expectedSig !== sig) return null;
  return atob(emailB64);
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
