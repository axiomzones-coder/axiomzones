// functions/api/cancel-subscription.js
// POST /api/cancel-subscription — يتطلب جلسة مستخدم صالحة
// Body: { subscriptionId: 'sub_...' }
//
// إلغاء فعلي عبر Stripe API — لا يسحب الوصول فوراً هنا مباشرة، بل
// يطلب من Stripe إلغاء الاشتراك في نهاية الفترة المدفوعة الحالية
// (cancel_at_period_end)، وهذا هو السلوك القياسي المتوقَّع من
// المستخدمين (لا استرداد جزئي تلقائي لباقي الفترة). السحب الفعلي
// للوصول يحدث لاحقاً عبر webhooks/stripe.js عند وصول حدث
// customer.subscription.deleted الحقيقي من Stripe وقت انتهاء الفترة.
//
// ⚠️ أمان جوهري: نتحقق أن الاشتراك المطلوب إلغاؤه فعلاً مملوك لصاحب
// الجلسة الحالية قبل أي استدعاء لـStripe — لا نثق بأي subscriptionId
// يصل من المتصفح بلا تحقق ملكية.

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

  // ── تحقق ملكية إلزامي — لا نلغي اشتراكاً غير مملوك لصاحب الجلسة ──
  if (!sub) {
    return new Response(JSON.stringify({ ok: false, error: 'subscription_not_found' }), { status: 404, headers });
  }
  if (sub.status !== 'active') {
    return new Response(JSON.stringify({ ok: false, error: 'subscription_not_active' }), { status: 409, headers });
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
      body: 'cancel_at_period_end=true',
    });
    const data = await res.json();
    if (!res.ok) {
      return new Response(JSON.stringify({ ok: false, error: 'stripe_error', detail: data.error && data.error.message }), { status: 502, headers });
    }
    // ── تسجيل "طلب إلغاء" فوراً — الحالة النهائية "canceled" تُسجَّل لاحقاً عبر الـwebhook وقت الإلغاء الفعلي ──
    sub.cancelRequestedAt = new Date().toISOString();
    sub.cancelAtPeriodEnd = true;
    sub.currentPeriodEnd = data.current_period_end ? new Date(data.current_period_end * 1000).toISOString() : sub.currentPeriodEnd;
    await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(userRecord));
    return new Response(JSON.stringify({ ok: true, cancelAtPeriodEnd: true, periodEnd: sub.currentPeriodEnd }), { headers });
  }

  /* ⚠️ Paddle: غير مُنفَّذ بعد — البوابة نفسها لسه بانتظار موافقة Paddle
     على الحساب (القسم 69/70 بقاعدة المعرفة)، والاشتراكات المتكررة
     الحقيقية لـPaddle مؤجَّلة عمداً حتى تُبنى (مرحلة منفصلة تالية
     لسترايب) */
  return new Response(JSON.stringify({ ok: false, error: 'provider_not_supported' }), { status: 501, headers });
}

/* ══ تحقق جلسة المستخدم — نفس منطق checkout.js حرفياً، لضمان اتساق
   قواعد الأمان عبر كل الـendpoints المصادَق عليها بجلسة مستخدم ══ */
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
