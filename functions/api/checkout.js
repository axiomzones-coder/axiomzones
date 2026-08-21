// functions/api/checkout.js
// POST /api/checkout — يتطلب جلسة مستخدم صالحة
// Body: { platform: 'nabigha', tier: 'growth', cycle: 'monthly'|'annual' }
//
// ⚠️ مبدأ أمني جوهري: لا نثق أبداً بأي سعر يصل من المتصفح — الواجهة
// ترسل فقط "أي منصة/مستوى/دورة"، والسيرفر يقرأ السعر الحقيقي من
// config.pricing (نفس المصدر اللي بيتحكم فيه المالك من الداشبورد)،
// ويبني جلسة الدفع بالسعر الحقيقي فقط.

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_CONFIG_KV || !env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }
  if (!env.STRIPE_SECRET_KEY) {
    return new Response(JSON.stringify({ ok: false, error: 'payment_not_configured' }), { status: 503, headers });
  }

  // ── تحقق من جلسة المستخدم (نفس منطق كل الملفات الأخرى بالضبط) ──
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
  const platform = String((body && body.platform) || '').trim().toLowerCase();
  const tierKey = String((body && body.tier) || '').trim().toLowerCase();
  const cycle = (body && body.cycle === 'annual') ? 'annual' : 'monthly';

  if (!platform || !tierKey) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_fields' }), { status: 400, headers });
  }

  // ── ① قراءة السعر الحقيقي من config.pricing — المصدر الوحيد المعتمَد ──
  const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
  const configForGateway = configRaw ? JSON.parse(configRaw) : {};
  /* ══ احترام تفعيل/إيقاف البوابة من الداشبورد — لو المالك عطَّل Stripe
     يدوياً، نرفض حتى لو المفتاح السري مضبوط فعلياً في متغيّرات البيئة ══ */
  const gatewayEnabled = configForGateway.paymentGateways && configForGateway.paymentGateways.stripe && configForGateway.paymentGateways.stripe.enabled === true;
  if (!gatewayEnabled) {
    return new Response(JSON.stringify({ ok: false, error: 'gateway_disabled' }), { status: 503, headers });
  }
  const config = configForGateway; // نفس الكائن المُحلَّل بالفعل أعلاه — لا داعي لتحليل JSON مرتين
  const platformPricing = (config.pricing && config.pricing[platform] && config.pricing[platform].tiers) || {};
  const tier = platformPricing[tierKey];

  if (!tier || tier.enabled !== true) {
    return new Response(JSON.stringify({ ok: false, error: 'tier_not_available' }), { status: 404, headers });
  }

  const isLifetime = (tier.price !== undefined);
  let amountCents, currency, mode, intervalLabel;

  if (isLifetime) {
    // ── تحقق إضافي: لو الكمية محدودة ونفدت، ارفض الدفع حتى لو الرابط وصل ──
    if (tier.maxCount > 0 && (tier.claimedCount || 0) >= tier.maxCount) {
      return new Response(JSON.stringify({ ok: false, error: 'sold_out' }), { status: 410, headers });
    }
    amountCents = Math.round((tier.price || 0) * 100);
    mode = 'payment'; // دفعة واحدة، لا اشتراك متكرر
  } else {
    const monthly = tier.monthlyPrice || 0;
    if (cycle === 'annual') {
      const discount = tier.annualDiscount || 0;
      amountCents = Math.round(monthly * 12 * (1 - discount / 100) * 100);
      mode = 'payment'; // يُحصَّل سنوياً كدفعة واحدة (تبسيط أولي، لا اشتراك Stripe متكرر بعد)
      intervalLabel = 'سنوي';
    } else {
      amountCents = Math.round(monthly * 100);
      mode = 'payment';
      intervalLabel = 'شهري';
    }
  }
  currency = (tier.currency || 'USD').toLowerCase();

  if (amountCents <= 0) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_price' }), { status: 400, headers });
  }

  // ── ② بناء جلسة Stripe Checkout عبر REST API مباشرة (لا حزمة SDK) ──
  const originUrl = new URL(request.url).origin;
  const stripeParams = new URLSearchParams();
  stripeParams.append('mode', mode);
  stripeParams.append('success_url', originUrl + '/payment-success?session_id={CHECKOUT_SESSION_ID}');
  stripeParams.append('cancel_url', originUrl + '/pricing-cancelled');
  stripeParams.append('customer_email', email);
  stripeParams.append('line_items[0][price_data][currency]', currency);
  stripeParams.append('line_items[0][price_data][unit_amount]', String(amountCents));
  stripeParams.append('line_items[0][price_data][product_data][name]', `${platform} — ${tier.name || tierKey}${intervalLabel ? ' (' + intervalLabel + ')' : ''}`);
  stripeParams.append('line_items[0][quantity]', '1');
  // ── metadata: تُقرَأ عند الـWebhook لتحديد بالضبط مين ياخد وصول لإيه ──
  stripeParams.append('metadata[userEmail]', email);
  stripeParams.append('metadata[platform]', platform);
  stripeParams.append('metadata[tier]', tierKey);
  stripeParams.append('metadata[cycle]', cycle);
  stripeParams.append('metadata[isLifetime]', isLifetime ? '1' : '0');

  const stripeRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + env.STRIPE_SECRET_KEY,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: stripeParams.toString(),
  });

  const stripeData = await stripeRes.json();
  if (!stripeRes.ok) {
    return new Response(JSON.stringify({ ok: false, error: 'stripe_error', detail: stripeData.error && stripeData.error.message }), { status: 502, headers });
  }

  return new Response(JSON.stringify({ ok: true, checkoutUrl: stripeData.url }), { headers });
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
