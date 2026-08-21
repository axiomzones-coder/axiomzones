// functions/api/checkout.js
// POST /api/checkout — يتطلب جلسة مستخدم صالحة
// مساران بديلان في نفس الـendpoint:
//   (أ) منصة واحدة + مستوى: { platform: 'nabigha', tier: 'growth', cycle: 'monthly'|'annual', provider?: 'stripe'|'paddle' }
//   (ب) باقة مُجمَّعة (Bundle): { bundleId: 'bundle_...', provider?: 'stripe'|'paddle' }
//
// ⚠️ مبدأ أمني جوهري: لا نثق أبداً بأي سعر يصل من المتصفح — الواجهة
// ترسل فقط "أي منصة/مستوى/دورة" أو "أي باقة"، والسيرفر يقرأ السعر
// الحقيقي من config.pricing أو config.bundles (نفس المصدر اللي
// بيتحكم فيه المالك من الداشبورد).
//
// ══ موجِّه حقيقي متعدد البوابات ══
// المنطق المشترك (تحقق الجلسة) يعمل مرة واحدة بغض النظر عن البوابة أو
// المسار. بعدها حساب السعر حسب المسار (منصة+مستوى أو باقة)، ثم التوجيه
// لدالة البوابة المحدَّدة (buildStripeSession أو buildPaddleSession).
// إضافة بوابة جديدة مستقبلاً = دالة جديدة هنا + سطر واحد في
// PROVIDER_BUILDERS، بلا لمس أي منطق مشترك قائم.
//
// ⚠️ ناقص عمداً حتى الآن (موثَّق صراحة، القسم (68) بقاعدة المعرفة):
// نجاح دفع باقة يبني جلسة Stripe صحيحة بميتاداتا isBundle+bundlePlatforms،
// لكن functions/api/webhooks/stripe.js لم يُحدَّث بعد ليقرأ هذه
// الميتاداتا ويمنح وصولاً فعلياً لكل منصات الباقة. لا تُفعَّل بيع
// باقات حقيقي بمفاتيح Stripe حقيقية قبل تحديث الـwebhook.

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_CONFIG_KV || !env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  // ── تحقق من جلسة المستخدم (مشترك، بغض النظر عن المسار أو البوابة) ──
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
  const bundleId = String((body && body.bundleId) || '').trim();
  const platform = String((body && body.platform) || '').trim().toLowerCase();
  const tierKey = String((body && body.tier) || '').trim().toLowerCase();
  const cycle = (body && body.cycle === 'annual') ? 'annual' : 'monthly';
  let requestedProvider = String((body && body.provider) || '').trim().toLowerCase();
  const isBundleRequest = !!bundleId;

  if (!isBundleRequest && (!platform || !tierKey)) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_fields' }), { status: 400, headers });
  }

  // ── قراءة الإعدادات مرة واحدة (مشترك) ──
  const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
  const config = configRaw ? JSON.parse(configRaw) : {};
  const gatewaysConfig = config.paymentGateways || {};

  /* ══ اختيار البوابة: لو الواجهة حدَّدت واحدة صراحةً، نستخدمها (بشرط
     كونها مفعَّلة). غير ذلك، نختار أول بوابة مفعَّلة تلقائيًا — يسمح
     للواجهة مستقبلاً بعرض خيار للزائر لو أكثر من بوابة مفعَّلة معًا ══ */
  if (!requestedProvider || !gatewaysConfig[requestedProvider] || gatewaysConfig[requestedProvider].enabled !== true) {
    requestedProvider = Object.keys(gatewaysConfig).find(function (p) { return gatewaysConfig[p] && gatewaysConfig[p].enabled === true; }) || '';
  }
  if (!requestedProvider) {
    return new Response(JSON.stringify({ ok: false, error: 'gateway_disabled' }), { status: 503, headers });
  }
  if (!PROVIDER_BUILDERS[requestedProvider]) {
    return new Response(JSON.stringify({ ok: false, error: 'gateway_not_implemented' }), { status: 501, headers });
  }

  const originUrl = new URL(request.url).origin;
  let orderInfo;

  if (isBundleRequest) {
    // ══ مسار (ب): باقة مُجمَّعة — السعر والمنصات من config.bundles حصراً ══
    const bundles = config.bundles || [];
    const bundle = bundles.find(function (b) { return b.id === bundleId; });

    if (!bundle || bundle.enabled !== true || bundle.archived === true) {
      return new Response(JSON.stringify({ ok: false, error: 'bundle_not_available' }), { status: 404, headers });
    }
    if (bundle.type === 'lifetime_limited' && bundle.offerExpiry && new Date(bundle.offerExpiry) < new Date()) {
      return new Response(JSON.stringify({ ok: false, error: 'offer_expired' }), { status: 410, headers });
    }
    if (!Array.isArray(bundle.platforms) || !bundle.platforms.length) {
      return new Response(JSON.stringify({ ok: false, error: 'bundle_not_available' }), { status: 404, headers });
    }

    const isLifetime = bundle.type === 'lifetime_limited';
    const amountCents = Math.round((bundle.price || 0) * (1 - (bundle.discount || 0) / 100) * 100);
    if (amountCents <= 0) {
      return new Response(JSON.stringify({ ok: false, error: 'invalid_price' }), { status: 400, headers });
    }
    const currency = (bundle.currency || 'USD').toLowerCase();
    const intervalLabel = bundle.type === 'monthly' ? 'شهري' : (bundle.type === 'annual' ? 'سنوي' : undefined);

    orderInfo = {
      email, originUrl, isBundle: true,
      bundleId: bundle.id, bundleName: bundle.name || bundle.id, bundlePlatforms: bundle.platforms,
      cycle: bundle.type === 'annual' ? 'annual' : 'monthly',
      isLifetime, amountCents, currency, intervalLabel,
    };
  } else {
    // ══ مسار (أ): منصة واحدة + مستوى — كما كان بالضبط، بلا أي تعديل منطقي ══
    const platformPricing = (config.pricing && config.pricing[platform] && config.pricing[platform].tiers) || {};
    const tier = platformPricing[tierKey];

    if (!tier || tier.enabled !== true) {
      return new Response(JSON.stringify({ ok: false, error: 'tier_not_available' }), { status: 404, headers });
    }

    const isLifetime = (tier.price !== undefined);
    let amountCents, intervalLabel;

    if (isLifetime) {
      if (tier.maxCount > 0 && (tier.claimedCount || 0) >= tier.maxCount) {
        return new Response(JSON.stringify({ ok: false, error: 'sold_out' }), { status: 410, headers });
      }
      amountCents = Math.round((tier.price || 0) * 100);
    } else {
      const monthly = tier.monthlyPrice || 0;
      if (cycle === 'annual') {
        const discount = tier.annualDiscount || 0;
        amountCents = Math.round(monthly * 12 * (1 - discount / 100) * 100);
        intervalLabel = 'سنوي';
      } else {
        amountCents = Math.round(monthly * 100);
        intervalLabel = 'شهري';
      }
    }
    const currency = (tier.currency || 'USD').toLowerCase();

    if (amountCents <= 0) {
      return new Response(JSON.stringify({ ok: false, error: 'invalid_price' }), { status: 400, headers });
    }

    orderInfo = { email, originUrl, isBundle: false, platform, tierKey, tierName: tier.name || tierKey, cycle, isLifetime, amountCents, currency, intervalLabel };
  }

  // ── التوجيه الفعلي لدالة البوابة المحدَّدة (نفس المسار لكلا الحالتين) ──
  try {
    const result = await PROVIDER_BUILDERS[requestedProvider](orderInfo, env);
    if (!result.ok) {
      return new Response(JSON.stringify({ ok: false, error: result.error || 'gateway_error', detail: result.detail }), { status: result.status || 502, headers });
    }
    return new Response(JSON.stringify({ ok: true, provider: requestedProvider, checkoutUrl: result.checkoutUrl }), { headers });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'gateway_exception' }), { status: 502, headers });
  }
}

/* ══ سجل دوال البوابات — إضافة بوابة جديدة = دالة جديدة + سطر واحد هنا ══ */
const PROVIDER_BUILDERS = {
  stripe: buildStripeSession,
  paddle: buildPaddleSession,
};

async function buildStripeSession(order, env) {
  if (!env.STRIPE_SECRET_KEY) {
    return { ok: false, error: 'payment_not_configured', status: 503 };
  }
  const productName = order.isBundle
    ? `باقة — ${order.bundleName}${order.intervalLabel ? ' (' + order.intervalLabel + ')' : ''}`
    : `${order.platform} — ${order.tierName}${order.intervalLabel ? ' (' + order.intervalLabel + ')' : ''}`;

  const stripeParams = new URLSearchParams();
  stripeParams.append('mode', 'payment');
  stripeParams.append('success_url', order.originUrl + '/payment-success?session_id={CHECKOUT_SESSION_ID}');
  stripeParams.append('cancel_url', order.originUrl + '/pricing-cancelled');
  stripeParams.append('customer_email', order.email);
  stripeParams.append('line_items[0][price_data][currency]', order.currency);
  stripeParams.append('line_items[0][price_data][unit_amount]', String(order.amountCents));
  stripeParams.append('line_items[0][price_data][product_data][name]', productName);
  stripeParams.append('line_items[0][quantity]', '1');
  stripeParams.append('metadata[userEmail]', order.email);
  if (order.isBundle) {
    stripeParams.append('metadata[isBundle]', '1');
    stripeParams.append('metadata[bundleId]', order.bundleId);
    /* ⚠️ webhooks/stripe.js لازم يتحدَّث ليقرأ الحقل ده ويمنح وصولاً
       لكل منصة فيه — غير منفَّذ من جهة الـwebhook حتى الآن */
    stripeParams.append('metadata[bundlePlatforms]', order.bundlePlatforms.join(','));
  } else {
    stripeParams.append('metadata[platform]', order.platform);
    stripeParams.append('metadata[tier]', order.tierKey);
  }
  stripeParams.append('metadata[cycle]', order.cycle);
  stripeParams.append('metadata[isLifetime]', order.isLifetime ? '1' : '0');

  const res = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + env.STRIPE_SECRET_KEY,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: stripeParams.toString(),
  });
  const data = await res.json();
  if (!res.ok) {
    return { ok: false, error: 'stripe_error', detail: data.error && data.error.message, status: 502 };
  }
  return { ok: true, checkoutUrl: data.url };
}

/* ══ Paddle — بنية جاهزة، منطق حقيقي غير مُنفَّذ بعد بصراحة كاملة.
   يُرجِع خطأ واضح صريح بدل التظاهر بالعمل — يُستكمَل فور توفر حساب
   Paddle حقيقي واختباره، دون أي حاجة لتعديل أي جزء آخر من هذا الملف ══ */
async function buildPaddleSession(order, env) {
  return { ok: false, error: 'paddle_not_yet_implemented', status: 501 };
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
