// functions/api/webhooks/paddle.js
// POST /api/webhooks/paddle — يُستدعى من Paddle مباشرة عند نجاح الدفع
//
// نفس البنية والمبدأ العام المطبَّق في webhooks/stripe.js تمامًا: قراءة
// raw body، تحقق توقيع، فحص Idempotency، ثم منح الوصول الفعلي — مسارا
// منصة+مستوى وباقة معاً بنفس شكل custom_data المستخدم في checkout.js
// (buildPaddleSession).
//
// ⚠️ فروق جوهرية عن توقيع Stripe (موثَّقة رسميًا من Paddle):
// - اسم الهيدر: Paddle-Signature (لا Stripe-Signature)
// - الصيغة: ts=<timestamp>;h1=<hex> (فاصلة منقوطة، لا فاصلة)
// - البايلود الموقَّع: "{ts}:{rawBody}" (نقطتين، لا نقطة)
// - حدث النجاح: transaction.completed (لا checkout.session.completed)
// - بيانات المستخدم المخصَّصة: event.data.custom_data (لا metadata)

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.PADDLE_WEBHOOK_SECRET || !env.AZ_USERS_KV || !env.AZ_CONFIG_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  const rawBody = await request.text();
  const sigHeader = request.headers.get('Paddle-Signature') || '';

  const isValid = await verifyPaddleSignature(rawBody, sigHeader, env.PADDLE_WEBHOOK_SECRET);
  if (!isValid) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_signature' }), { status: 400, headers });
  }

  let event;
  try { event = JSON.parse(rawBody); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_json' }), { status: 400, headers });
  }

  // ── Idempotency: نفس مبدأ stripe.js بالضبط — بادئة منفصلة (paddle_event) تمنع أي تصادم مع أحداث Stripe ──
  const eventKey = 'paddle_event:' + event.event_id;
  const alreadyProcessed = await env.AZ_CONFIG_KV.get(eventKey);
  if (alreadyProcessed) {
    return new Response(JSON.stringify({ ok: true, alreadyProcessed: true }), { headers });
  }

  if (event.event_type === 'transaction.completed') {
    const txn = event.data || {};
    const meta = txn.custom_data || {};
    const email = meta.userEmail;
    const isBundle = meta.isBundle === '1';
    const platform = meta.platform;
    const tierKey = meta.tier;
    const cycle = meta.cycle;
    const isLifetime = meta.isLifetime === '1';
    const bundleId = meta.bundleId;
    const bundlePlatforms = (meta.bundlePlatforms || '').split(',').map(function (p) { return p.trim(); }).filter(Boolean);

    if (email && (isBundle ? bundlePlatforms.length : platform)) {
      const userRaw = await env.AZ_USERS_KV.get('user:' + email);
      if (userRaw) {
        const userRecord = JSON.parse(userRaw);
        userRecord.platformAccess = userRecord.platformAccess || { all: false, platforms: [] };
        if (!Array.isArray(userRecord.platformAccess.platforms)) userRecord.platformAccess.platforms = [];

        if (isBundle) {
          bundlePlatforms.forEach(function (p) {
            if (!userRecord.platformAccess.platforms.includes(p)) {
              userRecord.platformAccess.platforms.push(p);
            }
          });
        } else {
          if (!userRecord.platformAccess.platforms.includes(platform)) {
            userRecord.platformAccess.platforms.push(platform);
          }
        }

        const totals = txn.details && txn.details.totals;
        userRecord.transactions = userRecord.transactions || [];
        userRecord.transactions.push(isBundle
          ? { id: event.event_id, provider: 'paddle', isBundle: true, bundleId, platforms: bundlePlatforms, cycle, isLifetime, amount: totals && totals.total, currency: txn.currency_code, at: new Date().toISOString() }
          : { id: event.event_id, provider: 'paddle', platform, tier: tierKey, cycle, isLifetime, amount: totals && totals.total, currency: txn.currency_code, at: new Date().toISOString() }
        );
        await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(userRecord));

        // ── لو مدى الحياة محدودة العدد (منصة واحدة فقط — الباقات لا تدعم عدّاد كمية بعد، نفس ملاحظة stripe.js) ──
        if (isLifetime && !isBundle) {
          try {
            const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
            const config = configRaw ? JSON.parse(configRaw) : {};
            if (config.pricing && config.pricing[platform] && config.pricing[platform].tiers && config.pricing[platform].tiers[tierKey]) {
              config.pricing[platform].tiers[tierKey].claimedCount = (config.pricing[platform].tiers[tierKey].claimedCount || 0) + 1;
              await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
            }
          } catch (e) { /* لا نفشل الويبهوك كله بسبب فشل تحديث العدَّاد الثانوي */ }
        }
      }
    }
  }

  // ── تسجيل الحدث كمُعالَج — يمنع أي تكرار مستقبلي لنفس المعرِّف ──
  await env.AZ_CONFIG_KV.put(eventKey, JSON.stringify({ processedAt: new Date().toISOString(), type: event.event_type }), { expirationTtl: 60 * 60 * 24 * 30 });

  return new Response(JSON.stringify({ ok: true }), { headers });
}

/* ══ تحقق يدوي من توقيع Paddle — موثَّق رسميًا (developer.paddle.com):
   HMAC-SHA256(secret, "{ts}:{rawBody}") يجب أن يطابق h1، بمقارنة زمن
   ثابت (Constant-Time) — ثغرة توقيت حقيقية موثَّقة (GHSA-mjgf-xj26-9qf9)
   اكتُشفت في مكتبة خارجية استخدمت مقارنة نصية عادية (==) بدل هذا ══ */
async function verifyPaddleSignature(rawBody, sigHeader, secret) {
  const parts = {};
  sigHeader.split(';').forEach(function (kv) {
    const idx = kv.indexOf('=');
    if (idx === -1) return;
    parts[kv.slice(0, idx)] = kv.slice(idx + 1);
  });
  const timestamp = parts.ts;
  const h1 = parts.h1;
  if (!timestamp || !h1) return false;

  // ── حماية إضافية من Replay Attack (اجتهاد دفاعي بنفس نمط stripe.js، وليس شرطاً موثَّقاً إلزاميًا من Paddle) ──
  const age = Date.now() / 1000 - parseInt(timestamp, 10);
  if (age > 300 || age < -60) return false;

  const signedPayload = timestamp + ':' + rawBody;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
  const computedHex = Array.from(new Uint8Array(sigBuf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');

  return timingSafeEqualHex(computedHex, h1.toLowerCase());
}

/* ══ مقارنة بزمن ثابت — تمنع استنتاج التوقيع الصحيح حرفاً بحرف عبر قياس
   زمن الاستجابة (Timing Attack)، بخلاف مقارنة `===` العادية اللي بتوقف
   عند أول اختلاف ══ */
function timingSafeEqualHex(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
