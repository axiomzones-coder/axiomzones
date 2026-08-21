// functions/api/webhooks/stripe.js
// POST /api/webhooks/stripe — يُستدعى من Stripe مباشرة عند نجاح الدفع
//
// خطوات إلزامية بالترتيب: (١) قراءة الجسم الخام (raw body) — التوقيع
// يعتمد على البايتات الأصلية بالضبط، لا JSON مُعاد تفسيره. (٢) التحقق
// من التوقيع (Stripe-Signature) — رفض أي طلب لم يوقِّعه Stripe فعلياً.
// (٣) فحص Idempotency — منع معالجة نفس الحدث مرتين لو Stripe أعاد
// الإرسال (يحدث فعلياً، ليس افتراضاً نظرياً). (٤) منح الوصول الفعلي —
// مساران بديلان حسب نوع الطلب اللي بناه checkout.js:
//   (أ) منصة واحدة + مستوى: metadata.platform + metadata.tier
//   (ب) باقة مُجمَّعة: metadata.isBundle='1' + metadata.bundlePlatforms
//       (قائمة مفصولة بفواصل) — يمنح وصولاً لكل منصة فيها دفعة واحدة.

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.STRIPE_WEBHOOK_SECRET || !env.AZ_USERS_KV || !env.AZ_CONFIG_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  const rawBody = await request.text();
  const sigHeader = request.headers.get('Stripe-Signature') || '';

  const isValid = await verifyStripeSignature(rawBody, sigHeader, env.STRIPE_WEBHOOK_SECRET);
  if (!isValid) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_signature' }), { status: 400, headers });
  }

  let event;
  try { event = JSON.parse(rawBody); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_json' }), { status: 400, headers });
  }

  // ── Idempotency: هل عالجنا هذا الحدث من قبل؟ (Stripe قد يعيد الإرسال) ──
  const eventKey = 'stripe_event:' + event.id;
  const alreadyProcessed = await env.AZ_CONFIG_KV.get(eventKey);
  if (alreadyProcessed) {
    return new Response(JSON.stringify({ ok: true, alreadyProcessed: true }), { headers });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const meta = session.metadata || {};
    const email = meta.userEmail;
    const isBundle = meta.isBundle === '1';
    const platform = meta.platform;
    const tierKey = meta.tier;
    const cycle = meta.cycle;
    const isLifetime = meta.isLifetime === '1';
    const bundleId = meta.bundleId;
    /* ══ metadata لا تدعم مصفوفات — checkout.js يبعتها كنص مفصول
       بفواصل، نفكّها هنا لمصفوفة حقيقية ══ */
    const bundlePlatforms = (meta.bundlePlatforms || '').split(',').map(function (p) { return p.trim(); }).filter(Boolean);

    if (email && (isBundle ? bundlePlatforms.length : platform)) {
      const userRaw = await env.AZ_USERS_KV.get('user:' + email);
      if (userRaw) {
        const userRecord = JSON.parse(userRaw);
        userRecord.platformAccess = userRecord.platformAccess || { all: false, platforms: [] };
        if (!Array.isArray(userRecord.platformAccess.platforms)) userRecord.platformAccess.platforms = [];

        if (isBundle) {
          // ── باقة مُجمَّعة: منح وصول لكل منصة فيها دفعة واحدة ──
          bundlePlatforms.forEach(function (p) {
            if (!userRecord.platformAccess.platforms.includes(p)) {
              userRecord.platformAccess.platforms.push(p);
            }
          });
        } else {
          // ── منصة واحدة + مستوى — كما كان بالضبط، بلا أي تغيير منطقي ──
          if (!userRecord.platformAccess.platforms.includes(platform)) {
            userRecord.platformAccess.platforms.push(platform);
          }
        }

        /* ══ سجل معاملة داخل نفس سجل المستخدم — لا جدول transactions منفصل
           بعد (بند مؤجَّل)، لكن هذا يحفظ الحد الأدنى الضروري للتتبّع ══ */
        userRecord.transactions = userRecord.transactions || [];
        userRecord.transactions.push(isBundle
          ? { id: event.id, isBundle: true, bundleId, platforms: bundlePlatforms, cycle, isLifetime, amount: session.amount_total, currency: session.currency, at: new Date().toISOString() }
          : { id: event.id, platform, tier: tierKey, cycle, isLifetime, amount: session.amount_total, currency: session.currency, at: new Date().toISOString() }
        );
        await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(userRecord));

        // ── لو مدى الحياة محدودة العدد، نزوِّد عدَّاد "تم بيع" تلقائياً ──
        if (isLifetime) {
          try {
            const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
            const config = configRaw ? JSON.parse(configRaw) : {};
            if (isBundle) {
              /* ══ ملاحظة: بنية config.bundles الحالية (القسم (65) بقاعدة
                 المعرفة) لا تحتوي claimedCount/maxCount أصلاً — عروض
                 "مدى الحياة المحدودة" للباقات تُدار حالياً بـofferExpiry
                 (تاريخ) فقط، لا بعدّاد كمية. لا شيء يُحدَّث هنا عمداً؛
                 إضافة عدّاد كمية للباقات مستقبلاً = بند منفصل يحتاج
                 تعديل checkout.js أيضاً (فحص sold_out بالكمية) ══ */
            } else if (config.pricing && config.pricing[platform] && config.pricing[platform].tiers && config.pricing[platform].tiers[tierKey]) {
              config.pricing[platform].tiers[tierKey].claimedCount = (config.pricing[platform].tiers[tierKey].claimedCount || 0) + 1;
              await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
            }
          } catch (e) { /* لا نفشل الويبهوك كله بسبب فشل تحديث العدَّاد الثانوي */ }
        }
      }
    }
  }

  // ── تسجيل الحدث كمُعالَج — يمنع أي تكرار مستقبلي لنفس المعرِّف ──
  await env.AZ_CONFIG_KV.put(eventKey, JSON.stringify({ processedAt: new Date().toISOString(), type: event.type }), { expirationTtl: 60 * 60 * 24 * 30 });

  return new Response(JSON.stringify({ ok: true }), { headers });
}

/* ══ تحقق يدوي من توقيع Stripe — نفس الخوارزمية الرسمية بالضبط:
   HMAC-SHA256(secret, timestamp + "." + rawBody) يجب أن يطابق v1 ══ */
async function verifyStripeSignature(rawBody, sigHeader, secret) {
  const parts = {};
  sigHeader.split(',').forEach(function (kv) {
    const idx = kv.indexOf('=');
    if (idx === -1) return;
    parts[kv.slice(0, idx)] = kv.slice(idx + 1);
  });
  const timestamp = parts.t;
  const v1 = parts.v1;
  if (!timestamp || !v1) return false;

  // ── رفض التوقيعات القديمة جداً (أكثر من 5 دقائق) — يمنع إعادة تشغيل هجومية (Replay Attack) ──
  const age = Date.now() / 1000 - parseInt(timestamp, 10);
  if (age > 300 || age < -60) return false;

  const signedPayload = timestamp + '.' + rawBody;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
  const computedHex = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

  return computedHex === v1;
}
