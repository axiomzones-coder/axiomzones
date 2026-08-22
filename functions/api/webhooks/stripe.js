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
//   (ج) اشتراك المنظومة الكاملة: metadata.isEcosystem='1' + metadata.tier
//
// ⚠️ اشتراكات متكررة حقيقية (22 أغسطس 2026، مرحلة "ج"): checkout.js
// بقى يُنشئ Stripe Subscription فعلي (mode:'subscription') لكل شيء
// غير "مدى الحياة". هذا الملف يتعامل الآن مع 3 أحداث بدل حدث واحد:
//   - checkout.session.completed → منح الوصول الأول + تسجيل الاشتراك
//     في userRecord.subscriptions[] (يلزم لاحقاً للإلغاء/الإيقاف)
//   - invoice.paid → تجديد ناجح، تسجيل معاملة فقط (الوصول ممنوح أصلاً)
//   - customer.subscription.deleted → إلغاء فعلي، سحب الوصول المرتبط
//     بهذا الاشتراك تحديداً (لا كل وصول المستخدم) عبر البحث بـ
//     subscription id في userRecord.subscriptions[]
//
// ⚠️ نطاق مقصود لهذه المرحلة (موثَّق صراحة، لا نسيان): حالات
// 'past_due'/'unpaid' (فشل تحصيل الدفع مع استمرار محاولات Stripe) غير
// معالَجة هنا — لا سحب فوري للوصول عند أول فشل تحصيل (فترة سماح
// معيارية)، ولا إشعار للمستخدم بعد. بند مستقبلي منفصل.

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
    await handleCheckoutCompleted(event, env);
  } else if (event.type === 'invoice.paid') {
    await handleInvoicePaid(event, env);
  } else if (event.type === 'customer.subscription.deleted') {
    await handleSubscriptionDeleted(event, env);
  }

  // ── تسجيل الحدث كمُعالَج — يمنع أي تكرار مستقبلي لنفس المعرِّف ──
  await env.AZ_CONFIG_KV.put(eventKey, JSON.stringify({ processedAt: new Date().toISOString(), type: event.type }), { expirationTtl: 60 * 60 * 24 * 30 });

  return new Response(JSON.stringify({ ok: true }), { headers });
}

async function handleCheckoutCompleted(event, env) {
  const session = event.data.object;
  const meta = session.metadata || {};
  const email = meta.userEmail;
  const isBundle = meta.isBundle === '1';
  const isEcosystem = meta.isEcosystem === '1';
  const platform = meta.platform;
  const tierKey = meta.tier;
  const cycle = meta.cycle;
  const isLifetime = meta.isLifetime === '1';
  const bundleId = meta.bundleId;
  /* ══ metadata لا تدعم مصفوفات — checkout.js يبعتها كنص مفصول
     بفواصل، نفكّها هنا لمصفوفة حقيقية ══ */
  const bundlePlatforms = (meta.bundlePlatforms || '').split(',').map(function (p) { return p.trim(); }).filter(Boolean);

  if (!email || !(isBundle ? bundlePlatforms.length : (isEcosystem ? tierKey : platform))) return;

  const userRaw = await env.AZ_USERS_KV.get('user:' + email);
  if (!userRaw) return;
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
  } else if (isEcosystem) {
    /* ══ اشتراك المنظومة الكاملة — منصة وهمية "ecosystem" داخل
       Pricing Management، يمنح وصولاً لكل المنصات الحالية
       والمستقبلية دفعة واحدة (access.all=true)، بلا الحاجة
       لسرد كل منصة بالاسم كما في الباقات المحدودة ══ */
    userRecord.platformAccess.all = true;
  } else {
    // ── منصة واحدة + مستوى — كما كان بالضبط، بلا أي تغيير منطقي ──
    if (!userRecord.platformAccess.platforms.includes(platform)) {
      userRecord.platformAccess.platforms.push(platform);
    }
  }

  /* ══ تسجيل الاشتراك المتكرر (إن وُجد) — ضروري لاحقاً لربط
     customer.subscription.deleted بالضبط بهذا الشراء تحديداً، وربط
     /api/cancel-subscription و/api/pause-subscription المستقبليين
     بالاشتراك الصحيح لو المستخدم عنده أكثر من اشتراك نشط. "مدى الحياة"
     لا ينشئ Subscription أصلاً في Stripe (session.subscription = null) ══ */
  if (session.subscription) {
    userRecord.subscriptions = userRecord.subscriptions || [];
    /* منع تكرار نفس الاشتراك لو الحدث اتعالج جزئيًا من قبل بطريقة ما */
    if (!userRecord.subscriptions.some(function (s) { return s.id === session.subscription; })) {
      userRecord.subscriptions.push({
        id: session.subscription,
        provider: 'stripe',
        customerId: session.customer || null,
        kind: isBundle ? 'bundle' : (isEcosystem ? 'ecosystem' : 'platform'),
        platform: isEcosystem || isBundle ? undefined : platform,
        tier: tierKey,
        bundleId: isBundle ? bundleId : undefined,
        bundlePlatforms: isBundle ? bundlePlatforms : undefined,
        cycle,
        status: 'active',
        createdAt: new Date().toISOString(),
      });
    }
  }

  /* ══ سجل معاملة داخل نفس سجل المستخدم — لا جدول transactions منفصل
     بعد (بند مؤجَّل)، لكن هذا يحفظ الحد الأدنى الضروري للتتبّع ══ */
  userRecord.transactions = userRecord.transactions || [];
  userRecord.transactions.push(isBundle
    ? { id: event.id, isBundle: true, bundleId, platforms: bundlePlatforms, cycle, isLifetime, amount: session.amount_total, currency: session.currency, at: new Date().toISOString() }
    : isEcosystem
      ? { id: event.id, isEcosystem: true, tier: tierKey, cycle, isLifetime, amount: session.amount_total, currency: session.currency, at: new Date().toISOString() }
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
      } else {
        /* ══ "ecosystem" منصة عادية من منظور config.pricing —
           نفس مسار المنصة الواحدة بالضبط، بلا فرع خاص ══ */
        const pKey = isEcosystem ? 'ecosystem' : platform;
        if (config.pricing && config.pricing[pKey] && config.pricing[pKey].tiers && config.pricing[pKey].tiers[tierKey]) {
          config.pricing[pKey].tiers[tierKey].claimedCount = (config.pricing[pKey].tiers[tierKey].claimedCount || 0) + 1;
          await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
        }
      }
    } catch (e) { /* لا نفشل الويبهوك كله بسبب فشل تحديث العدَّاد الثانوي */ }
  }
}

/* ══ تجديد ناجح — الوصول ممنوح بالفعل منذ الشراء الأول، لا حاجة
   لإعادة منحه. الغرض الوحيد هنا: تسجيل معاملة التجديد للتتبّع
   التاريخي (تقارير MRR/Churn مستقبلاً، المرحلة "د") ══ */
async function handleInvoicePaid(event, env) {
  const invoice = event.data.object;
  /* أول فاتورة لأي اشتراك جديد بتيجي مصحوبة أحياناً بنفس حدث
     checkout.session.completed تقريباً في نفس اللحظة — نتجاهلها هنا
     لتفادي تسجيل معاملة مكررة، ونكتفي بمعاملات التجديد الفعلية
     (billing_reason = 'subscription_cycle') */
  if (invoice.billing_reason !== 'subscription_cycle') return;
  const subId = invoice.subscription;
  if (!subId) return;

  const email = await findUserEmailBySubscriptionId(subId, env);
  if (!email) return;
  const userRaw = await env.AZ_USERS_KV.get('user:' + email);
  if (!userRaw) return;
  const userRecord = JSON.parse(userRaw);
  const sub = (userRecord.subscriptions || []).find(function (s) { return s.id === subId; });

  userRecord.transactions = userRecord.transactions || [];
  userRecord.transactions.push({
    id: event.id, renewal: true, subscriptionId: subId,
    kind: sub ? sub.kind : undefined, platform: sub ? sub.platform : undefined,
    tier: sub ? sub.tier : undefined, bundleId: sub ? sub.bundleId : undefined,
    amount: invoice.amount_paid, currency: invoice.currency, at: new Date().toISOString(),
  });
  await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(userRecord));
}

/* ══ إلغاء فعلي (سواء فوري أو بعد انتهاء الفترة المدفوعة، Stripe
   بترسل الحدث ده في الحالتين وقت الإلغاء الفعلي) — سحب الوصول
   المرتبط بهذا الاشتراك تحديداً فقط، لا كل وصول المستخدم، لأن ممكن
   يكون عنده اشتراك تاني نشط منفصل ══ */
async function handleSubscriptionDeleted(event, env) {
  const subscription = event.data.object;
  const subId = subscription.id;
  const meta = subscription.metadata || {};
  const email = meta.userEmail;
  if (!email) return;

  const userRaw = await env.AZ_USERS_KV.get('user:' + email);
  if (!userRaw) return;
  const userRecord = JSON.parse(userRaw);
  userRecord.subscriptions = userRecord.subscriptions || [];
  const sub = userRecord.subscriptions.find(function (s) { return s.id === subId; });
  if (!sub) return; /* اشتراك غير معروف لدينا — تجاهل آمن */

  sub.status = 'canceled';
  sub.canceledAt = new Date().toISOString();

  userRecord.platformAccess = userRecord.platformAccess || { all: false, platforms: [] };
  if (!Array.isArray(userRecord.platformAccess.platforms)) userRecord.platformAccess.platforms = [];

  if (sub.kind === 'ecosystem') {
    /* ══ لو عنده أي اشتراك ecosystem آخر نشط (نظرياً نادر لكن ممكن)،
       لا نسحب access.all — نتحقق أولاً قبل السحب ══ */
    const stillHasEcosystem = userRecord.subscriptions.some(function (s) {
      return s.kind === 'ecosystem' && s.status === 'active' && s.id !== subId;
    });
    if (!stillHasEcosystem) userRecord.platformAccess.all = false;
  } else if (sub.kind === 'bundle' && Array.isArray(sub.bundlePlatforms)) {
    sub.bundlePlatforms.forEach(function (p) {
      /* لا نسحب منصة لو مضمونة من مصدر آخر نشط (اشتراك منصة مفردة، باقة تانية، هدية) */
      const stillGranted = userRecord.subscriptions.some(function (s) {
        return s.status === 'active' && s.id !== subId && (
          (s.kind === 'platform' && s.platform === p) ||
          (s.kind === 'bundle' && Array.isArray(s.bundlePlatforms) && s.bundlePlatforms.includes(p))
        );
      }) || (userRecord.giftedAccess && userRecord.giftedAccess[p] !== undefined);
      if (!stillGranted) {
        const idx = userRecord.platformAccess.platforms.indexOf(p);
        if (idx !== -1) userRecord.platformAccess.platforms.splice(idx, 1);
      }
    });
  } else if (sub.kind === 'platform' && sub.platform) {
    const stillGranted = userRecord.subscriptions.some(function (s) {
      return s.status === 'active' && s.id !== subId && (
        (s.kind === 'platform' && s.platform === sub.platform) ||
        (s.kind === 'bundle' && Array.isArray(s.bundlePlatforms) && s.bundlePlatforms.includes(sub.platform))
      );
    }) || (userRecord.giftedAccess && userRecord.giftedAccess[sub.platform] !== undefined);
    if (!stillGranted) {
      const idx = userRecord.platformAccess.platforms.indexOf(sub.platform);
      if (idx !== -1) userRecord.platformAccess.platforms.splice(idx, 1);
    }
  }

  await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(userRecord));
}

/* ⚠️ محدودية معروفة ومقصودة لهذه المرحلة: البحث عن مستخدم بمعرِّف
   اشتراك يمر بقراءة كل سجلات AZ_USERS_KV — غير قابل للتوسّع لقاعدة
   مستخدمين كبيرة (آلاف+). الحل الصحيح لاحقاً: فهرس منفصل
   sub_index:{subscriptionId} → email يُكتب وقت الإنشاء في
   handleCheckoutCompleted. أُجِّل عمداً هذه المرحلة (نطاق أول اشتراك
   حقيقي محدود)، ويجب تنفيذه قبل نمو قاعدة المستخدمين فعليًا. */
async function findUserEmailBySubscriptionId(subId, env) {
  const list = await env.AZ_USERS_KV.list({ prefix: 'user:' });
  for (const key of list.keys) {
    const raw = await env.AZ_USERS_KV.get(key.name);
    if (!raw) continue;
    const record = JSON.parse(raw);
    if (Array.isArray(record.subscriptions) && record.subscriptions.some(function (s) { return s.id === subId; })) {
      return key.name.replace(/^user:/, '');
    }
  }
  return null;
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
