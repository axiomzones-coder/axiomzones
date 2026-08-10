// functions/api/contact-submit.js
// POST /api/contact-submit — Body: { kind:'contact'|'subscribe_interest', name, email, message?, plan? }
// endpoint عام (بدون تسجيل دخول) يستقبل: (أ) رسائل نموذج "تواصل معنا"،
// (ب) رغبات الاشتراك من أزرار الأسعار (طالما بوابات الدفع لسه قيد الموافقة).
// محدود بـ5 طلبات/ساعة لكل IP لمنع السبام. يُحفظ في AZ_CONFIG_KV تحت مفتاح "contactLeads"
// (نفس الكونفيج الرئيسي، بمفتاح مستقل — يُقرأ من الداشبورد عبر config-get العام أصلاً).

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_CONFIG_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  // ── Rate limiting: 5 طلبات/ساعة لكل IP ──
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlKey = `ratelimit:contact:${ip}`;
  const rlRaw = await env.AZ_CONFIG_KV.get(rlKey);
  const rlCount = rlRaw ? (JSON.parse(rlRaw).count || 0) : 0;
  if (rlCount >= 5) {
    return new Response(JSON.stringify({ ok: false, error: 'rate_limited' }), { status: 429, headers });
  }
  await env.AZ_CONFIG_KV.put(rlKey, JSON.stringify({ count: rlCount + 1 }), { expirationTtl: 3600 });

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  const ALLOWED_KINDS = ['contact', 'subscribe_interest', 'waitlist'];
  const kind = String((body && body.kind) || '');
  if (!ALLOWED_KINDS.includes(kind)) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_kind' }), { status: 400, headers });
  }

  const name = String((body && body.name) || '').slice(0, 120);
  const email = String((body && body.email) || '').slice(0, 160);
  const message = String((body && body.message) || '').slice(0, 2000);
  const plan = String((body && body.plan) || '').slice(0, 40);

  if (!name || !email || !email.includes('@')) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_fields' }), { status: 400, headers });
  }

  const record = {
    id: crypto.randomUUID(),
    kind, name, email, message, plan,
    country: (request.cf && request.cf.country) || 'XX',
    read: false,
    createdAt: new Date().toISOString(),
  };

  try {
    const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
    const config = configRaw ? JSON.parse(configRaw) : {};
    config.contactLeads = config.contactLeads || [];
    config.contactLeads.unshift(record);
    config.contactLeads = config.contactLeads.slice(0, 200); // الاحتفاظ بآخر 200 فقط
    await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'save_failed' }), { status: 500, headers });
  }

  return new Response(JSON.stringify({ ok: true }), { headers });
}
