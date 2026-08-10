// functions/api/support-submit.js
// POST /api/support-submit — Body: { name, email, category, subject, message, platform? }
// endpoint عام (بدون تسجيل دخول) لإنشاء تذكرة دعم حقيقية.
// category المسموحة: 'financial' | 'technical' | 'general'
// تذاكر 'financial' تُعطى أولوية 'urgent' تلقائياً (تظهر أولاً في الداشبورد).
// يُحاول جلب خطة العميل الحالية تلقائياً لو عنده جلسة مستخدم صالحة (بدون طلبها منه).
// Rate limit: 5 تذاكر/ساعة لكل IP — يمنع السبام.

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_CONFIG_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlKey = `ratelimit:support:${ip}`;
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

  const ALLOWED_CATEGORIES = ['financial', 'technical', 'general'];
  const category = String((body && body.category) || 'general');
  if (!ALLOWED_CATEGORIES.includes(category)) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_category' }), { status: 400, headers });
  }

  const name = String((body && body.name) || '').slice(0, 120);
  const email = String((body && body.email) || '').trim().toLowerCase().slice(0, 160);
  const subject = String((body && body.subject) || '').slice(0, 200);
  const message = String((body && body.message) || '').slice(0, 3000);
  const platform = String((body && body.platform) || '').slice(0, 40);

  if (!name || !email || !email.includes('@') || !message) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_fields' }), { status: 400, headers });
  }

  // ── سياق تلقائي: الخطة الحالية لو المستخدم مسجّل دخول فعلاً (بدون سؤاله) ──
  let plan = null;
  try {
    if (env.AZ_USERS_KV) {
      const raw = await env.AZ_USERS_KV.get('user:' + email);
      if (raw) plan = JSON.parse(raw).plan || null;
    }
  } catch (e) { /* تجاهل، ليست حرجة */ }

  const browserLang = (request.headers.get('Accept-Language') || '').split(',')[0] || null;
  const country = (request.cf && request.cf.country) || 'XX';

  const ticketId = 'SUP-' + Math.random().toString(36).substring(2, 6).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();

  const ticket = {
    id: ticketId,
    name, email, category, subject, message,
    platform: platform || null,
    plan, browserLang, country,
    priority: category === 'financial' ? 'urgent' : 'normal',
    status: 'open',
    replies: [],
    createdAt: new Date().toISOString(),
  };

  try {
    const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
    const config = configRaw ? JSON.parse(configRaw) : {};
    config.supportTickets = config.supportTickets || [];
    config.supportTickets.unshift(ticket);
    config.supportTickets = config.supportTickets.slice(0, 500); // الاحتفاظ بآخر 500 تذكرة
    await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'save_failed' }), { status: 500, headers });
  }

  return new Response(JSON.stringify({ ok: true, ticketId }), { headers });
}
