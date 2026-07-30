// functions/api/track.js
// POST /api/track — Body: { type: 'pageview'|'platform_click'|'signup'|'login', platform?: string }
// يسجّل حدثاً حقيقياً في AZ_ANALYTICS_KV مع كود الدولة الحقيقي من Cloudflare (request.cf.country)
// لا يحتاج تسجيل دخول — يُستدعى من كل زائر. فشله لا يجب أن يكسر تجربة المستخدم أبداً (fire-and-forget)

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  // لو الـ KV لسه مش مربوط، رجّع نجاح صامت — لا نكسر الواجهة، بس مفيش تسجيل فعلي
  if (!env.AZ_ANALYTICS_KV) {
    return new Response(JSON.stringify({ ok: true, recorded: false }), { headers });
  }

  let body;
  try { body = await request.json(); } catch (e) { body = {}; }

  const ALLOWED_TYPES = ['pageview', 'platform_click', 'signup', 'login'];
  const type = String((body && body.type) || '');
  if (!ALLOWED_TYPES.includes(type)) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_type' }), { status: 400, headers });
  }

  const platform = (body && body.platform) ? String(body.platform).slice(0, 40) : null;
  // كود الدولة الحقيقي — Cloudflare يوفّره تلقائياً مع كل طلب، بدون أي تخمين أو نسب مُلفَّقة
  const country = (request.cf && request.cf.country) || 'XX';
  const now = new Date();
  const dayKey = now.toISOString().slice(0, 10); // YYYY-MM-DD — يسمح بحصر الأحداث يومياً بسرعة لاحقاً
  const id = crypto.randomUUID();

  const record = { type, platform, country, ts: now.toISOString() };

  try {
    await env.AZ_ANALYTICS_KV.put(`event:${dayKey}:${id}`, JSON.stringify(record), {
      expirationTtl: 60 * 60 * 24 * 400, // الاحتفاظ بالحدث نحو 13 شهراً — يمنع تراكماً غير محدود في KV
    });
  } catch (e) {
    // فشل التسجيل لا يُفشل الطلب — الأولوية لتجربة الزائر
  }

  return new Response(JSON.stringify({ ok: true, recorded: true }), { headers });
}
