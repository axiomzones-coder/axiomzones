// functions/api/config-get.js
// GET /api/config-get — قراءة عامة لحالة المنصات (مفعّلة/متوقفة) والأسعار
// لا يحتاج تسجيل دخول — الصفحة الرئيسية تستدعيه لكل زائر لعرض الحالة الصحيحة

export async function onRequestGet(context) {
  const { env } = context;

  const headers = new Headers({
    'content-type': 'application/json',
    'Cache-Control': 'no-store', // لا تخزين مؤقت أبداً — أي تعديل من المالك (تفعيل/تعطيل منصة، صيانة...) يجب أن يظهر فوراً لكل زائر جديد
  });

  try {
    if (!env.AZ_CONFIG_KV) {
      // لو لم يُضبط KV بعد — رجّع فارغاً بأمان، الصفحة الرئيسية تستخدم قيمها الافتراضية المكتوبة بالكود
      return new Response(JSON.stringify({ ok: true, config: null }), { headers });
    }
    const raw = await env.AZ_CONFIG_KV.get('az_master_config');
    const config = raw ? JSON.parse(raw) : null;
    return new Response(JSON.stringify({ ok: true, config }), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, config: null }), { status: 200, headers });
  }
}
