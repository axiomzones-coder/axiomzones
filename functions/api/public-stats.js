// functions/api/public-stats.js
// GET /api/public-stats — أرقام حقيقية غير حساسة للعرض العام في الموقع (بدون تسجيل دخول)
// لا يعرض أي بيانات مالية أو حساسة (MRR, الإيميلات...) — فقط أعداد إجمالية بسيطة
// منفصل عمداً عن owner-stats.js المحمي بالمالك، لأن هذا الـ endpoint يُستخدم في الصفحة الرئيسية العامة

export async function onRequestGet(context) {
  const { env } = context;
  const headers = new Headers({ 'content-type': 'application/json', 'Cache-Control': 'public, max-age=300' });

  let totalUsers = 0;
  let totalPlatforms = 0;
  let livePlatforms = 0;

  try {
    if (env.AZ_USERS_KV) {
      let cursor;
      do {
        const page = await env.AZ_USERS_KV.list({ prefix: 'user:', cursor, limit: 1000 });
        totalUsers += page.keys.length;
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
    }
  } catch (e) {}

  try {
    if (env.AZ_CONFIG_KV) {
      const raw = await env.AZ_CONFIG_KV.get('az_master_config');
      const config = raw ? JSON.parse(raw) : {};
      const custom = config.customPlatforms || {};
      totalPlatforms = 17 + Object.keys(custom).length; // 17 منصة أساسية مبنية بالكود + أي منصة مخصصة
      const overrides = config.platforms || {};
      // تقدير عدد المباشر: نفترض المنصات الأساسية live افتراضياً إلا لو عُطِّلت، ونحسب المخصصة حسب حالتها المحفوظة
      let liveCount = 17;
      Object.keys(overrides).forEach((k) => { if (overrides[k].active === false) liveCount--; });
      Object.keys(custom).forEach((k) => { if (custom[k].status === 'live') liveCount++; });
      livePlatforms = Math.max(0, liveCount);
    } else {
      totalPlatforms = 17;
      livePlatforms = 17;
    }
  } catch (e) {
    totalPlatforms = 17;
    livePlatforms = 17;
  }

  return new Response(JSON.stringify({ ok: true, totalUsers, totalPlatforms, livePlatforms }), { headers });
}
