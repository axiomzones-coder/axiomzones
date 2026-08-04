// functions/api/wb-rate.js
// GET /api/wb-rate?country=MA — يجلب معدل الإقراض العام الحقيقي من البنك الدولي (World Bank Open Data API)
// مصدر مجاني ومفتوح، لكن: (1) هذا معدل إقراض تجاري عام، ليس قرضاً شخصياً بالتحديد،
// (2) بعض دول الخليج لا ترفع هذا المؤشر بانتظام للبنك الدولي، فقد يرجع "غير متوفر"
//
// يُخزَّن الرد في AZ_CONFIG_KV لمدة 24 ساعة لتقليل الطلبات على خدمة البنك الدولي

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json', 'Cache-Control': 'public, max-age=3600' });
  const url = new URL(request.url);
  const country = (url.searchParams.get('country') || '').toUpperCase().slice(0, 3);

  if (!country) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_country' }), { status: 400, headers });
  }

  const cacheKey = `wbrate:${country}`;
  try {
    if (env.AZ_CONFIG_KV) {
      const cached = await env.AZ_CONFIG_KV.get(cacheKey);
      if (cached) return new Response(cached, { headers });
    }
  } catch (e) {}

  try {
    const wbUrl = `https://api.worldbank.org/v2/country/${country}/indicator/FR.INR.LEND?format=json&per_page=5&mrnev=1`;
    const res = await fetch(wbUrl);
    if (!res.ok) throw new Error('worldbank_unreachable');
    const json = await res.json();
    const series = json[1];
    const latest = series && series.find((d) => d.value !== null);

    const result = latest
      ? { ok: true, available: true, rate: latest.value, year: latest.date, source: 'World Bank — General Lending Rate' }
      : { ok: true, available: false, reason: 'not_reported_by_country' };

    const body = JSON.stringify(result);
    if (env.AZ_CONFIG_KV) {
      try { await env.AZ_CONFIG_KV.put(cacheKey, body, { expirationTtl: 60 * 60 * 24 }); } catch (e) {}
    }
    return new Response(body, { headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: 'fetch_failed' }), { status: 502, headers });
  }
}
