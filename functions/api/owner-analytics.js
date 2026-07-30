// functions/api/owner-analytics.js
// GET /api/owner-analytics — يجمّع أحداث آخر 30 يوماً من AZ_ANALYTICS_KV (زيارات، ضربات منصات، تسجيلات)
// محمي بجلسة المالك (نفس آلية owner-verify.js)
//
// ملاحظة أداء للمستقبل: التنفيذ الحالي يعمل list()+get() لكل حدث — مقبول تماماً في المرحلة الحالية
// (قبل نمو الزيارات بشكل كبير). لو الزيارات كبرت لآلاف يومياً، يُنصح بالتحول لعدّادات مجمَّعة
// (aggregated counters) بدل تخزين كل حدث فردياً، أو الانتقال لـ D1.

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  // ── تحقق من جلسة المالك ──
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_owner_session=([^;]+)/);
  if (!match) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }
  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 3) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }
  const [tag, expStr, sig] = parts;
  if (tag !== 'owner') {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }
  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) {
    return new Response(JSON.stringify({ ok: false, error: 'session_expired' }), { status: 401, headers });
  }
  const secret = env.OWNER_SECRET || env.OWNER_CODE || '';
  const payload = `${tag}.${expStr}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const expectedSig = base64url(new Uint8Array(sigBuf));
  if (expectedSig !== sig) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }

  if (!env.AZ_ANALYTICS_KV) {
    return new Response(JSON.stringify({ ok: true, analytics: emptyAnalytics() }), { headers });
  }

  try {
    const RANGE_DAYS = 30;
    const byCountry = {};
    const byPlatformClicks = {};
    let totalPageviews = 0;
    let totalSignups = 0;
    let totalLogins = 0;

    const today = new Date();
    for (let i = 0; i < RANGE_DAYS; i++) {
      const d = new Date(today);
      d.setUTCDate(d.getUTCDate() - i);
      const dayKey = d.toISOString().slice(0, 10);

      let cursor;
      do {
        const page = await env.AZ_ANALYTICS_KV.list({ prefix: `event:${dayKey}:`, cursor, limit: 1000 });
        for (const k of page.keys) {
          const raw = await env.AZ_ANALYTICS_KV.get(k.name);
          if (!raw) continue;
          let rec;
          try { rec = JSON.parse(raw); } catch (e) { continue; }
          if (rec.type === 'pageview') {
            totalPageviews++;
            byCountry[rec.country] = (byCountry[rec.country] || 0) + 1;
          } else if (rec.type === 'platform_click' && rec.platform) {
            byPlatformClicks[rec.platform] = (byPlatformClicks[rec.platform] || 0) + 1;
          } else if (rec.type === 'signup') {
            totalSignups++;
          } else if (rec.type === 'login') {
            totalLogins++;
          }
        }
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
    }

    return new Response(JSON.stringify({
      ok: true,
      analytics: {
        rangeDays: RANGE_DAYS,
        totalPageviews,
        totalSignups,
        totalLogins,
        byCountry,
        byPlatformClicks,
        generatedAt: new Date().toISOString(),
      },
    }), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: 'kv_error' }), { status: 500, headers });
  }
}

function emptyAnalytics() {
  return {
    rangeDays: 30,
    totalPageviews: 0,
    totalSignups: 0,
    totalLogins: 0,
    byCountry: {},
    byPlatformClicks: {},
    generatedAt: new Date().toISOString(),
  };
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
