// functions/api/owner-stats.js
// GET /api/owner-stats — إحصاءات حقيقية (عدد المستخدمين، الباقات، MRR) من AZ_USERS_KV
// محمي بجلسة المالك (نفس آلية التحقق في owner-verify.js) — لا يُعرض لأي زائر عادي

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  const ownerOk = await checkOwnerSession(request, env);
  const adminOk = ownerOk ? false : (await checkAdminPermission(request, env, 'analytics')).ok;

  if (!ownerOk && !adminOk) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }

  // ── لو الـ KV لسه مش مربوط، رجّع أصفار بأمان بدل خطأ ──
  if (!env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: true, stats: emptyStats() }), { headers });
  }

  try {
    // أسعار الباقات — نفس القيم المستخدمة في الصفحة الرئيسية (BASE_USD)
    // ملاحظة: تُحدَّث هنا يدوياً حالياً إلى أن يُربط نظام دفع فعلي (Dodo Payments) يكتب الباقة الحقيقية وسعرها وقت الاشتراك
    const PRICES = { free: 0, pro: 237, ent: 773, charity: 77 };

    let cursor;
    let totalUsers = 0;
    const byPlan = { free: 0, pro: 0, ent: 0, charity: 0 };
    let mrr = 0;

    do {
      const page = await env.AZ_USERS_KV.list({ prefix: 'user:', cursor, limit: 1000 });
      for (const k of page.keys) {
        const raw = await env.AZ_USERS_KV.get(k.name);
        if (!raw) continue;
        totalUsers++;
        let plan = 'free';
        try {
          const rec = JSON.parse(raw);
          if (rec && rec.plan) plan = rec.plan;
        } catch (e) { /* سجل تالف — يُحتسب كـ free ولا يوقف العملية */ }
        if (!(plan in byPlan)) byPlan[plan] = 0;
        byPlan[plan]++;
        mrr += PRICES[plan] || 0;
      }
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);

    const activeSubs = totalUsers - (byPlan.free || 0);

    return new Response(JSON.stringify({
      ok: true,
      stats: {
        totalUsers,
        activeSubs,
        byPlan,
        mrr,
        generatedAt: new Date().toISOString(),
      },
    }), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: 'kv_error' }), { status: 500, headers });
  }
}

function emptyStats() {
  return {
    totalUsers: 0,
    activeSubs: 0,
    byPlan: { free: 0, pro: 0, ent: 0, charity: 0 },
    mrr: 0,
    generatedAt: new Date().toISOString(),
  };
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function checkOwnerSession(request, env) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_owner_session=([^;]+)/);
  if (!match) return false;
  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [tag, expStr, sig] = parts;
  if (tag !== 'owner') return false;
  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) return false;
  const secret = env.OWNER_SECRET || env.OWNER_CODE || '';
  const payload = `${tag}.${expStr}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return base64url(new Uint8Array(sigBuf)) === sig;
}

async function checkAdminPermission(request, env, permission) {
  if (!env.AZ_ADMINS_KV) return { ok: false };
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_admin_session=([^;]+)/);
  if (!match) return { ok: false };
  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 4) return { ok: false };
  const [tag, emailB64, expStr, sig] = parts;
  if (tag !== 'admin') return { ok: false };
  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) return { ok: false };
  const secret = env.OWNER_SECRET || 'fallback-secret-change-me';
  const payload = `${tag}.${emailB64}.${expStr}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  if (base64url(new Uint8Array(sigBuf)) !== sig) return { ok: false };
  let email;
  try { email = atob(emailB64); } catch (e) { return { ok: false }; }
  const raw = await env.AZ_ADMINS_KV.get('admin:' + email);
  if (!raw) return { ok: false };
  const rec = JSON.parse(raw);
  if (rec.disabled) return { ok: false };
  if (!rec.permissions || !rec.permissions[permission]) return { ok: false };
  return { ok: true, email };
}
