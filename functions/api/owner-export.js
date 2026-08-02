// functions/api/owner-export.js
// GET /api/owner-export — يصدّر نسخة احتياطية كاملة (JSON) من كل بيانات المنصة الحرجة
// محمي بالمالك فقط
//
// ⚠️ قرار أمني مقصود: لا يتم تصدير passwordHash/salt لأي مستخدم أو مدير أبداً —
// حتى لو الملف اتسرّب أو اتخزّن في مكان غير آمن، مفيش أي كلمة مرور (حتى مشفَّرة) تتعرّض للخطر.
// لو احتجت استرجاع حساب، تقدر تعمل "password reset" حقيقي بدل استرجاع الهاش القديم.

async function verifyOwnerSession(request, env) {
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

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({
    'content-type': 'application/json',
    'content-disposition': `attachment; filename="axiomzones-backup-${new Date().toISOString().slice(0, 10)}.json"`,
  });

  if (!(await verifyOwnerSession(request, env))) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers: { 'content-type': 'application/json' } });
  }

  const backup = { exportedAt: new Date().toISOString(), users: [], admins: [], config: {} };

  try {
    // ── المستخدمون (بدون كلمات المرور المشفَّرة) ──
    if (env.AZ_USERS_KV) {
      let cursor;
      do {
        const page = await env.AZ_USERS_KV.list({ prefix: 'user:', cursor, limit: 1000 });
        for (const k of page.keys) {
          const raw = await env.AZ_USERS_KV.get(k.name);
          if (!raw) continue;
          try {
            const rec = JSON.parse(raw);
            backup.users.push({ email: rec.email, name: rec.name, plan: rec.plan, createdAt: rec.createdAt });
          } catch (e) {}
        }
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
    }

    // ── المديرون (بدون كلمات المرور المشفَّرة) ──
    if (env.AZ_ADMINS_KV) {
      let cursor;
      do {
        const page = await env.AZ_ADMINS_KV.list({ prefix: 'admin:', cursor, limit: 1000 });
        for (const k of page.keys) {
          const raw = await env.AZ_ADMINS_KV.get(k.name);
          if (!raw) continue;
          try {
            const rec = JSON.parse(raw);
            backup.admins.push({ email: rec.email, name: rec.name, permissions: rec.permissions, disabled: rec.disabled, createdAt: rec.createdAt });
          } catch (e) {}
        }
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
    }

    // ── إعدادات المنصة (المنصات، الصيانة، الأسعار، المنصات المخصصة) ──
    if (env.AZ_CONFIG_KV) {
      const raw = await env.AZ_CONFIG_KV.get('az_master_config');
      backup.config = raw ? JSON.parse(raw) : {};
    }

    return new Response(JSON.stringify(backup, null, 2), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: 'export_failed' }), { status: 500, headers: { 'content-type': 'application/json' } });
  }
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
