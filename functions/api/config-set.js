// functions/api/config-set.js
// POST /api/config-set — حفظ تكوين المنصات في KV — محمي بجلسة المالك فقط
// Body: { config: {...} }  (نفس بنية AZ_MASTER كما هي في admin.html)

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  var actor = 'owner';

  // ── المحاولة الأولى: جلسة المالك (كما كانت دائماً) ──
  var ownerOk = await checkOwnerSession(request, env);

  // ── المحاولة الثانية: جلسة مدير يملك صلاحية "platforms" — أُضيفت 30 يوليو 2026 مع نظام صلاحيات المديرين ──
  var adminOk = false;
  if (!ownerOk) {
    var adminCheck = await checkAdminPermission(request, env, 'platforms');
    adminOk = adminCheck.ok;
    if (adminOk) actor = adminCheck.email;
  }

  if (!ownerOk && !adminOk) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthenticated' }), { status: 401, headers });
  }

  // ── الجلسة صالحة (مالك أو مدير مصرَّح له) — نكتب الآن ──
  if (!env.AZ_CONFIG_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'kv_not_configured' }), { status: 500, headers });
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  if (!body || typeof body.config !== 'object') {
    return new Response(JSON.stringify({ ok: false, error: 'missing_config' }), { status: 400, headers });
  }

  await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(body.config));
  // سجل تدقيق بسيط لمعرفة آخر من عدَّل الإعدادات (مالك أو مدير مُحدَّد بالإيميل)
  try { await env.AZ_CONFIG_KV.put('az_master_config_last_editor', JSON.stringify({ actor: actor, at: new Date().toISOString() })); } catch (e) {}
  await writeLog(env, 'config', actor, 'Updated platform/pricing configuration');

  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
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
  return { ok: true, email: email };
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function writeLog(env, type, actor, detail) {
  if (!env.AZ_CONFIG_KV) return;
  try {
    const id = crypto.randomUUID();
    const at = new Date().toISOString();
    await env.AZ_CONFIG_KV.put(`syslog:${at}:${id}`, JSON.stringify({ type, actor, detail, at }), {
      expirationTtl: 60 * 60 * 24 * 90,
    });
  } catch (e) {}
}
