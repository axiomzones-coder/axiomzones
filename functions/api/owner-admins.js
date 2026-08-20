// functions/api/owner-admins.js
// GET  /api/owner-admins — يعرض كل حسابات المديرين (بدون كلمات المرور المشفَّرة)
// POST /api/owner-admins — Body: { action: 'create'|'update'|'delete', email, password?, name?, permissions? }
// كل العمليات هنا محمية بجلسة المالك فقط (az_owner_session) — المدير نفسه لا يقدر ينادي هذا الملف أبداً

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

// ── قائمة الصلاحيات المسموح للمالك تفعيلها — أي مفتاح غير هذه القائمة يُتجاهل بصمت لمنع حقن حقول غير معروفة ──
const ALLOWED_PERMISSIONS = ['platforms', 'analytics', 'users'];

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!(await verifyOwnerSession(request, env))) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }
  if (!env.AZ_ADMINS_KV) {
    return new Response(JSON.stringify({ ok: true, admins: [] }), { headers });
  }

  const admins = [];
  let cursor;
  do {
    const page = await env.AZ_ADMINS_KV.list({ prefix: 'admin:', cursor, limit: 1000 });
    for (const k of page.keys) {
      const raw = await env.AZ_ADMINS_KV.get(k.name);
      if (!raw) continue;
      const rec = JSON.parse(raw);
      admins.push({
        email: rec.email,
        name: rec.name,
        permissions: rec.permissions || {},
        disabled: !!rec.disabled,
        createdAt: rec.createdAt,
      });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return new Response(JSON.stringify({ ok: true, admins }), { headers });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!(await verifyOwnerSession(request, env))) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }
  if (!env.AZ_ADMINS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  const action = String((body && body.action) || '');
  const email = String((body && body.email) || '').trim().toLowerCase();

  if (!email || !email.includes('@')) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_email' }), { status: 400, headers });
  }

  const key = 'admin:' + email;

  if (action === 'create') {
    const existing = await env.AZ_ADMINS_KV.get(key);
    if (existing) {
      return new Response(JSON.stringify({ ok: false, error: 'email_exists' }), { status: 409, headers });
    }
    const password = String((body && body.password) || '');
    if (password.length < 8) {
      return new Response(JSON.stringify({ ok: false, error: 'password_too_short' }), { status: 400, headers });
    }
    const name = String((body && body.name) || email.split('@')[0]);
    const permissions = sanitizePermissions(body && body.permissions);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await hashPassword(password, salt);

    const record = {
      email, name,
      passwordHash: base64url(hash),
      salt: base64url(salt),
      permissions,
      disabled: false,
      createdAt: new Date().toISOString(),
      createdBy: 'owner',
    };
    await env.AZ_ADMINS_KV.put(key, JSON.stringify(record));
    await writeLog(env, 'admin', 'owner', `Created admin: ${email}`);
    return new Response(JSON.stringify({ ok: true, admin: { email, name, permissions } }), { headers });
  }

  if (action === 'update') {
    const raw = await env.AZ_ADMINS_KV.get(key);
    if (!raw) return new Response(JSON.stringify({ ok: false, error: 'not_found' }), { status: 404, headers });
    const rec = JSON.parse(raw);

    if (body.permissions !== undefined) rec.permissions = sanitizePermissions(body.permissions);
    if (body.name !== undefined) rec.name = String(body.name);
    if (body.disabled !== undefined) rec.disabled = !!body.disabled;
    if (body.password) {
      if (String(body.password).length < 8) {
        return new Response(JSON.stringify({ ok: false, error: 'password_too_short' }), { status: 400, headers });
      }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const hash = await hashPassword(String(body.password), salt);
      rec.passwordHash = base64url(hash);
      rec.salt = base64url(salt);
    }

    await env.AZ_ADMINS_KV.put(key, JSON.stringify(rec));
    await writeLog(env, 'admin', 'owner', `Updated admin: ${email}`);
    return new Response(JSON.stringify({ ok: true, admin: { email: rec.email, name: rec.name, permissions: rec.permissions, disabled: !!rec.disabled } }), { headers });
  }

  if (action === 'delete') {
    /* ══ لا حذف نهائي — تعطيل وأرشفة بدلاً منه (بند صريح من الدستور:
       "لا تُحذَف سجلاته التاريخية، عطّل الحساب أو أرشفه، احتفظ بسجلات
       Audit Logs"). تعطيل الحساب (disabled:true) يمنع تسجيل الدخول
       فوراً — نفس الأثر العملي المطلوب، لكن مع حفظ السجل كاملاً ══ */
    const raw = await env.AZ_ADMINS_KV.get(key);
    if (!raw) return new Response(JSON.stringify({ ok: false, error: 'not_found' }), { status: 404, headers });
    const rec = JSON.parse(raw);
    rec.disabled = true;
    rec.archivedAt = new Date().toISOString();
    await env.AZ_ADMINS_KV.put(key, JSON.stringify(rec));
    await writeLog(env, 'admin', 'owner', `Archived (disabled) admin: ${email}`);
    return new Response(JSON.stringify({ ok: true, archived: true }), { headers });
  }

  return new Response(JSON.stringify({ ok: false, error: 'invalid_action' }), { status: 400, headers });
}

function sanitizePermissions(input) {
  const out = {};
  if (input && typeof input === 'object') {
    ALLOWED_PERMISSIONS.forEach(function (p) { out[p] = !!input[p]; });
  } else {
    ALLOWED_PERMISSIONS.forEach(function (p) { out[p] = false; });
  }
  return out;
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  return new Uint8Array(bits);
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
