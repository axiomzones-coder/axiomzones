// functions/api/owner-users-list.js
// GET /api/owner-users-list — قائمة حقيقية بأول 100 مستخدم من AZ_USERS_KV
// محمي بجلسة المالك، أو مدير يملك صلاحية "users"

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

async function verifyAdminUsersPermission(request, env) {
  if (!env.AZ_ADMINS_KV) return false;
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_admin_session=([^;]+)/);
  if (!match) return false;
  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 4) return false;
  const [tag, emailB64, expStr, sig] = parts;
  if (tag !== 'admin') return false;
  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) return false;
  const secret = env.OWNER_SECRET || 'fallback-secret-change-me';
  const payload = `${tag}.${emailB64}.${expStr}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  if (base64url(new Uint8Array(sigBuf)) !== sig) return false;
  let email;
  try { email = atob(emailB64); } catch (e) { return false; }
  const raw = await env.AZ_ADMINS_KV.get('admin:' + email);
  if (!raw) return false;
  const rec = JSON.parse(raw);
  return !rec.disabled && rec.permissions && !!rec.permissions.users;
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  const isOwner = await verifyOwnerSession(request, env);
  const isAdminWithPerm = isOwner ? false : await verifyAdminUsersPermission(request, env);
  if (!isOwner && !isAdminWithPerm) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }

  if (!env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: true, users: [] }), { headers });
  }

  try {
    const PRICES = { free: 0, pro: 237, ent: 773, charity: 77 };
    const users = [];
    let cursor;
    let count = 0;
    const LIMIT = 100; // حد أقصى معقول لعرض أولي — يمكن إضافة ترقيم صفحات لاحقاً عند الحاجة

    do {
      const page = await env.AZ_USERS_KV.list({ prefix: 'user:', cursor, limit: 1000 });
      for (const k of page.keys) {
        if (count >= LIMIT) break;
        const raw = await env.AZ_USERS_KV.get(k.name);
        if (!raw) continue;
        let rec;
        try { rec = JSON.parse(raw); } catch (e) { continue; }
        const plan = rec.plan || 'free';
        users.push({
          email: rec.email,
          name: rec.name || (rec.email || '').split('@')[0],
          plan,
          revenue: PRICES[plan] || 0,
          createdAt: rec.createdAt || null,
        });
        count++;
      }
      cursor = (count >= LIMIT || page.list_complete) ? undefined : page.cursor;
    } while (cursor);

    users.sort(function (a, b) {
      return new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
    });

    return new Response(JSON.stringify({ ok: true, users, total: users.length }), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: 'kv_error' }), { status: 500, headers });
  }
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
