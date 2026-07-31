// functions/api/owner-system-logs.js
// GET /api/owner-system-logs — يعرض آخر 50 حدث حقيقي مسجَّل (دخول مالك، تعديل إعدادات، إدارة مديرين)
// محمي بجلسة المالك فقط

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
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!(await verifyOwnerSession(request, env))) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }
  if (!env.AZ_CONFIG_KV) {
    return new Response(JSON.stringify({ ok: true, logs: [] }), { headers });
  }

  try {
    const logs = [];
    let cursor;
    do {
      const page = await env.AZ_CONFIG_KV.list({ prefix: 'syslog:', cursor, limit: 1000 });
      for (const k of page.keys) {
        const raw = await env.AZ_CONFIG_KV.get(k.name);
        if (!raw) continue;
        try { logs.push(JSON.parse(raw)); } catch (e) {}
      }
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);

    logs.sort((a, b) => new Date(b.at) - new Date(a.at));
    const last24hCount = logs.filter(l => Date.now() - new Date(l.at).getTime() < 86400000).length;

    return new Response(JSON.stringify({
      ok: true,
      logs: logs.slice(0, 50),
      totalEvents24h: last24hCount,
    }), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: 'kv_error' }), { status: 500, headers });
  }
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
