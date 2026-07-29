// functions/api/config-set.js
// POST /api/config-set — حفظ تكوين المنصات في KV — محمي بجلسة المالك فقط
// Body: { config: {...} }  (نفس بنية AZ_MASTER كما هي في admin.html)

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  // ── نفس منطق التحقق من الجلسة الموجود في owner-verify.js — لا كتابة بدون جلسة صالحة ──
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_owner_session=([^;]+)/);
  if (!match) return new Response(JSON.stringify({ ok: false, error: 'unauthenticated' }), { status: 401, headers });

  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 3) return new Response(JSON.stringify({ ok: false, error: 'invalid_token' }), { status: 401, headers });

  const [tag, expStr, sig] = parts;
  if (tag !== 'owner') return new Response(JSON.stringify({ ok: false, error: 'invalid_token' }), { status: 401, headers });

  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) return new Response(JSON.stringify({ ok: false, error: 'expired' }), { status: 401, headers });

  const secret = env.OWNER_SECRET || env.OWNER_CODE || '';
  const payload = `${tag}.${expStr}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const expectedSig = base64url(new Uint8Array(sigBuf));
  if (expectedSig !== sig) return new Response(JSON.stringify({ ok: false, error: 'invalid_signature' }), { status: 401, headers });

  // ── الجلسة صالحة — نكتب الآن ──
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

  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
