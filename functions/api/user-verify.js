// functions/api/user-verify.js
// GET /api/user-verify — يتحقق من كوكي جلسة المستخدم ويرجع بياناته

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_user_session=([^;]+)/);
  if (!match) return new Response(JSON.stringify({ valid: false }), { headers });

  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 4) return new Response(JSON.stringify({ valid: false }), { headers });

  const [tag, emailB64, expStr, sig] = parts;
  if (tag !== 'user') return new Response(JSON.stringify({ valid: false }), { headers });

  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) return new Response(JSON.stringify({ valid: false, reason: 'expired' }), { headers });

  const secret = env.OWNER_SECRET || 'fallback-secret-change-me';
  const payload = `${tag}.${emailB64}.${expStr}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const expectedSig = base64url(new Uint8Array(sigBuf));

  if (expectedSig !== sig) return new Response(JSON.stringify({ valid: false }), { headers });

  const email = atob(emailB64);

  if (env.AZ_USERS_KV) {
    const raw = await env.AZ_USERS_KV.get('user:' + email);
    if (raw) {
      const record = JSON.parse(raw);
      return new Response(JSON.stringify({
        valid: true,
        user: { email: record.email, name: record.name, plan: record.plan }
      }), { headers });
    }
  }

  return new Response(JSON.stringify({ valid: false }), { headers });
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
