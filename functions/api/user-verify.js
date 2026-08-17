// functions/api/user-verify.js
// GET /api/user-verify — يتحقق من صلاحية جلسة az_user_session الحالية

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_user_session=([^;]+)/);
  if (!match) {
    return new Response(JSON.stringify({ valid: false }), { headers });
  }

  try {
    const token = decodeURIComponent(match[1]);
    const parts = token.split('.');
    if (parts.length !== 4) {
      return new Response(JSON.stringify({ valid: false }), { headers });
    }
    const [tag, emailB64, expStr, sig] = parts;
    const exp = parseInt(expStr, 10);
    if (tag !== 'user' || !exp || Date.now() > exp) {
      return new Response(JSON.stringify({ valid: false }), { headers });
    }

    const secret = env.OWNER_SECRET || 'fallback-secret-change-me';
    const payload = `${tag}.${emailB64}.${expStr}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
    const expectedSig = base64url(new Uint8Array(sigBuf));
    if (expectedSig !== sig) {
      return new Response(JSON.stringify({ valid: false }), { headers });
    }

    const email = atob(emailB64);
    if (env.AZ_USERS_KV) {
      const raw = await env.AZ_USERS_KV.get('user:' + email);
      if (!raw) return new Response(JSON.stringify({ valid: false }), { headers });
      const userRecord = JSON.parse(raw);
      return new Response(JSON.stringify({ valid: true, user: { email, name: userRecord.name } }), { headers });
    }

    return new Response(JSON.stringify({ valid: true, user: { email } }), { headers });
  } catch (e) {
    return new Response(JSON.stringify({ valid: false }), { headers });
  }
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
