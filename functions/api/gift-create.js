// functions/api/gift-create.js
// POST /api/gift-create — للمالك فقط
// Body: { platform, durationDays (رقم أو null للدائم), purpose, count (عدد الأشخاص) }
// يُنشئ "count" رابط إهداء مستقل، كل واحد بمعرِّف فريد خاص به.

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_CONFIG_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  // ── المالك/المدير فقط ──
  const role = await checkOwnerOrAdminSession(request, env);
  if (!role) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  const platform = String((body && body.platform) || '').trim().toLowerCase();
  const durationDays = (body && body.durationDays !== undefined) ? body.durationDays : null; // null = دائم
  const purpose = String((body && body.purpose) || '').slice(0, 300);
  const count = Math.min(Math.max(parseInt((body && body.count) || 1, 10), 1), 100); // بين 1 و100 رابط دفعة واحدة

  if (!platform) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_platform' }), { status: 400, headers });
  }

  try {
    const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
    const config = configRaw ? JSON.parse(configRaw) : {};
    config.gifts = config.gifts || [];

    const newGifts = [];
    for (let i = 0; i < count; i++) {
      const gift = {
        id: 'gift_' + crypto.randomUUID(),
        platform, durationDays, purpose,
        createdAt: new Date().toISOString(),
        claimed: false,
        claimedBy: null,
        claimedAt: null,
      };
      config.gifts.unshift(gift);
      newGifts.push(gift);
    }

    await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));

    return new Response(JSON.stringify({
      ok: true,
      gifts: newGifts.map(g => ({ id: g.id, url: `https://axiomzones.com/claim-gift?id=${g.id}` })),
    }), { headers });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'save_failed' }), { status: 500, headers });
  }
}

async function checkOwnerOrAdminSession(request, env) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const secret = env.OWNER_SECRET || env.OWNER_CODE || '';

  const ownerMatch = cookieHeader.match(/az_owner_session=([^;]+)/);
  if (ownerMatch) {
    try {
      const token = decodeURIComponent(ownerMatch[1]);
      const parts = token.split('.');
      if (parts.length === 3) {
        const [tag, expStr, sig] = parts;
        const exp = parseInt(expStr, 10);
        if (tag === 'owner' && exp && Date.now() <= exp) {
          const payload = `${tag}.${expStr}`;
          const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
          const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
          if (base64url(new Uint8Array(sigBuf)) === sig) return 'owner';
        }
      }
    } catch (e) {}
  }

  const adminMatch = cookieHeader.match(/az_admin_session=([^;]+)/);
  if (adminMatch && env.AZ_ADMINS_KV) {
    try {
      const token = decodeURIComponent(adminMatch[1]);
      const parts = token.split('.');
      if (parts.length === 4) {
        const [tag, emailB64, expStr, sig] = parts;
        const exp = parseInt(expStr, 10);
        if (tag === 'admin' && exp && Date.now() <= exp) {
          const adminSecret = env.OWNER_SECRET || 'fallback-secret-change-me';
          const payload = `${tag}.${emailB64}.${expStr}`;
          const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(adminSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
          const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
          if (base64url(new Uint8Array(sigBuf)) === sig) {
            const email = atob(emailB64);
            const raw = await env.AZ_ADMINS_KV.get('admin:' + email);
            if (raw) { const rec = JSON.parse(raw); if (!rec.disabled) return 'admin'; }
          }
        }
      }
    } catch (e) {}
  }
  return null;
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
