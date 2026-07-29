// functions/api/owner-login.js
// Cloudflare Pages Function — يعمل تلقائياً بدون أي إعداد إضافي بمجرد رفعه للمسار الصحيح
//
// يتطلب متغيرين بيئيين (Environment Variables) مضبوطين من لوحة Cloudflare Pages:
//   OWNER_CODE   → كود دخول المالك (Encrypted)
//   OWNER_SECRET → نص عشوائي طويل منفصل، يُستخدم فقط لتوقيع الجلسة (Encrypted)
//
// لا تتردد أبداً في وضع القيم هنا في الكود — هذا الملف يُرفع لمستودع GitHub
// وقد يكون علنياً، لذا يجب أن تبقى القيم الحساسة في لوحة Cloudflare فقط.

export async function onRequestPost(context) {
  const { request, env } = context;

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ ok: false, error: 'bad_request' }, 400);
  }

  const code = String((body && body.code) || '');
  const expected = env.OWNER_CODE || '';

  if (!expected) {
    return json({ ok: false, error: 'server_not_configured' }, 500);
  }

  const match = await timingSafeEqual(code, expected);
  if (!match) {
    return json({ ok: false }, 401);
  }

  const token = await makeToken(env.OWNER_SECRET || expected);
  const headers = new Headers({ 'content-type': 'application/json' });
  headers.append(
    'Set-Cookie',
    `az_owner_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=7200`
  );
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

// مقارنة بزمن ثابت (تمنع هجمات قياس الزمن) عبر مقارنة هاش القيمتين
async function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const [aBuf, bBuf] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ]);
  const aArr = new Uint8Array(aBuf);
  const bArr = new Uint8Array(bBuf);
  if (aArr.length !== bArr.length) return false;
  let diff = 0;
  for (let i = 0; i < aArr.length; i++) diff |= aArr[i] ^ bArr[i];
  return diff === 0;
}

// جلسة موقّعة (HMAC-SHA256) صالحة لمدة ساعتين — لا تحتاج قاعدة بيانات
async function makeToken(secret) {
  const exp = Date.now() + 2 * 60 * 60 * 1000;
  const payload = `owner.${exp}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const sig = base64url(new Uint8Array(sigBuf));
  return `${payload}.${sig}`;
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'content-type': 'application/json' },
  });
}
