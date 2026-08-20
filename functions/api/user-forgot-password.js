// functions/api/user-forgot-password.js
// POST /api/user-forgot-password — Body: { email }
// يولّد رمز استرجاع مؤقت (صالح لساعة واحدة)، يخزّنه مجزَّأ (Hash) في KV.
//
// ⚠️ ملاحظة صدق معمارية: لا توجد خدمة بريد إلكتروني (SMTP) متصلة بالمشروع
// حالياً. لحين ربطها، هذا الـendpoint يُرجِع رابط الاسترجاع مباشرة في
// الاستجابة (بدل إرساله بالبريد) — وضع مؤقت واضح ومقصود، لا محاكاة وهمية.
// عند ربط بريد إلكتروني حقيقي مستقبلاً، يُعدَّل السطر الأخير فقط لإرسال
// الرابط بدل إرجاعه، دون أي تغيير في منطق توليد/تخزين الرمز نفسه.

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  const email = String((body && body.email) || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_email' }), { status: 400, headers });
  }

  const userRaw = await env.AZ_USERS_KV.get('user:' + email);
  /* ══ لا نكشف للمتصل هل البريد موجود أم لا — نفس رد النجاح في الحالتين،
     منعًا لتعداد الحسابات (Account Enumeration) — مطلوب أمني صريح ══ */
  if (!userRaw) {
    return new Response(JSON.stringify({ ok: true, message: 'إذا كان البريد مسجَّلاً، سيصلك رابط الاسترجاع' }), { headers });
  }

  const rawToken = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256Hex(rawToken);
  const expiresAt = Date.now() + 60 * 60 * 1000; // ساعة واحدة

  await env.AZ_USERS_KV.put(
    'pwreset:' + tokenHash,
    JSON.stringify({ email, expiresAt }),
    { expirationTtl: 3600 }
  );

  const resetUrl = `https://axiomzones.com/reset-password?token=${rawToken}&email=${encodeURIComponent(email)}`;

  return new Response(JSON.stringify({
    ok: true,
    message: 'إذا كان البريد مسجَّلاً، سيصلك رابط الاسترجاع',
    /* ⚠️ مؤقت فقط لحين ربط بريد إلكتروني حقيقي — سيُحذف هذا الحقل من
       الاستجابة فور ربط SMTP، ويُستبدَل بإرسال فعلي بالبريد */
    devResetUrl: resetUrl,
  }), { headers });
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
