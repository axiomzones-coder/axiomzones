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

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const lockCheck = await checkRateLimit(env, ip);
  if (lockCheck.locked) {
    return json({ ok: false, error: 'too_many_attempts' }, 429);
  }

  const code = String((body && body.code) || '');
  const expected = env.OWNER_CODE || '';

  if (!expected) {
    return json({ ok: false, error: 'server_not_configured' }, 500);
  }

  const match = await timingSafeEqual(code, expected);
  if (!match) {
    await registerFailure(env, ip);
    return json({ ok: false }, 401);
  }

  await clearRateLimit(env, ip);
  const token = await makeToken(env.OWNER_SECRET || expected);
  await writeLog(env, 'auth', 'owner', 'Owner logged in');
  const headers = new Headers({ 'content-type': 'application/json' });
  headers.append(
    'Set-Cookie',
    `az_owner_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=7200`
  );
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

// ── تحديد معدل المحاولات من جهة السيرفر — مقاومة تخطي المتصفح تماماً، بعكس القفل السابق في sessionStorage ──
// ملاحظة: يعيد استخدام AZ_CONFIG_KV بمفتاح مسبوق بـ "ratelimit:" لتجنب طلب KV مخصص إضافي من المالك
const RL_MAX_ATTEMPTS = 5;
const RL_LOCK_SECONDS = 15 * 60; // 15 دقيقة — أطول من قفل المتصفح القديم لأنه الحارس الحقيقي الأخير

async function checkRateLimit(env, ip) {
  if (!env.AZ_CONFIG_KV) return { locked: false }; // لو الـ KV غير متاح، لا نمنع الدخول المشروع بسبب ذلك
  const raw = await env.AZ_CONFIG_KV.get(`ratelimit:owner:${ip}`);
  if (!raw) return { locked: false };
  const data = JSON.parse(raw);
  return { locked: (data.count || 0) >= RL_MAX_ATTEMPTS };
}

async function registerFailure(env, ip) {
  if (!env.AZ_CONFIG_KV) return;
  const key = `ratelimit:owner:${ip}`;
  const raw = await env.AZ_CONFIG_KV.get(key);
  const data = raw ? JSON.parse(raw) : { count: 0 };
  data.count = (data.count || 0) + 1;
  await env.AZ_CONFIG_KV.put(key, JSON.stringify(data), { expirationTtl: RL_LOCK_SECONDS });
}

async function clearRateLimit(env, ip) {
  if (!env.AZ_CONFIG_KV) return;
  try { await env.AZ_CONFIG_KV.delete(`ratelimit:owner:${ip}`); } catch (e) {}
}

// ── تسجيل حدث في سجل الأحداث الحقيقي (System Logs) — فشل الكتابة لا يوقف العملية الأساسية أبداً ──
async function writeLog(env, type, actor, detail) {
  if (!env.AZ_CONFIG_KV) return;
  try {
    const id = crypto.randomUUID();
    const at = new Date().toISOString();
    await env.AZ_CONFIG_KV.put(`syslog:${at}:${id}`, JSON.stringify({ type, actor, detail, at }), {
      expirationTtl: 60 * 60 * 24 * 90, // 90 يوماً
    });
  } catch (e) {}
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
