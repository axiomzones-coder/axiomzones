// functions/api/owner-platforms.js
// GET  /api/owner-platforms — يعرض كل المنصات المخصَّصة المضافة عبر الداشبورد (المالك فقط)
// POST /api/owner-platforms — Body: { action: 'create'|'update'|'delete', key, ...platformData }
//
// ⚠️ مقيّد بالمالك فقط عمداً — بخلاف toggleP (تفعيل/تعطيل منصة موجودة) المسموح للمدير بصلاحية platforms.
// إضافة/حذف منصة جديدة تماماً يغيّر بنية الموقع نفسه (SEO، البحث، التصنيفات)، فهو قرار أعلى مستوى من التفعيل/التعطيل.
//
// يُخزَّن كل شيء داخل نفس az_master_config (نفس مفتاح config-get.js العام) تحت config.customPlatforms
// حتى يقدر كل زائر يشوف المنصات الجديدة فوراً من غير أي تسجيل دخول (نفس آلية عرض platforms.active الحالية)

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

// أسماء التصنيفات المسموحة — يجب أن تطابق AZ_CATEGORIES في الموقع الرئيسي بالضبط (تُحدَّث ديناميكياً لاحقاً لتشمل التصنيفات المخصَّصة)
const BUILTIN_CATEGORIES = ['financial', 'islamic', 'educational', 'business'];
// حقول اختيارية بيضاء القائمة فقط — أي حقل غير هذه القائمة يُتجاهل بصمت لمنع حقن بيانات غير متوقعة
const ALLOWED_FIELDS = ['icon', 'color', 'colorLight', 'name_ar', 'name_en', 'tagline_ar', 'tagline_en', 'desc_short', 'desc_full', 'path', 'category', 'status', 'featured', 'logoData'];
const MAX_LOGO_SIZE = 350000; // ~350KB بعد الترميز base64 — حماية لحجم KV

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!(await verifyOwnerSession(request, env))) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }
  if (!env.AZ_CONFIG_KV) {
    return new Response(JSON.stringify({ ok: true, platforms: {}, categories: {} }), { headers });
  }

  try {
    const raw = await env.AZ_CONFIG_KV.get('az_master_config');
    const config = raw ? JSON.parse(raw) : {};
    return new Response(JSON.stringify({ ok: true, platforms: config.customPlatforms || {}, categories: config.customCategories || {} }), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: 'kv_error' }), { status: 500, headers });
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!(await verifyOwnerSession(request, env))) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401, headers });
  }
  if (!env.AZ_CONFIG_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  const action = String((body && body.action) || '');
  const raw = await env.AZ_CONFIG_KV.get('az_master_config');
  const config = raw ? JSON.parse(raw) : {};
  if (!config.customPlatforms) config.customPlatforms = {};
  if (!config.customCategories) config.customCategories = {};

  // ── إدارة التصنيفات (منفصلة عن إدارة المنصات، لكن بنفس نقطة الدخول لتوفير الاعتماد على جلسة المالك) ──
  if (action === 'create_category') {
    const catId = String((body && body.catId) || '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
    if (!catId || catId.length < 2) {
      return new Response(JSON.stringify({ ok: false, error: 'invalid_key' }), { status: 400, headers });
    }
    if (BUILTIN_CATEGORIES.includes(catId) || config.customCategories[catId]) {
      return new Response(JSON.stringify({ ok: false, error: 'key_exists' }), { status: 409, headers });
    }
    const title_ar = String((body && body.title_ar) || '').trim();
    const title_en = String((body && body.title_en) || '').trim();
    if (!title_ar || !title_en) {
      return new Response(JSON.stringify({ ok: false, error: 'missing_required_fields' }), { status: 400, headers });
    }
    config.customCategories[catId] = {
      icon: String((body && body.icon) || '🔷'),
      color: String((body && body.color) || '#c9a84c'),
      title_ar, title_en,
    };
    await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
    await writeLog(env, 'category', 'owner', `Created new category: ${catId} (${title_en})`);
    return new Response(JSON.stringify({ ok: true, catId, category: config.customCategories[catId] }), { headers });
  }

  if (action === 'delete_category') {
    const catId = String((body && body.catId) || '');
    delete config.customCategories[catId];
    await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
    await writeLog(env, 'category', 'owner', `Deleted category: ${catId}`);
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  // ── إدارة المنصات (كما كانت، مع دعم قبول أي تصنيف مسجَّل فعلياً — ثابت أو مخصَّص) ──
  const key = String((body && body.key) || '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (!key || key.length < 2) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_key' }), { status: 400, headers });
  }
  const allCategoryIds = BUILTIN_CATEGORIES.concat(Object.keys(config.customCategories));

  if (action === 'create') {
    if (config.customPlatforms[key]) {
      return new Response(JSON.stringify({ ok: false, error: 'key_exists' }), { status: 409, headers });
    }
    const platform = sanitizePlatform(body, allCategoryIds);
    if (!platform.name_ar || !platform.name_en || !platform.path) {
      return new Response(JSON.stringify({ ok: false, error: 'missing_required_fields' }), { status: 400, headers });
    }
    config.customPlatforms[key] = platform;
    await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
    await writeLog(env, 'platform', 'owner', `Created new platform: ${key} (${platform.name_en})`);
    return new Response(JSON.stringify({ ok: true, key, platform }), { headers });
  }

  if (action === 'update') {
    if (!config.customPlatforms[key]) {
      return new Response(JSON.stringify({ ok: false, error: 'not_found' }), { status: 404, headers });
    }
    const updated = Object.assign({}, config.customPlatforms[key], sanitizePlatform(body, allCategoryIds));
    config.customPlatforms[key] = updated;
    await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
    await writeLog(env, 'platform', 'owner', `Updated platform: ${key}`);
    return new Response(JSON.stringify({ ok: true, key, platform: updated }), { headers });
  }

  if (action === 'delete') {
    delete config.customPlatforms[key];
    await env.AZ_CONFIG_KV.put('az_master_config', JSON.stringify(config));
    await writeLog(env, 'platform', 'owner', `Deleted platform: ${key}`);
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  return new Response(JSON.stringify({ ok: false, error: 'invalid_action' }), { status: 400, headers });
}

function sanitizePlatform(body, allCategoryIds) {
  const out = {};
  ALLOWED_FIELDS.forEach(function (f) {
    if (body[f] !== undefined) out[f] = body[f];
  });
  if (out.category && allCategoryIds && !allCategoryIds.includes(out.category)) delete out.category;
  if (out.logoData) {
    if (typeof out.logoData !== 'string' || !out.logoData.startsWith('data:image/') || out.logoData.length > MAX_LOGO_SIZE) {
      delete out.logoData; // لوجو غير صالح أو كبير جداً — يُتجاهل بصمت، تفضل الأيقونة (إيموجي) كبديل
    }
  }
  if (out.status && out.status !== 'live' && out.status !== 'coming') out.status = 'coming';
  if (!out.colorLight && out.color) out.colorLight = out.color;
  out.featured = !!out.featured;
  return out;
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
