// functions/api/platform-access.js
// GET /api/platform-access?platform=kashf
// endpoint موحّد واحد يُستدعى من أي ملف منصة فرعية — يرجّع حالة واحدة من 4:
//   full     → مشترك في هذه المنصة تحديداً، أو حامل باقة كاملة (كل المنصات)
//   trial    → داخل فترة التجربة المجانية (يُرجع أيضاً daysLeft)
//   expired  → انتهت فترة التجربة، ولم يشترك
//   login_required → لم يسجّل دخول (لا يمكن بدء تجربة أو التحقق من اشتراك بدون حساب)
//
// مدة التجربة الافتراضية: 7 أيام لكل منصة (مستقلة عن باقي المنصات)
// التجربة تُربط بالحساب الحقيقي (البريد الإلكتروني في AZ_USERS_KV) لا بكوكيز/localStorage
// يمنع الالتفاف عليها بمسح بيانات المتصفح.

const TRIAL_DAYS = 7;

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  const url = new URL(request.url);
  const platform = String(url.searchParams.get('platform') || '').trim().toLowerCase();
  if (!platform) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_platform' }), { status: 400, headers });
  }

  if (!env.AZ_USERS_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  // ── فحص أول: هل المنصة الفرعية معطّلة يدوياً من الداشبورد؟ يحجب الجميع بلا استثناء ──
  var visibilityStatus = 'visible';
  var seoNoindex = false; /* ══ قرار مستقل تماماً عن الرؤية — لا يُشتق تلقائياً منها (بطلب صريح من المالك) ══ */
  if (env.AZ_CONFIG_KV) {
    const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
    if (configRaw) {
      const config = JSON.parse(configRaw);
      const platCfg = (config.platforms && config.platforms[platform]) || {};
      if (platCfg.subPlatformDisabled === true) {
        return new Response(JSON.stringify({ ok: true, status: 'disabled', visibility: 'hidden', noindex: true }), { headers });
      }
      /* ══ حالة "الصيانة" — تحجب الجميع مؤقتاً بما فيهم المشتركون الحاليون
         (خلافاً للأرشفة)، مع رسالة مؤقتة واضحة، ومنفصلة عن visibility ══ */
      if (platCfg.maintenanceMode === true) {
        return new Response(JSON.stringify({ ok: true, status: 'maintenance', visibility: 'hidden', noindex: true }), { headers });
      }
      var isArchived = platCfg.archived === true;
      visibilityStatus = platCfg.visibility || (platCfg.hiddenFromHub === true ? 'hidden' : 'visible');
      if (platCfg.scheduledVisibility && platCfg.scheduledVisibility.at && new Date(platCfg.scheduledVisibility.at) <= new Date()) {
        visibilityStatus = platCfg.scheduledVisibility.mode;
      }
      seoNoindex = platCfg.seoNoindex === true;
    }
  }

  // ── فحص جلسة المالك/المدير أولاً — وصول كامل تلقائي بلا أي قيد (يسبق كل الفحوصات التالية) ──
  const ownerAccess = await checkOwnerOrAdminSession(request, env);
  if (ownerAccess) {
    return new Response(JSON.stringify({ ok: true, status: 'full', role: ownerAccess, visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  // ── تحقق من جلسة المستخدم (نفس منطق user-verify.js بالضبط) ──
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/az_user_session=([^;]+)/);
  if (!match) {
    return new Response(JSON.stringify({ ok: true, status: 'login_required', visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 4) {
    return new Response(JSON.stringify({ ok: true, status: 'login_required', visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  const [tag, emailB64, expStr, sig] = parts;
  if (tag !== 'user') {
    return new Response(JSON.stringify({ ok: true, status: 'login_required', visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) {
    return new Response(JSON.stringify({ ok: true, status: 'login_required', reason: 'session_expired', visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  const secret = env.OWNER_SECRET || 'fallback-secret-change-me';
  const payload = `${tag}.${emailB64}.${expStr}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const expectedSig = base64url(new Uint8Array(sigBuf));
  if (expectedSig !== sig) {
    return new Response(JSON.stringify({ ok: true, status: 'login_required', visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  const email = atob(emailB64);
  const raw = await env.AZ_USERS_KV.get('user:' + email);
  if (!raw) {
    return new Response(JSON.stringify({ ok: true, status: 'login_required', visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  const record = JSON.parse(raw);

  // ── ١) هل عنده باقة كاملة أو اشتراك مباشر في هذه المنصة؟ ──
  const access = record.platformAccess || { all: false, platforms: [] };
  if (access.all === true || (Array.isArray(access.platforms) && access.platforms.includes(platform))) {
    return new Response(JSON.stringify({ ok: true, status: 'full', visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  // ── ١.٥) هل هذه المنصة "مُهداة" له من المالك؟ (دائمة أو بتاريخ انتهاء) ──
  const gifts = record.giftedAccess || {};
  const giftExpiry = gifts[platform];
  if (giftExpiry !== undefined) {
    if (giftExpiry === null || new Date(giftExpiry) > new Date()) {
      return new Response(JSON.stringify({ ok: true, status: 'full', gifted: true, visibility: visibilityStatus, noindex: seoNoindex }), { headers });
    }
    // الهدية انتهت — تُعامَل كأي اشتراك منتهٍ، لا نعيدها لحالة "تجربة" مجدداً
    return new Response(JSON.stringify({ ok: true, status: 'expired', wasGifted: true, visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  // ── ٢) لا يوجد اشتراك أو هدية — تحقق من التجربة المجانية الخاصة بهذه المنصة تحديداً ──
  const trials = record.platformTrials || {};
  const trialStartedAt = trials[platform];

  if (!trialStartedAt) {
    /* ══ منصة مؤرشَفة: لا تجارب جديدة — "تختفي من البيع الجديد" بالضبط،
       لكن هذا الشرط لا يمس أي مستخدم لديه بالفعل وصول أو تجربة سابقة
       (تلك الحالات عولجت بالكامل في الفحوصات الأعلى، لن تصل هنا) ══ */
    if (isArchived) {
      return new Response(JSON.stringify({ ok: true, status: 'archived', visibility: visibilityStatus, noindex: seoNoindex }), { headers });
    }
    // أول زيارة لهذه المنصة تحديداً — تبدأ التجربة الآن وتُحفظ فوراً
    trials[platform] = new Date().toISOString();
    record.platformTrials = trials;
    await env.AZ_USERS_KV.put('user:' + email, JSON.stringify(record));
    return new Response(JSON.stringify({ ok: true, status: 'trial', daysLeft: TRIAL_DAYS, visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  const startedMs = new Date(trialStartedAt).getTime();
  const elapsedDays = (Date.now() - startedMs) / (24 * 60 * 60 * 1000);
  const daysLeft = Math.ceil(TRIAL_DAYS - elapsedDays);

  if (daysLeft > 0) {
    return new Response(JSON.stringify({ ok: true, status: 'trial', daysLeft, visibility: visibilityStatus, noindex: seoNoindex }), { headers });
  }

  return new Response(JSON.stringify({ ok: true, status: 'expired', visibility: visibilityStatus, noindex: seoNoindex }), { headers });
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* ══ فحص جلسة المالك أو المدير — يمنح وصولاً كاملاً تلقائياً لكل المنصات بلا استثناء ══ */
async function checkOwnerOrAdminSession(request, env) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const secret = env.OWNER_SECRET || env.OWNER_CODE || '';

  // ── جلسة المالك (az_owner_session) — الصيغة: owner.exp.sig ──
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

  // ── جلسة المدير (az_admin_session) — الصيغة: admin.emailB64.exp.sig ──
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
            if (raw) {
              const rec = JSON.parse(raw);
              if (!rec.disabled) return 'admin';
            }
          }
        }
      }
    } catch (e) {}
  }

  return null;
}
