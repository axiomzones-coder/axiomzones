// functions/api/platform-chat.js
// POST /api/platform-chat — Body: { platform: 'kashf', question: '...', system: '...' }
// يستخدم Cloudflare Workers AI (مجاني، 10,000 نيورون/يوم) بدل Anthropic المكشوف للمتصفح

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AI) {
    return new Response(JSON.stringify({ ok: false, error: 'workers_ai_not_configured' }), { status: 500, headers });
  }

  // ── تحديد معدل الطلبات لكل IP — يحمي رصيد Workers AI المجاني اليومي من الاستنزاف الخارجي ──
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (env.AZ_CONFIG_KV) {
    const rlKey = `ratelimit:chat:${ip}`;
    const raw = await env.AZ_CONFIG_KV.get(rlKey);
    const count = raw ? (JSON.parse(raw).count || 0) : 0;
    if (count >= 20) { // 20 سؤال/ساعة لكل زائر — كافٍ لأي استخدام مشروع
      return new Response(JSON.stringify({ ok: false, error: 'rate_limited' }), { status: 429, headers });
    }
    await env.AZ_CONFIG_KV.put(rlKey, JSON.stringify({ count: count + 1 }), { expirationTtl: 3600 });
  }

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  const question = String((body && body.question) || '').slice(0, 500); // حد أقصى للطول يمنع إساءة استخدام النيورونات
  const system = String((body && body.system) || 'Answer under 80 words.');

  if (!question) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_question' }), { status: 400, headers });
  }

  try {
    const result = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: question }
      ],
      max_tokens: 200,
    });

    const answer = (result && result.response) || 'Try the platform free to explore!';
    return new Response(JSON.stringify({ ok: true, answer }), { status: 200, headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: 'chat_failed' }), { status: 500, headers });
  }
}
