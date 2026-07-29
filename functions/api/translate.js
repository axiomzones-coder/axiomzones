// functions/api/translate.js
// POST /api/translate — Body: { lang: 'es', texts: {key: "English text", ...} }
// يترجم عبر Cloudflare Workers AI (مجاني، 10,000 نيورون/يوم) — بدون أي مفتاح API مكشوف للمتصفح

const LANG_NAME_MAP = {
  es:'spanish', de:'german', it:'italian', pt:'portuguese', ru:'russian',
  zh:'chinese', 'zh-tw':'chinese', ja:'japanese', ko:'korean',
  hi:'hindi', bn:'bengali', ta:'tamil', te:'telugu', mr:'marathi', gu:'gujarati',
  pa:'punjabi', ne:'nepali', si:'sinhala', th:'thai', vi:'vietnamese',
  id:'indonesian', ms:'malay', tl:'filipino', my:'burmese', km:'khmer', lo:'lao', mn:'mongolian',
  tr:'turkish', nl:'dutch', sv:'swedish', no:'norwegian', da:'danish', fi:'finnish',
  is:'icelandic', ca:'catalan', eu:'basque', gl:'galician', cy:'welsh', ga:'irish',
  pl:'polish', cs:'czech', sk:'slovak', hu:'hungarian', ro:'romanian', el:'greek',
  bg:'bulgarian', sr:'serbian', hr:'croatian', sl:'slovenian', uk:'ukrainian',
  lt:'lithuanian', lv:'latvian', et:'estonian', sq:'albanian', mk:'macedonian',
  bs:'bosnian', be:'belarusian', ka:'georgian', hy:'armenian', az:'azerbaijani',
  kk:'kazakh', uz:'uzbek', fa:'persian', he:'hebrew', ur:'urdu', ku:'kurdish',
  sw:'swahili', am:'amharic', yo:'yoruba', ig:'igbo', ha:'hausa', zu:'zulu',
  af:'afrikaans', so:'somali', 'pt-br':'portuguese',
};

const SEP = '\n@@AZ@@\n'; // فاصل نادر الحدوث يفصل بين القيم عند الدمج والتفكيك

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AI) {
    return new Response(JSON.stringify({ ok: false, error: 'workers_ai_not_configured' }), { status: 500, headers });
  }

  let body;
  try { body = await request.json(); } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'bad_request' }), { status: 400, headers });
  }

  const lang = String((body && body.lang) || '').toLowerCase();
  const texts = (body && body.texts) || {};
  const targetName = LANG_NAME_MAP[lang];

  if (!targetName) {
    return new Response(JSON.stringify({ ok: false, error: 'unsupported_language' }), { status: 400, headers });
  }

  const keys = Object.keys(texts);
  if (!keys.length) {
    return new Response(JSON.stringify({ ok: false, error: 'no_texts' }), { status: 400, headers });
  }

  const joined = keys.map(k => texts[k]).join(SEP);

  try {
    const result = await env.AI.run('@cf/meta/m2m100-1.2b', {
      text: joined,
      source_lang: 'english',
      target_lang: targetName,
    });

    const translatedText = (result && result.translated_text) || '';
    const parts = translatedText.split(SEP);

    const out = {};
    keys.forEach((k, i) => {
      out[k] = (parts[i] != null ? parts[i].trim() : texts[k]); // لو اختل العدد، نرجع النص الأصلي لتلك القيمة تحديداً بدل كسر الصفحة
    });

    return new Response(JSON.stringify({ ok: true, lang, translations: out }), { status: 200, headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: 'translation_failed' }), { status: 500, headers });
  }
}
