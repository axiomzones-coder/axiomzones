// functions/api/support-status.js
// GET /api/support-status?id=SUP-XXXX-XXXX&email=user@example.com
// endpoint عام يسمح للعميل بمتابعة حالة تذكرته بدون تسجيل دخول —
// يتطلب رقم التذكرة + نفس الإيميل المُستخدَم عند الإنشاء (كتحقق بسيط من الهوية).

export async function onRequestGet(context) {
  const { request, env } = context;
  const headers = new Headers({ 'content-type': 'application/json' });

  if (!env.AZ_CONFIG_KV) {
    return new Response(JSON.stringify({ ok: false, error: 'server_not_configured' }), { status: 500, headers });
  }

  const url = new URL(request.url);
  const id = String(url.searchParams.get('id') || '').trim().toUpperCase();
  const email = String(url.searchParams.get('email') || '').trim().toLowerCase();

  if (!id || !email) {
    return new Response(JSON.stringify({ ok: false, error: 'missing_params' }), { status: 400, headers });
  }

  try {
    const configRaw = await env.AZ_CONFIG_KV.get('az_master_config');
    const config = configRaw ? JSON.parse(configRaw) : {};
    const tickets = config.supportTickets || [];
    const ticket = tickets.find(t => t.id === id && t.email === email);

    if (!ticket) {
      return new Response(JSON.stringify({ ok: false, error: 'not_found' }), { status: 404, headers });
    }

    // لا نُرجع بيانات داخلية حساسة (مثل الـIP أو الدولة) — فقط ما يهم العميل
    return new Response(JSON.stringify({
      ok: true,
      ticket: {
        id: ticket.id,
        subject: ticket.subject,
        status: ticket.status,
        createdAt: ticket.createdAt,
        replies: ticket.replies || [],
      }
    }), { headers });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'server_error' }), { status: 500, headers });
  }
}
