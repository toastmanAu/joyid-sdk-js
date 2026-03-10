/**
 * embedded-worker.ts — Cloudflare Worker: JoyID callback receiver + session store
 *
 * Deploy: wrangler deploy packages/common/src/sdk/embedded-worker.ts
 *
 * Routes:
 *   GET  /callback?session=<id>&_data_=<joyid_response>
 *        → JoyID redirects here after auth; stores credential in KV; redirects to success page
 *
 *   GET  /session/<id>
 *        → Device polls here; returns 200+JSON when credential ready, 404 while pending
 *
 *   GET  /qr?<auth_params>
 *        → Optional: builds the JoyID URL server-side so ESP32 doesn't need JS
 *
 * KV namespace: JOYID_SESSIONS
 *   key: session:<id>   value: JSON credential   TTL: 600s (10 min)
 */

export interface Env {
  JOYID_SESSIONS: KVNamespace
  /** Allowed origin for CORS (your device's domain or *) */
  ALLOWED_ORIGIN?: string
}

const CORS = (env: Env) => ({
  'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN ?? '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
})

const json = (data: unknown, status = 200, env: Env) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS(env) },
  })

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS(env) })
    }

    // ── GET /callback ───────────────────────────────────────────────────────
    // JoyID redirects here after successful auth.
    // Extracts _data_ param, stores in KV, shows success page.
    if (url.pathname === '/callback') {
      const sessionId = url.searchParams.get('session')
      const rawData   = url.searchParams.get('_data_')

      if (!sessionId || !rawData) {
        return new Response('Missing session or _data_', { status: 400 })
      }

      // Decode JoyID response (base64url encoded JSON)
      let credential: unknown
      try {
        credential = JSON.parse(atob(rawData.replace(/-/g, '+').replace(/_/g, '/')))
      } catch {
        // Try as-is (some versions use plain JSON encoding)
        try { credential = JSON.parse(decodeURIComponent(rawData)) }
        catch { return new Response('Invalid _data_ format', { status: 400 }) }
      }

      // Store in KV with 10 min TTL
      await env.JOYID_SESSIONS.put(
        `session:${sessionId}`,
        JSON.stringify(credential),
        { expirationTtl: 600 }
      )

      // Return a success page the phone can show
      return new Response(SUCCESS_HTML, {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
      })
    }

    // ── GET /session/<id> ───────────────────────────────────────────────────
    // Device polls here. Returns 200+credential when ready, 404 while pending.
    const sessionMatch = url.pathname.match(/^\/session\/([a-f0-9]{32})$/)
    if (sessionMatch) {
      const sessionId = sessionMatch[1]
      const stored = await env.JOYID_SESSIONS.get(`session:${sessionId}`)

      if (!stored) {
        return json({ pending: true }, 404, env)
      }

      // Delete after retrieval (single-use)
      await env.JOYID_SESSIONS.delete(`session:${sessionId}`)

      return json(JSON.parse(stored), 200, env)
    }

    // ── GET /health ─────────────────────────────────────────────────────────
    if (url.pathname === '/health') {
      return json({ ok: true, service: 'joyid-embedded-auth' }, 200, env)
    }

    return new Response('Not found', { status: 404 })
  },
}

// ── Success page ─────────────────────────────────────────────────────────────

const SUCCESS_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authenticated</title>
  <style>
    body { font-family: system-ui, sans-serif; display: flex; align-items: center;
           justify-content: center; min-height: 100vh; margin: 0; background: #0d1117; color: #e6edf3; }
    .card { text-align: center; padding: 2rem; }
    .icon { font-size: 3rem; margin-bottom: 1rem; }
    h1 { font-size: 1.4rem; margin: 0 0 .5rem; }
    p { color: #8b949e; font-size: .9rem; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>Authenticated</h1>
    <p>You can return to your device.</p>
  </div>
</body>
</html>`
