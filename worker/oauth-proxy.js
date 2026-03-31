/* ═══════════════════════════════════════════════════════════
   DepScan — Cloudflare Worker: OAuth Token Exchange Proxy
   
   This worker does ONE thing: exchange a GitHub OAuth
   authorization code for an access token. The client_secret
   is stored securely as a Cloudflare environment variable.
   
   Environment Variables (set via `wrangler secret put`):
     GITHUB_CLIENT_ID     — from your GitHub OAuth App
     GITHUB_CLIENT_SECRET — from your GitHub OAuth App
     ALLOWED_ORIGIN       — your GitHub Pages origin
                            e.g. https://yourusername.github.io
   ═══════════════════════════════════════════════════════════ */

export default {
  async fetch(request, env) {
    const origin = env.ALLOWED_ORIGIN || '*';

    // ── CORS Headers ───────────────────────────────────────
    const corsHeaders = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    };

    // ── Preflight ──────────────────────────────────────────
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    // ── Only accept POST /exchange ─────────────────────────
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/exchange') {
      return new Response(
        JSON.stringify({ error: 'Not Found. Use POST /exchange' }),
        {
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        }
      );
    }

    // ── Validate request ───────────────────────────────────
    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(
        JSON.stringify({ error: 'Invalid JSON body' }),
        {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        }
      );
    }

    const { code } = body;
    if (!code) {
      return new Response(
        JSON.stringify({ error: 'Missing "code" in request body' }),
        {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        }
      );
    }

    // ── Exchange code for token ────────────────────────────
    try {
      const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code: code,
        }),
      });

      const tokenData = await tokenResponse.json();

      // Check for error from GitHub
      if (tokenData.error) {
        return new Response(
          JSON.stringify({
            error: tokenData.error,
            error_description: tokenData.error_description,
          }),
          {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          }
        );
      }

      // Return only the access_token — never forward other fields
      return new Response(
        JSON.stringify({ access_token: tokenData.access_token }),
        {
          status: 200,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        }
      );
    } catch (err) {
      return new Response(
        JSON.stringify({ error: 'Failed to exchange code with GitHub', detail: err.message }),
        {
          status: 502,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        }
      );
    }
  },
};
