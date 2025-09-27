/**
 * proxy.js
 * Edge function / Cloudflare Pages function style
 *
 * Usage:
 *   GET /proxy?url=<ENCODED_TARGET_URL>
 * Optional env:
 *   AUTH_TOKEN    - (optional) required token sent in header 'x-proxy-token'
 *   ALLOWLIST     - (optional) comma-separated hostnames allowed (e.g. "raw.githubusercontent.com,example.com")
 *   UPSTREAM_PROXY- (optional) professional proxy base. If it contains "{url}", it will be replaced with encodeURIComponent(target).
 *                   Otherwise the target will be appended as encodeURIComponent(target) to the string.
 *
 * Security notes:
 *   - Strongly recommended to set AUTH_TOKEN or ALLOWLIST in production to avoid being an open proxy.
 *   - Do NOT set UPSTREAM_PROXY to public demo proxies like cors-anywhere.herokuapp.com.
 */

export async function onRequest(context) {
  const { request, env } = context;

  // Simple auth: check x-proxy-token if AUTH_TOKEN is set
  const requiredToken = env?.AUTH_TOKEN;
  if (requiredToken) {
    const provided = request.headers.get('x-proxy-token') || '';
    if (provided !== requiredToken) {
      return new Response('Unauthorized - missing or invalid x-proxy-token', { status: 401 });
    }
  }

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization,x-proxy-token',
        'Access-Control-Max-Age': '86400'
      }
    });
  }

  // Parse target URL from query param
  let targetParam;
  try {
    const reqUrl = new URL(request.url);
    targetParam = reqUrl.searchParams.get('url');
  } catch (err) {
    return new Response('Bad request URL', { status: 400 });
  }

  if (!targetParam) {
    return new Response("Query parameter 'url' is missing.", { status: 400 });
  }

  let targetUrl;
  try {
    targetUrl = new URL(targetParam);
  } catch (err) {
    return new Response("Invalid target URL.", { status: 400 });
  }

  // Optional allowlist check
  const allowlistRaw = env?.ALLOWLIST || '';
  if (allowlistRaw) {
    const allowHosts = allowlistRaw.split(',').map(s => s.trim()).filter(Boolean);
    const hostOk = allowHosts.some(h => {
      if (h === targetUrl.hostname) return true;
      // allow subdomains: if allowlist contains example.com, then a.example.com is allowed
      return targetUrl.hostname === h || targetUrl.hostname.endsWith('.' + h);
    });
    if (!hostOk) {
      return new Response('Target host not allowed by ALLOWLIST.', { status: 403 });
    }
  }

  // Build outbound headers - copy safe headers only
  const outHeaders = new Headers();
  for (const [k, v] of request.headers) {
    const lk = k.toLowerCase();
    // skip headers we should not forward
    if (['host', 'cookie', 'authorization', 'origin', 'referer', 'x-proxy-token'].includes(lk)) continue;
    if (lk.startsWith('sec-')) continue; // browser security headers not needed upstream
    outHeaders.set(k, v);
  }

  // Prepare upstream URL: either direct target or via UPSTREAM_PROXY
  const upstreamBase = env?.UPSTREAM_PROXY || '';
  let fetchUrl;
  if (upstreamBase) {
    // If UPSTREAM_PROXY contains {url}, replace it; otherwise append encoded target
    if (upstreamBase.includes('{url}')) {
      fetchUrl = upstreamBase.replace('{url}', encodeURIComponent(targetUrl.toString()));
    } else {
      // ensure if upstreamBase seems to require a trailing delimiter we just append encoded URL
      // e.g. "https://myproxy.example.com/fetch?u=" -> becomes "...?u=<encoded>"
      fetchUrl = upstreamBase + encodeURIComponent(targetUrl.toString());
    }
  } else {
    fetchUrl = targetUrl.toString();
  }

  const fetchOptions = {
    method: request.method,
    headers: outHeaders,
    redirect: 'follow',
    // forward body for POST/PUT/PATCH etc. Use request.body directly to preserve streaming where supported.
    body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body
  };

  let upstreamResp;
  try {
    upstreamResp = await fetch(fetchUrl, fetchOptions);
  } catch (err) {
    // upstream fetch/network error
    return new Response('Upstream fetch failed: ' + err.message, { status: 502 });
  }

  // Build response headers: clone and sanitize
  const respHeaders = new Headers();
  for (const [k, v] of upstreamResp.headers) {
    const lk = k.toLowerCase();
    // strip cookies for security
    if (['set-cookie', 'set-cookie2'].includes(lk)) continue;
    // let edge handle compression
    if (lk === 'content-encoding') continue;
    // Avoid leaking any proxy-specific headers if desired (optional)
    // if (lk.startsWith('x-')) continue;
    respHeaders.set(k, v);
  }

  // Add CORS headers for browser access. Prefer echoing Origin if present.
  const origin = request.headers.get('Origin');
  respHeaders.set('Access-Control-Allow-Origin', origin || '*');
  respHeaders.set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  respHeaders.set('Access-Control-Allow-Headers', 'Content-Type,Authorization,x-proxy-token');
  // Signal varied by origin
  respHeaders.set('Vary', 'Origin');

  // Return streamed body to preserve large responses
  return new Response(upstreamResp.body, {
    status: upstreamResp.status,
    statusText: upstreamResp.statusText,
    headers: respHeaders
  });
}
