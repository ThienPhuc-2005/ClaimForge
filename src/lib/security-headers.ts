/**
 * Production (Nitro / Vercel / vite preview) response headers.
 * Not applied on the Vite dev server so the live-preview iframe still works.
 *
 * CSP allows grok.com (platform PWA injector), module workers, and optional JWKS fetch.
 */

export const CSP_VALUE = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://grok.com blob:",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https:",
  "font-src 'self' data:",
  "connect-src 'self' https: blob: http://127.0.0.1:* http://localhost:* http://[::1]:*",
  "worker-src 'self' blob:",
  "child-src 'self' blob:",
  "frame-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

export function productionSecurityHeaders(): Record<string, string> {
  return {
    "Content-Security-Policy": CSP_VALUE,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "X-Frame-Options": "DENY",
  };
}

export function applySecurityHeaders(headers: Headers): Headers {
  const next = new Headers(headers);
  for (const [k, v] of Object.entries(productionSecurityHeaders())) {
    if (!next.has(k)) next.set(k, v);
  }
  return next;
}
