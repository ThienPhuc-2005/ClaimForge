/**
 * Production / vite-preview security headers. Nitro only (not Vite :8080),
 * so the live-preview iframe is unaffected.
 */
import { applySecurityHeaders } from "../../src/lib/security-headers.ts";

export default async function securityHeadersMiddleware(
  _event: unknown,
  next: () => unknown | Promise<unknown>,
): Promise<unknown> {
  const result = await next();
  if (!(result instanceof Response)) return result;
  return new Response(result.body, {
    status: result.status,
    statusText: result.statusText,
    headers: applySecurityHeaders(result.headers),
  });
}
