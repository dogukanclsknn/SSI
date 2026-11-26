// SSI — HTTP security headers, applied once per response at the server entry point.
//
// Two Content-Security-Policies:
//  - APP: the React UI. Everything is served by SSI itself; no inline script or style
//    and no third-party origin is needed (React's `style` props use the CSSOM, which
//    CSP does not restrict).
//  - DOCUMENT: generated HTML reports. They carry an inline <style> block and must
//    never run script, so script is disabled entirely.
// HSTS is only sent for HTTPS deployments (browsers ignore it over plain HTTP anyway);
// SSI uses secure cookies as the signal that it is served over HTTPS.

const APP_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export const DOCUMENT_CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  "img-src 'self' data:",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

const BASE_HEADERS = Object.freeze({
  'Content-Security-Policy': APP_CSP,
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
});

const HSTS_VALUE = 'max-age=31536000; includeSubDomains';

export function securityHeaders({ https = false } = {}) {
  return https ? { ...BASE_HEADERS, 'Strict-Transport-Security': HSTS_VALUE } : { ...BASE_HEADERS };
}

export function applySecurityHeaders(response, options) {
  for (const [name, value] of Object.entries(securityHeaders(options))) {
    response.setHeader(name, value);
  }
}
