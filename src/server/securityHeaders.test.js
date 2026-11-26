import { describe, expect, it } from 'vitest';
import { applySecurityHeaders, DOCUMENT_CSP, securityHeaders } from './securityHeaders.js';

describe('security headers', () => {
  it('sets a strict, self-only CSP for the app', () => {
    const csp = securityHeaders()['Content-Security-Policy'];
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
  });

  it('never allows script in generated documents', () => {
    expect(DOCUMENT_CSP).toContain("default-src 'none'");
    expect(DOCUMENT_CSP).not.toContain('script-src');
  });

  it('includes clickjacking, sniffing and referrer protections', () => {
    expect(securityHeaders()).toMatchObject({
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Opener-Policy': 'same-origin',
    });
  });

  it('sends HSTS only for HTTPS deployments', () => {
    expect(securityHeaders({ https: false })).not.toHaveProperty('Strict-Transport-Security');
    expect(securityHeaders({ https: true })['Strict-Transport-Security']).toMatch(/^max-age=31536000/);
  });

  it('applies every header to a response', () => {
    const set = {};
    applySecurityHeaders({ setHeader: (name, value) => (set[name] = value) }, { https: true });
    expect(Object.keys(set)).toEqual(Object.keys(securityHeaders({ https: true })));
  });
});
