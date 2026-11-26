import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import {
  buildClearCookie,
  buildSessionCookie,
  MIN_SESSION_SECRET_BYTES,
  readSessionCookie,
  SESSION_COOKIE_NAME,
  sessionSecretProblem,
  signSession,
  verifySession,
} from './session.js';

const secret = 'unit-test-secret-32-bytes-minimum-xxxxx';

describe('session sign/verify', () => {
  it('imzalanan token doğrulanır ve subject + roller döner', () => {
    const token = signSession({ sub: 'alex', roles: ['approver'] }, secret);
    const session = verifySession(token, secret);
    expect(session).toMatchObject({ sub: 'alex', roles: ['approver'] });
    expect(session.jti).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(session.exp - session.iat).toBe(8 * 60 * 60);
  });

  it('every token carries a unique id (jti) so it can be revoked on its own', () => {
    const a = verifySession(signSession({ sub: 'alex', roles: [] }, secret), secret);
    const b = verifySession(signSession({ sub: 'alex', roles: [] }, secret), secret);
    expect(a.jti).not.toBe(b.jti);
  });

  it('rejects a correctly signed token without a jti (pre-revocation format)', () => {
    const payload = Buffer.from(JSON.stringify({ sub: 'alex', roles: ['admin'], exp: 9999999999 })).toString(
      'base64url',
    );
    const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
    expect(verifySession(`${payload}.${sig}`, secret)).toBeNull();
  });

  it('kurcalanmış payload reddedilir', () => {
    const token = signSession({ sub: 'alex', roles: ['viewer'] }, secret);
    const [, sig] = token.split('.');
    const forged = `${Buffer.from(JSON.stringify({ sub: 'admin', roles: ['admin'], exp: 9999999999 })).toString('base64url')}.${sig}`;
    expect(verifySession(forged, secret)).toBeNull();
  });

  it('yanlış secret ile doğrulanmaz', () => {
    const token = signSession({ sub: 'alex', roles: ['operator'] }, secret);
    expect(verifySession(token, 'baska-secret')).toBeNull();
  });

  it('süresi geçmiş token reddedilir', () => {
    const past = () => Date.now() - 10 * 60 * 60 * 1000; // 10 saat önce imzalanmış
    const token = signSession({ sub: 'alex', roles: ['viewer'] }, secret, { ttlSeconds: 3600, now: past });
    expect(verifySession(token, secret)).toBeNull();
  });

  it('bozuk / eksik token güvenle null döner', () => {
    expect(verifySession('', secret)).toBeNull();
    expect(verifySession('abc', secret)).toBeNull();
    expect(verifySession('a.b.c', secret)).toBeNull();
    expect(verifySession(null, secret)).toBeNull();
  });
});

describe('session cookie yardımcıları', () => {
  it('Set-Cookie güvenlik özniteliklerini içerir', () => {
    const cookie = buildSessionCookie('tok', { secure: true });
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=tok`);
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Lax');
  });

  it('clear cookie Max-Age=0 ile siler', () => {
    expect(buildClearCookie()).toContain('Max-Age=0');
  });

  it('readSessionCookie yalnızca oturum çerezini çıkarır', () => {
    expect(readSessionCookie(`foo=1; ${SESSION_COOKIE_NAME}=xyz; bar=2`)).toBe('xyz');
    expect(readSessionCookie('foo=1; bar=2')).toBe('');
    expect(readSessionCookie('')).toBe('');
  });
});

describe('sessionSecretProblem', () => {
  it('requires a secret of at least 32 bytes', () => {
    expect(sessionSecretProblem('')).toMatch(/not set/);
    expect(sessionSecretProblem('x'.repeat(MIN_SESSION_SECRET_BYTES - 1))).toMatch(/at least 32 bytes/);
    expect(sessionSecretProblem('x'.repeat(MIN_SESSION_SECRET_BYTES))).toBe('');
  });
});
