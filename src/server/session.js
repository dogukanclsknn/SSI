import crypto from 'node:crypto';

// SSI session — a signed cookie so a user signed in via LDAP or the local admin does not
// re-enter a password on every request.
//
// Token format: "<payloadB64url>.<hmacB64url>" (HMAC-SHA256 over the payload).
// Payload: { sub, roles, jti, iat, exp }. Passwords are never placed in the token.
// `jti` is a random token id so a single session can be revoked at sign-out
// (see sessionRevocations.js); tokens without a `jti` are rejected.

export const SESSION_COOKIE_NAME = 'ssi_session';
export const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 hours
export const MIN_SESSION_SECRET_BYTES = 32;

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

// Fail-fast validation for SSI_SESSION_SECRET. Returns an error message or ''.
export function sessionSecretProblem(secret) {
  const value = String(secret || '');
  if (!value) return 'SSI_SESSION_SECRET is not set.';
  if (Buffer.byteLength(value, 'utf8') < MIN_SESSION_SECRET_BYTES) {
    return `SSI_SESSION_SECRET must be at least ${MIN_SESSION_SECRET_BYTES} bytes (generate one with: openssl rand -base64 48).`;
  }
  return '';
}

export function signSession(payload, secret, { ttlSeconds = SESSION_TTL_SECONDS, now = Date.now } = {}) {
  if (!secret) throw new Error('SSI_SESSION_SECRET is required.');
  const issuedAt = Math.floor(now() / 1000);
  const body = {
    sub: String(payload.sub || '').slice(0, 200),
    roles: Array.isArray(payload.roles) ? payload.roles : [],
    jti: crypto.randomBytes(16).toString('base64url'),
    iat: issuedAt,
    exp: issuedAt + ttlSeconds,
  };
  const payloadB64 = b64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', secret).update(payloadB64).digest('base64url');
  return `${payloadB64}.${sig}`;
}

export function verifySession(token, secret, { now = Date.now } = {}) {
  if (!token || !secret) return null;
  const parts = String(token).split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;

  const expected = crypto.createHmac('sha256', secret).update(payloadB64).digest('base64url');
  const provided = Buffer.from(sig);
  const wanted = Buffer.from(expected);
  // Timing-safe signature comparison (a length mismatch is rejected first).
  if (provided.length !== wanted.length || !crypto.timingSafeEqual(provided, wanted)) {
    return null;
  }

  let body;
  try {
    body = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!body || typeof body.exp !== 'number' || body.exp < Math.floor(now() / 1000)) return null;
  if (typeof body.jti !== 'string' || body.jti === '') return null;
  return {
    sub: String(body.sub || ''),
    roles: Array.isArray(body.roles) ? body.roles : [],
    jti: body.jti,
    iat: typeof body.iat === 'number' ? body.iat : null,
    exp: body.exp,
  };
}

export function buildSessionCookie(token, { maxAgeSeconds = SESSION_TTL_SECONDS, secure = true } = {}) {
  const attrs = [`${SESSION_COOKIE_NAME}=${token}`, 'HttpOnly', 'Path=/', 'SameSite=Lax', `Max-Age=${maxAgeSeconds}`];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

export function buildClearCookie({ secure = true } = {}) {
  const attrs = [`${SESSION_COOKIE_NAME}=`, 'HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=0'];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

// Extracts the SSI session token from a Cookie header.
export function readSessionCookie(cookieHeader) {
  if (!cookieHeader) return '';
  for (const part of String(cookieHeader).split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() === SESSION_COOKIE_NAME) {
      return part.slice(idx + 1).trim();
    }
  }
  return '';
}
