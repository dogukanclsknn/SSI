import crypto from 'node:crypto';
import { promisify } from 'node:util';

// Local admin — the bootstrap administrator that does not depend on LDAP.
//
// Someone must be able to assign roles before any LDAP user exists, so a single local
// admin is configured from the environment. The password is never stored in clear
// text: the environment holds only a scrypt HASH (`scripts/hash-password.mjs`).
// Verification is asynchronous (scrypt runs on the libuv pool, never blocking the
// event loop) and timing-safe.

const SCHEME = 'scrypt';
const KEYLEN = 64;
const scryptAsync = promisify(crypto.scrypt);

// A fixed, well-formed hash used to spend the same scrypt cost on unknown usernames,
// so response time does not reveal whether an account exists.
const DECOY_HASH = `${SCHEME}:${'00'.repeat(16)}:${'00'.repeat(KEYLEN)}`;

export function hashPassword(password, { saltBytes = 16 } = {}) {
  const salt = crypto.randomBytes(saltBytes);
  const derived = crypto.scryptSync(String(password), salt, KEYLEN);
  return `${SCHEME}:${salt.toString('hex')}:${derived.toString('hex')}`;
}

function parseHash(storedHash) {
  const parts = String(storedHash || '').split(':');
  if (parts.length !== 3 || parts[0] !== SCHEME) return null;
  if (!/^[0-9a-f]+$/i.test(parts[1]) || !/^[0-9a-f]+$/i.test(parts[2])) return null;
  const salt = Buffer.from(parts[1], 'hex');
  const expected = Buffer.from(parts[2], 'hex');
  if (salt.length === 0 || expected.length === 0) return null;
  return { salt, expected };
}

export async function verifyPassword(password, storedHash) {
  if (!password || !storedHash) return false;
  const parsed = parseHash(storedHash);
  if (!parsed) return false;
  let derived;
  try {
    derived = await scryptAsync(String(password), parsed.salt, parsed.expected.length);
  } catch {
    return false;
  }
  return derived.length === parsed.expected.length && crypto.timingSafeEqual(derived, parsed.expected);
}

// Spends one scrypt verification and always resolves false (timing equaliser).
export async function verifyDecoyPassword(password) {
  await verifyPassword(String(password || 'x'), DECOY_HASH);
  return false;
}

// Local admin configuration from the environment; null when username or hash is missing.
export function parseLocalAdmin(env = process.env) {
  const username = String(env.SSI_LOCAL_ADMIN_USERNAME || '').trim();
  const passwordHash = String(env.SSI_LOCAL_ADMIN_PASSWORD_HASH || '').trim();
  if (!username || !passwordHash) return null;
  return {
    username,
    passwordHash,
    displayName: String(env.SSI_LOCAL_ADMIN_DISPLAY || username).trim() || username,
    email: String(env.SSI_LOCAL_ADMIN_EMAIL || '').trim(),
  };
}

// Is the given username the local admin (case-insensitive)?
export function isLocalAdminUsername(localAdmin, username) {
  if (!localAdmin) return false;
  return localAdmin.username.toLowerCase() === String(username || '').trim().toLowerCase();
}
