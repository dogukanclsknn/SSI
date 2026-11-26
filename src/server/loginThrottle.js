// SSI — sign-in throttling (brute-force and password-spraying defence).
//
// Two fixed-window counters of FAILED sign-ins:
//  - per username (case-insensitive): stops guessing one account's password from many
//    addresses. Comparable to a directory account-lockout policy.
//  - per client address (socket peer): stops spraying many usernames from one host.
// A successful sign-in clears the username counter. Counters live in process memory:
// SSI runs as a single instance, and a restart only resets the windows.
//
// The client address is the TCP peer, never a client-supplied header, so the limit
// cannot be dodged by forging X-Forwarded-For. Behind a reverse proxy every request
// shares the proxy's address; the per-address limit is sized for that.

export const LOGIN_THROTTLE_DEFAULTS = Object.freeze({
  windowSeconds: 15 * 60,
  maxFailuresPerUsername: 5,
  maxFailuresPerAddress: 50,
  maxTrackedKeys: 10_000,
});

function normalizeUsername(username) {
  return String(username || '').trim().toLowerCase();
}

export function createLoginThrottle(options = {}) {
  const { windowSeconds, maxFailuresPerUsername, maxFailuresPerAddress, maxTrackedKeys } = {
    ...LOGIN_THROTTLE_DEFAULTS,
    ...options,
  };
  const now = options.now || Date.now;
  const windowMs = windowSeconds * 1000;
  const counters = new Map(); // key → { failures, resetAt }

  function prune(at) {
    for (const [key, entry] of counters) {
      if (entry.resetAt <= at) counters.delete(key);
    }
  }

  function current(key, at) {
    const entry = counters.get(key);
    return entry && entry.resetAt > at ? entry : null;
  }

  function keysFor({ username, address }) {
    const keys = [];
    const user = normalizeUsername(username);
    if (user) keys.push({ key: `user:${user}`, limit: maxFailuresPerUsername });
    if (address) keys.push({ key: `addr:${address}`, limit: maxFailuresPerAddress });
    return keys;
  }

  // Returns { allowed: true } or { allowed: false, retryAfterSeconds, scope }.
  function check(subject) {
    const at = now();
    let blocked = null;
    for (const { key, limit } of keysFor(subject)) {
      const entry = current(key, at);
      if (entry && entry.failures >= limit) {
        const retryAfterSeconds = Math.max(1, Math.ceil((entry.resetAt - at) / 1000));
        if (!blocked || retryAfterSeconds > blocked.retryAfterSeconds) {
          blocked = { allowed: false, retryAfterSeconds, scope: key.startsWith('user:') ? 'username' : 'address' };
        }
      }
    }
    return blocked || { allowed: true };
  }

  function recordFailure(subject) {
    const at = now();
    if (counters.size >= maxTrackedKeys) prune(at);
    for (const { key } of keysFor(subject)) {
      const entry = current(key, at);
      if (entry) entry.failures += 1;
      else if (counters.size < maxTrackedKeys) counters.set(key, { failures: 1, resetAt: at + windowMs });
    }
  }

  function recordSuccess({ username }) {
    const user = normalizeUsername(username);
    if (user) counters.delete(`user:${user}`);
  }

  return { check, recordFailure, recordSuccess };
}
