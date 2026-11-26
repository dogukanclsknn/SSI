import { describe, expect, it } from 'vitest';
import { createLoginThrottle } from './loginThrottle.js';

function clock(start = 1_000_000) {
  let value = start;
  return { now: () => value, advance: (ms) => (value += ms) };
}

describe('login throttle', () => {
  it('locks a username after the failure limit, for any address', () => {
    const time = clock();
    const throttle = createLoginThrottle({ now: time.now, maxFailuresPerUsername: 3, windowSeconds: 60 });
    for (let i = 0; i < 3; i += 1) throttle.recordFailure({ username: 'SysAdmin', address: `10.0.0.${i}` });
    const result = throttle.check({ username: 'sysadmin', address: '10.9.9.9' });
    expect(result).toMatchObject({ allowed: false, scope: 'username' });
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
    expect(result.retryAfterSeconds).toBeLessThanOrEqual(60);
  });

  it('allows the username again once the window has passed', () => {
    const time = clock();
    const throttle = createLoginThrottle({ now: time.now, maxFailuresPerUsername: 2, windowSeconds: 60 });
    throttle.recordFailure({ username: 'a', address: '1.1.1.1' });
    throttle.recordFailure({ username: 'a', address: '1.1.1.1' });
    expect(throttle.check({ username: 'a', address: '1.1.1.1' }).allowed).toBe(false);
    time.advance(61_000);
    expect(throttle.check({ username: 'a', address: '1.1.1.1' }).allowed).toBe(true);
  });

  it('blocks an address that sprays many usernames', () => {
    const time = clock();
    const throttle = createLoginThrottle({ now: time.now, maxFailuresPerAddress: 4 });
    for (let i = 0; i < 4; i += 1) throttle.recordFailure({ username: `user${i}`, address: '192.0.2.10' });
    expect(throttle.check({ username: 'fresh-user', address: '192.0.2.10' })).toMatchObject({
      allowed: false,
      scope: 'address',
    });
    expect(throttle.check({ username: 'fresh-user', address: '192.0.2.11' }).allowed).toBe(true);
  });

  it('a successful sign-in clears the username counter', () => {
    const time = clock();
    const throttle = createLoginThrottle({ now: time.now, maxFailuresPerUsername: 2 });
    throttle.recordFailure({ username: 'a', address: '1.1.1.1' });
    throttle.recordSuccess({ username: 'A' });
    throttle.recordFailure({ username: 'a', address: '1.1.1.1' });
    expect(throttle.check({ username: 'a', address: '1.1.1.1' }).allowed).toBe(true);
  });

  it('bounds memory by pruning expired windows', () => {
    const time = clock();
    const throttle = createLoginThrottle({
      now: time.now,
      maxTrackedKeys: 2,
      windowSeconds: 1,
      maxFailuresPerUsername: 1,
    });
    throttle.recordFailure({ username: 'a' });
    throttle.recordFailure({ username: 'b' });
    time.advance(2_000);
    // Table is full of expired windows: they are pruned and the new key is tracked.
    throttle.recordFailure({ username: 'c' });
    expect(throttle.check({ username: 'c' }).allowed).toBe(false);
  });
});
