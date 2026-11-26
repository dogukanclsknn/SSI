import { describe, expect, it } from 'vitest';
import { hashPassword, isLocalAdminUsername, parseLocalAdmin, verifyDecoyPassword, verifyPassword } from './localAdmin.js';

describe('localAdmin password', () => {
  it('hashes and verifies the right password, rejects a wrong one', async () => {
    const hash = hashPassword('S3cret!parola');
    expect(hash.startsWith('scrypt:')).toBe(true);
    await expect(verifyPassword('S3cret!parola', hash)).resolves.toBe(true);
    await expect(verifyPassword('yanlis', hash)).resolves.toBe(false);
  });

  it('returns false for empty input or a malformed hash', async () => {
    await expect(verifyPassword('', 'scrypt:aa:bb')).resolves.toBe(false);
    await expect(verifyPassword('x', '')).resolves.toBe(false);
    await expect(verifyPassword('x', 'md5:aa:bb')).resolves.toBe(false);
    await expect(verifyPassword('x', 'bozuk')).resolves.toBe(false);
    await expect(verifyPassword('x', 'scrypt:zz:yy')).resolves.toBe(false);
  });

  it('verifies asynchronously (does not block the event loop)', () => {
    const pending = verifyPassword('S3cret!parola', hashPassword('S3cret!parola'));
    expect(pending).toBeInstanceOf(Promise);
    return pending;
  });

  it('decoy verification always resolves false', async () => {
    await expect(verifyDecoyPassword('anything')).resolves.toBe(false);
  });
});

describe('parseLocalAdmin', () => {
  it('kullanıcı adı + hash varsa yapılandırma döner', () => {
    const cfg = parseLocalAdmin({
      SSI_LOCAL_ADMIN_USERNAME: 'sysadmin',
      SSI_LOCAL_ADMIN_PASSWORD_HASH: 'scrypt:aa:bb',
      SSI_LOCAL_ADMIN_DISPLAY: 'Sistem Yöneticisi',
    });
    expect(cfg).toMatchObject({ username: 'sysadmin', displayName: 'Sistem Yöneticisi' });
  });

  it('eksik alanlarda null (özellik kapalı)', () => {
    expect(parseLocalAdmin({ SSI_LOCAL_ADMIN_USERNAME: 'x' })).toBeNull();
    expect(parseLocalAdmin({})).toBeNull();
  });

  it('isLocalAdminUsername büyük/küçük harf duyarsız eşler', () => {
    const cfg = { username: 'sysadmin' };
    expect(isLocalAdminUsername(cfg, 'SysAdmin')).toBe(true);
    expect(isLocalAdminUsername(cfg, 'baska')).toBe(false);
    expect(isLocalAdminUsername(null, 'sysadmin')).toBe(false);
  });
});
