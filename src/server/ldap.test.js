import { describe, expect, it } from 'vitest';
import {
  authenticateUser,
  buildUserFilter,
  groupCommonName,
  isLdapConfigured,
  LdapAuthError,
  rolesForGroups,
  toStringArray,
} from './ldap.js';

const config = {
  url: 'ldaps://dc.example:636',
  baseDN: 'OU=All Users,DC=corp,DC=example',
  bindDN: 'CN=svc,OU=Service Accounts,DC=corp,DC=example',
  bindPassword: 'svc-secret',
  userFilter: '(sAMAccountName={username})',
  tlsRejectUnauthorized: false,
};

// Sahte ldapts client'ı: bind/search/unbind çağrılarını kaydeder.
function fakeClient({ userDn, groups = [], userPassword = 'correct', bindServiceFails = false, notFound = false }) {
  const calls = { binds: [], searched: false, unbound: false };
  return {
    calls,
    async bind(dn, password) {
      calls.binds.push({ dn, password });
      if (dn === config.bindDN) {
        if (bindServiceFails) throw new Error('service bind failed');
        return;
      }
      if (dn === userDn && password === userPassword) return;
      const err = new Error('invalid credentials');
      err.name = 'InvalidCredentialsError';
      throw err;
    },
    async search() {
      calls.searched = true;
      if (notFound) return { searchEntries: [], searchReferences: [] };
      return { searchEntries: [{ dn: userDn, sAMAccountName: 'alex', memberOf: groups }], searchReferences: [] };
    },
    async unbind() {
      calls.unbound = true;
    },
  };
}

describe('ldap helpers', () => {
  it('toStringArray tekil, dizi ve Buffer değerlerini normalize eder', () => {
    expect(toStringArray(undefined)).toEqual([]);
    expect(toStringArray('a')).toEqual(['a']);
    expect(toStringArray(['a', 'b'])).toEqual(['a', 'b']);
    expect(toStringArray([Buffer.from('cn=x')])).toEqual(['cn=x']);
  });

  it('buildUserFilter kullanıcı adını LDAP-escape eder (injection önlenir)', () => {
    expect(buildUserFilter('(sAMAccountName={username})', 'alex')).toBe('(sAMAccountName=alex)');
    const injected = buildUserFilter('(sAMAccountName={username})', '*)(uid=*');
    expect(injected).not.toContain('*)(');
    expect(injected).toContain('\\2a');
  });

  it('groupCommonName ve rolesForGroups CN ya da tam DN ile eşler', () => {
    expect(groupCommonName('CN=SSI-Approvers,OU=Groups,DC=corp')).toBe('SSI-Approvers');
    const groups = ['CN=SSI-Approvers,OU=Groups,DC=corp', 'CN=SSI-Viewers,OU=Groups,DC=corp'];
    const map = { 'ssi-approvers': ['approver'], 'cn=ssi-viewers,ou=groups,dc=corp': ['viewer'] };
    expect(rolesForGroups(groups, map).sort()).toEqual(['approver', 'viewer']);
  });

  it('isLdapConfigured eksik alanları yakalar', () => {
    expect(isLdapConfigured(config)).toBe(true);
    expect(isLdapConfigured({ ...config, url: '' })).toBe(false);
  });
});

describe('authenticateUser', () => {
  const opts = (client) => ({ createClient: () => client });

  it('doğru şifre: subject + gruplar döner, servis + kullanıcı bind edilir, unbind yapılır', async () => {
    const client = fakeClient({
      userDn: 'CN=Alex,OU=All Users,DC=corp,DC=example',
      groups: ['CN=SSI-Approvers,OU=Groups,DC=corp,DC=example'],
    });
    const id = await authenticateUser('alex', 'correct', config, opts(client));
    expect(id.subject).toBe('alex');
    expect(id.groups).toEqual(['CN=SSI-Approvers,OU=Groups,DC=corp,DC=example']);
    expect(client.calls.binds[0].dn).toBe(config.bindDN); // önce servis
    expect(client.calls.binds[1].dn).toBe(id.dn); // sonra kullanıcı
    expect(client.calls.unbound).toBe(true);
  });

  it('yanlış şifre: LdapAuthError (401)', async () => {
    const client = fakeClient({ userDn: 'CN=Alex,OU=All Users,DC=corp,DC=example' });
    await expect(authenticateUser('alex', 'wrong', config, opts(client))).rejects.toBeInstanceOf(LdapAuthError);
    expect(client.calls.unbound).toBe(true);
  });

  it('boş şifre: bind denenmeden reddedilir (unauthenticated-bind bypass önlenir)', async () => {
    const client = fakeClient({ userDn: 'CN=Alex,OU=All Users,DC=corp,DC=example' });
    await expect(authenticateUser('alex', '', config, opts(client))).rejects.toBeInstanceOf(LdapAuthError);
    expect(client.calls.binds).toHaveLength(0); // hiç bağlanmadı
  });

  it('kullanıcı bulunamazsa: jenerik LdapAuthError', async () => {
    const client = fakeClient({ userDn: 'x', notFound: true });
    await expect(authenticateUser('yok', 'correct', config, opts(client))).rejects.toBeInstanceOf(LdapAuthError);
  });

  it('servis hesabı bağlanamazsa: 502', async () => {
    const client = fakeClient({ userDn: 'x', bindServiceFails: true });
    await expect(authenticateUser('alex', 'correct', config, opts(client))).rejects.toMatchObject({ statusCode: 502 });
  });
});
