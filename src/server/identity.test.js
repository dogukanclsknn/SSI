import { describe, expect, it } from 'vitest';
import { IDENTITY_SOURCE, isTrustedIdentity, resolveIdentity } from './identity.js';
import { signSession } from './session.js';

const req = (headers = {}) => ({ headers });
const SECRET = 'identity-test-session-secret-32bytes!!';
const cookieReq = (token, headers = {}) => ({ headers: { cookie: `ssi_session=${token}`, ...headers } });
const ENTRA_GROUPS = { 'ssi-approvers': ['approver'], 'ssi-viewers': ['viewer'] };

describe('resolveIdentity — enforcement off', () => {
  it('grants default roles and a wildcard, keeping a trusted subject for the audit trail', () => {
    const id = resolveIdentity(req({ 'x-ssi-actor-id': 'alex' }), {
      enforced: false,
      devLogin: true,
      defaultRoles: ['admin'],
    });
    expect(id).toMatchObject({
      subject: 'alex',
      permissions: ['*'],
      authenticated: false,
      enforced: false,
      source: IDENTITY_SOURCE.DEV_LOGIN,
    });
  });

  it('ignores X-SSI-Actor-Id unless dev login is enabled', () => {
    const id = resolveIdentity(req({ 'x-ssi-actor-id': 'mallory' }), {
      enforced: false,
      trustActorHeader: true,
      defaultActorId: 'ssi-api',
    });
    expect(id).toMatchObject({ subject: 'ssi-api', source: IDENTITY_SOURCE.DEFAULT });
    expect(isTrustedIdentity(id)).toBe(false);
  });
});

describe('resolveIdentity — trusted proxy (SSI_TRUST_ACTOR_HEADER)', () => {
  it('resolves X-Forwarded-User and maps X-Forwarded-Groups to roles server-side', () => {
    const id = resolveIdentity(
      req({ 'x-forwarded-user': 'sam@example', 'x-forwarded-groups': 'SSI-Approvers,SSI-Viewers' }),
      { enforced: true, trustActorHeader: true, groupRoleMap: ENTRA_GROUPS },
    );
    expect(id).toMatchObject({ subject: 'sam@example', authenticated: true, source: IDENTITY_SOURCE.PROXY });
    expect(id.permissions).toContain('publish:approve');
    expect(id.roles).toEqual(expect.arrayContaining(['approver', 'viewer']));
  });

  it('never honours a client-supplied X-SSI-Actor-Roles header (privilege-escalation guard)', () => {
    const id = resolveIdentity(
      req({
        'x-forwarded-user': 'viewer.user',
        'x-forwarded-groups': 'SSI-Viewers',
        'x-ssi-actor-roles': 'admin',
      }),
      { enforced: true, trustActorHeader: true, groupRoleMap: ENTRA_GROUPS },
    );
    expect(id.roles).toEqual(['viewer']);
    expect(id.permissions).not.toContain('*');
    expect(id.permissions).not.toContain('user:manage');
  });

  it('never lets X-SSI-Actor-Id replace the proxy-authenticated user', () => {
    const id = resolveIdentity(
      req({ 'x-forwarded-user': 'viewer.user', 'x-forwarded-groups': 'SSI-Viewers', 'x-ssi-actor-id': 'admin' }),
      { enforced: true, trustActorHeader: true, groupRoleMap: ENTRA_GROUPS },
    );
    expect(id.subject).toBe('viewer.user');
  });

  it('rejects X-SSI-Actor-* headers when only proxy trust is enabled', () => {
    const id = resolveIdentity(req({ 'x-ssi-actor-id': 'mallory', 'x-ssi-actor-roles': 'admin' }), {
      enforced: true,
      trustActorHeader: true,
    });
    expect(id).toMatchObject({ subject: 'anonymous', authenticated: false, permissions: [] });
  });

  it('falls back to server-side role bindings when groups map to nothing', () => {
    const id = resolveIdentity(req({ 'x-forwarded-user': 'Taylor', 'x-forwarded-groups': 'unmapped-group' }), {
      enforced: true,
      trustActorHeader: true,
      groupRoleMap: ENTRA_GROUPS,
      roleBindings: { taylor: ['operator'] },
    });
    expect(id.permissions).toContain('remediation:plan');
  });

  it('authenticates an unmapped user without any permission (fail-closed)', () => {
    const id = resolveIdentity(req({ 'x-forwarded-user': 'stranger' }), { enforced: true, trustActorHeader: true });
    expect(id).toMatchObject({ subject: 'stranger', authenticated: true, roles: [], permissions: [] });
  });

  it('ignores X-Forwarded-User when proxy trust is off', () => {
    const id = resolveIdentity(req({ 'x-forwarded-user': 'sam' }), { enforced: true, trustActorHeader: false });
    expect(id).toMatchObject({ subject: 'anonymous', source: IDENTITY_SOURCE.ANONYMOUS });
  });
});

describe('resolveIdentity — dev login (SSI_DEV_LOGIN)', () => {
  it('honours the demo identity headers only when dev login is enabled', () => {
    const id = resolveIdentity(req({ 'x-ssi-actor-id': 'sam', 'x-ssi-actor-roles': 'approver' }), {
      enforced: true,
      devLogin: true,
    });
    expect(id).toMatchObject({ subject: 'sam', authenticated: true, source: IDENTITY_SOURCE.DEV_LOGIN });
    expect(id.permissions).toContain('publish:approve');
    expect(id.permissions).not.toContain('publish:request');
  });

  it('falls back to server-side role bindings when no role header is sent', () => {
    const id = resolveIdentity(req({ 'x-ssi-actor-id': 'Taylor' }), {
      enforced: true,
      devLogin: true,
      roleBindings: { taylor: ['operator'] },
    });
    expect(id.permissions).toContain('remediation:plan');
  });

  it('is anonymous when dev login is disabled', () => {
    const id = resolveIdentity(req({ 'x-ssi-actor-id': 'alex', 'x-ssi-actor-roles': 'admin' }), {
      enforced: true,
      devLogin: false,
    });
    expect(id).toMatchObject({ subject: 'anonymous', authenticated: false, permissions: [] });
  });

  it('prefers the proxy-authenticated user when both sources are configured', () => {
    const id = resolveIdentity(
      req({ 'x-forwarded-user': 'real.user', 'x-forwarded-groups': 'SSI-Viewers', 'x-ssi-actor-id': 'admin' }),
      { enforced: true, trustActorHeader: true, devLogin: true, groupRoleMap: ENTRA_GROUPS },
    );
    expect(id).toMatchObject({ subject: 'real.user', source: IDENTITY_SOURCE.PROXY, roles: ['viewer'] });
  });
});

describe('resolveIdentity — signed session', () => {
  it('resolves the cookie and reads role and status live from the user store', () => {
    const token = signSession({ sub: 'alex', roles: ['viewer'] }, SECRET);
    const id = resolveIdentity(cookieReq(token), {
      enforced: true,
      sessionSecret: SECRET,
      resolveUser: () => ({ role: 'operator', status: 'active' }),
    });
    expect(id).toMatchObject({ subject: 'alex', authenticated: true, source: IDENTITY_SOURCE.SESSION });
    expect(id.roles).toEqual(['operator']);
    expect(id.permissions).toContain('remediation:plan');
  });

  it('wins over any identity header', () => {
    const token = signSession({ sub: 'alex', roles: ['viewer'] }, SECRET);
    const id = resolveIdentity(cookieReq(token, { 'x-ssi-actor-id': 'admin', 'x-ssi-actor-roles': 'admin' }), {
      enforced: true,
      devLogin: true,
      sessionSecret: SECRET,
      resolveUser: () => ({ role: 'viewer', status: 'active' }),
    });
    expect(id).toMatchObject({ subject: 'alex', roles: ['viewer'], source: IDENTITY_SOURCE.SESSION });
  });

  it('ignores a token that was revoked at sign-out', () => {
    const token = signSession({ sub: 'alex', roles: ['admin'] }, SECRET);
    const revoked = new Set();
    const options = {
      enforced: true,
      sessionSecret: SECRET,
      resolveUser: () => ({ role: 'admin', status: 'active' }),
      isSessionRevoked: (jti) => revoked.has(jti),
    };
    expect(resolveIdentity(cookieReq(token), options).authenticated).toBe(true);
    const [payload] = token.split('.');
    revoked.add(JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')).jti);
    expect(resolveIdentity(cookieReq(token), options)).toMatchObject({ subject: 'anonymous', authenticated: false });
  });

  it('is anonymous when the user has been disabled', () => {
    const token = signSession({ sub: 'alex', roles: ['admin'] }, SECRET);
    const id = resolveIdentity(cookieReq(token), {
      enforced: true,
      sessionSecret: SECRET,
      resolveUser: () => ({ role: 'admin', status: 'disabled' }),
    });
    expect(id).toMatchObject({ subject: 'anonymous', authenticated: false, permissions: [] });
  });
});

describe('isTrustedIdentity', () => {
  it('trusts session, proxy and dev-login sources only', () => {
    expect(isTrustedIdentity({ source: IDENTITY_SOURCE.SESSION })).toBe(true);
    expect(isTrustedIdentity({ source: IDENTITY_SOURCE.PROXY })).toBe(true);
    expect(isTrustedIdentity({ source: IDENTITY_SOURCE.DEV_LOGIN })).toBe(true);
    expect(isTrustedIdentity({ source: IDENTITY_SOURCE.DEFAULT })).toBe(false);
    expect(isTrustedIdentity({ source: IDENTITY_SOURCE.ANONYMOUS })).toBe(false);
    expect(isTrustedIdentity(null)).toBe(false);
  });
});
