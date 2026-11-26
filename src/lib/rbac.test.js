import { describe, expect, it } from 'vitest';
import {
  ROLES,
  RbacError,
  authorizePermission,
  parseRoleBindings,
  parseRoles,
  permissionForRoute,
  permissionsForRoles,
  isMachineRoute,
} from './rbac.js';

const parts = (path) => ['api', 'v1', ...path.split('/').filter(Boolean)];

describe('parseRoles / parseRoleBindings', () => {
  it('rolleri ayrıştırır, benzersiz ve küçük harf yapar', () => {
    expect(parseRoles(' Operator , approver ,operator')).toEqual(['operator', 'approver']);
  });
  it('subject:rol bağlamalarını ayrıştırır (| veya , ile çoklu rol)', () => {
    expect(parseRoleBindings('alice:approver, bob:operator|admin')).toEqual({
      alice: ['approver'],
      bob: ['operator', 'admin'],
    });
  });
});

describe('permissionsForRoles', () => {
  it('operator plan/manage/onboarding/request izinlerini taşır, approve taşımaz', () => {
    const perms = permissionsForRoles(['operator']);
    expect(perms).toContain('remediation:plan');
    expect(perms).toContain('publish:request');
    expect(perms).toContain('onboarding:create');
    expect(perms).not.toContain('publish:approve');
  });
  it('approver publish:approve taşır, plan/request taşımaz (görev ayrılığı)', () => {
    const perms = permissionsForRoles(['approver']);
    expect(perms).toContain('publish:approve');
    expect(perms).not.toContain('publish:request');
    expect(perms).not.toContain('remediation:plan');
  });
  it('admin joker taşır', () => {
    expect(permissionsForRoles([ROLES.ADMIN])).toEqual(['*']);
  });
  it('bilinmeyen rol yok sayılır', () => {
    expect(permissionsForRoles(['nope'])).toEqual([]);
  });
});

describe('permissionForRoute', () => {
  it('public ve makine-arası route muaf (null)', () => {
    expect(permissionForRoute('GET', parts('/health'))).toBeNull();
    expect(permissionForRoute('GET', parts('/session'))).toBeNull();
    expect(permissionForRoute('POST', parts('/remediation/RM-1/worker-evidence'))).toBeNull();
    expect(permissionForRoute('POST', parts('/remediation/RM-1/worker-supply-chain-evidence'))).toBeNull();
    expect(permissionForRoute('POST', parts('/remediation/RM-1/worker-candidate-test'))).toBeNull();
    expect(permissionForRoute('POST', parts('/remediation/RM-1/worker-canonical-report'))).toBeNull();
    expect(permissionForRoute('POST', parts('/publish-requests/PUB-1/receipt'))).toBeNull();
    expect(permissionForRoute('POST', parts('/onboarding/ONB-1/import-receipt'))).toBeNull();
    expect(permissionForRoute('GET', parts('/onboarding/ONB-1/worker-handoff'))).toBeNull();
  });
  it('mutasyonlar doğru izinleri ister', () => {
    expect(permissionForRoute('POST', parts('/images/x/remediation'))).toBe('remediation:plan');
    expect(permissionForRoute('POST', parts('/remediation/RM-1/canonical-report'))).toBe('remediation:manage');
    expect(permissionForRoute('POST', parts('/remediation/RM-1/supply-chain-evidence'))).toBe('remediation:manage');
    expect(permissionForRoute('POST', parts('/remediation/RM-1/candidate-test'))).toBe('remediation:manage');
    expect(permissionForRoute('POST', parts('/remediation/RM-1/consumer-acceptance'))).toBe('remediation:accept');
    expect(permissionForRoute('POST', parts('/publish-requests'))).toBe('publish:request');
    expect(permissionForRoute('POST', parts('/publish-requests/PUB-1/approve'))).toBe('publish:approve');
    expect(permissionForRoute('POST', parts('/onboarding'))).toBe('onboarding:create');
  });
  it('starting a worker pipeline needs remediation:manage; its runs are a remediation read', () => {
    expect(permissionForRoute('POST', parts('/remediation/RM-DRY-0004/pipeline-runs'))).toBe('remediation:manage');
    expect(permissionForRoute('GET', parts('/remediation/RM-DRY-0004/pipeline-runs'))).toBe('remediation:read');
  });

  it('starts onboarding, publish and inspection pipelines with the permission of that step', () => {
    expect(permissionForRoute('POST', parts('/onboarding/ONB-1/pipeline-runs'))).toBe('onboarding:create');
    expect(permissionForRoute('POST', parts('/publish-requests/PUB-1/pipeline-runs'))).toBe('publish:approve');
    expect(permissionForRoute('POST', parts('/scans/pipeline-runs'))).toBe('remediation:manage');
    expect(permissionForRoute('GET', parts('/publish-requests/PUB-1/pipeline-runs'))).toBe('publish:read');
    expect(permissionForRoute('GET', parts('/scans/pipeline-runs'))).toBe('scan:read');
  });

  it('the Azure DevOps integration status is for platform administrators only', () => {
    expect(permissionForRoute('GET', parts('/integrations/azure-devops'))).toBe('system:admin');
    expect(permissionForRoute('POST', parts('/integrations/azure-devops'))).toBe('system:admin');
  });
  it('bilinmeyen mutasyon admin-only (system:admin)', () => {
    expect(permissionForRoute('POST', parts('/something-new'))).toBe('system:admin');
  });
  it('okumalar :read izinleri ister', () => {
    expect(permissionForRoute('GET', parts('/images'))).toBe('inventory:read');
    expect(permissionForRoute('GET', parts('/onboarding'))).toBe('onboarding:read');
    expect(permissionForRoute('GET', parts('/audit-events'))).toBe('audit:read');
    expect(permissionForRoute('GET', parts('/publish-policy'))).toBe('publish:read');
  });
});

describe('authorizePermission', () => {
  const enforced = (permissions, authenticated = true) => ({ enforced: true, authenticated, permissions });

  it('muaf route (null izin) hiçbir şey yapmaz', () => {
    expect(() => authorizePermission(enforced([]), null)).not.toThrow();
  });
  it('enforce edilmeyen modda serbest (PoC)', () => {
    expect(() => authorizePermission({ enforced: false, authenticated: false, permissions: ['*'] }, 'publish:approve')).not.toThrow();
  });
  it('enforce + kimliksiz → 401', () => {
    try {
      authorizePermission(enforced([], false), 'inventory:read');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(RbacError);
      expect(e.statusCode).toBe(401);
    }
  });
  it('enforce + yetkisiz → 403', () => {
    try {
      authorizePermission(enforced(['inventory:read']), 'publish:approve');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e.statusCode).toBe(403);
    }
  });
  it('yetki varsa geçer, admin joker her şeye geçer', () => {
    expect(() => authorizePermission(enforced(['publish:approve']), 'publish:approve')).not.toThrow();
    expect(() => authorizePermission(enforced(['*']), 'system:admin')).not.toThrow();
  });
});

describe('risk acceptance permissions', () => {
  it('every role reads exceptions; operators request; approvers decide', () => {
    expect(permissionsForRoles(['viewer'])).toContain('exception:read');
    expect(permissionsForRoles(['operator'])).toEqual(expect.arrayContaining(['exception:read', 'exception:request']));
    expect(permissionsForRoles(['operator'])).not.toContain('exception:approve');
    expect(permissionsForRoles(['approver'])).toContain('exception:approve');
    expect(permissionsForRoles(['approver'])).not.toContain('exception:request');
  });

  it('maps the exception routes', () => {
    expect(permissionForRoute('GET', parts('exceptions'))).toBe('exception:read');
    expect(permissionForRoute('POST', parts('exceptions'))).toBe('exception:request');
    for (const action of ['approve', 'reject', 'revoke']) {
      expect(permissionForRoute('POST', parts(`exceptions/EXC-0001/${action}`))).toBe('exception:approve');
    }
    expect(permissionForRoute('POST', parts('exceptions/EXC-0001/delete'))).toBe('system:admin');
  });
});

describe('consumer acceptance permission', () => {
  it('operators and approvers can record a consumer decision; viewers cannot', () => {
    expect(permissionsForRoles([ROLES.OPERATOR])).toContain('remediation:accept');
    expect(permissionsForRoles([ROLES.APPROVER])).toContain('remediation:accept');
    expect(permissionsForRoles([ROLES.VIEWER])).not.toContain('remediation:accept');
  });
});

describe('publish lifecycle permissions', () => {
  it('reject and withdraw need publish:approve, like approve', () => {
    for (const action of ['approve', 'reject', 'withdraw']) {
      expect(permissionForRoute('POST', parts(`/publish-requests/PUB-0012/${action}`))).toBe('publish:approve');
    }
    expect(permissionsForRoles([ROLES.OPERATOR])).not.toContain('publish:approve');
    expect(permissionsForRoles([ROLES.APPROVER])).toContain('publish:approve');
  });
});

describe('team administration and machine routes', () => {
  it('requires tenant:manage for every team route, which only the admin wildcard carries', () => {
    for (const [method, path] of [
      ['GET', '/tenants'],
      ['POST', '/tenants'],
      ['PATCH', '/tenants/payments'],
      ['GET', '/tenants/payments/members'],
      ['PUT', '/tenants/payments/members/ayse'],
      ['DELETE', '/tenants/payments/members/ayse'],
    ]) {
      expect(permissionForRoute(method, parts(path))).toBe('tenant:manage');
    }
    expect(permissionsForRoles(['approver', 'operator', 'viewer'])).not.toContain('tenant:manage');
    expect(() => authorizePermission({ enforced: true, authenticated: true, permissions: ['*'] }, 'tenant:manage')).not.toThrow();
  });

  it('lists exactly the token/HMAC worker callbacks as machine routes', () => {
    expect(isMachineRoute('POST', parts('/remediation/RM-DRY-1/worker-evidence'))).toBe(true);
    expect(isMachineRoute('GET', parts('/publish-requests/PUB-1/worker-handoff'))).toBe(true);
    expect(isMachineRoute('POST', parts('/publish-requests/PUB-1/receipt'))).toBe(true);
    // A user route with a similar name is not a machine route.
    expect(isMachineRoute('GET', parts('/remediation/RM-DRY-1/worker-handoff'))).toBe(false);
    expect(isMachineRoute('POST', parts('/remediation/RM-DRY-1/supply-chain-evidence'))).toBe(false);
    expect(isMachineRoute('GET', parts('/publish-requests/PUB-1/receipt'))).toBe(false);
  });
});
