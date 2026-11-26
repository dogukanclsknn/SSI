import { describe, expect, it } from 'vitest';
import {
  ALL_TENANTS,
  assertScope,
  assertTenantChangeAllowed,
  assertTenantId,
  assertTenantRole,
  assertTenantSelected,
  buildTenancyConfig,
  recordTenantId,
  requireSingleTenant,
  resolveHarborTarget,
  resolveTenantContext,
  scopeIncludes,
  TenancyError,
  tenantScope,
  validateHarborTarget,
  validateNewTenant,
  validateTenantChanges,
} from './tenancy.js';

const enabled = { enabled: true };
const tenants = {
  default: { id: 'default', status: 'active' },
  payments: { id: 'payments', status: 'active' },
  mobile: { id: 'mobile', status: 'active' },
  legacy: { id: 'legacy', status: 'disabled' },
};
const getTenant = (id) => tenants[id] || null;
const user = (roles = ['viewer']) => ({ subject: 'ayse', roles, authenticated: true });

function resolve(overrides = {}) {
  return resolveTenantContext({ config: enabled, identity: user(), getTenant, ...overrides });
}

function refusal(action) {
  try {
    action();
  } catch (error) {
    return error;
  }
  throw new Error('expected a refusal');
}

describe('team ids', () => {
  it('accepts lower-case DNS-label ids and normalizes case and spaces', () => {
    expect(assertTenantId(' Payments ')).toBe('payments');
    expect(assertTenantId('team-42')).toBe('team-42');
  });

  it.each(['', 'a', '-team', 'team-', 'team_x', 'ekip/1', 'x'.repeat(41), 'çekirdek'])('refuses %j', (value) => {
    expect(refusal(() => assertTenantId(value))).toMatchObject({ name: 'TenancyError', statusCode: 400 });
  });
});

describe('scopes (fail-closed)', () => {
  it('refuses a data operation without a scope', () => {
    for (const scope of [undefined, null, {}, { all: false, tenantIds: [] }, { tenantIds: ['default'] }]) {
      expect(() => assertScope(scope)).toThrow(/tenant scope is required/);
    }
  });

  it('builds frozen, de-duplicated scopes and refuses empty or invalid ones', () => {
    const scope = tenantScope(['payments', 'PAYMENTS', 'mobile']);
    expect(scope).toEqual({ all: false, tenantIds: ['payments', 'mobile'] });
    expect(Object.isFrozen(scope) && Object.isFrozen(scope.tenantIds)).toBe(true);
    expect(() => tenantScope([])).toThrow(TenancyError);
    expect(() => tenantScope(['ok', 'not valid'])).toThrow(TenancyError);
  });

  it('includes a record only when its tenant is in the scope', () => {
    expect(scopeIncludes(ALL_TENANTS, 'anything')).toBe(true);
    expect(scopeIncludes(tenantScope('payments'), 'payments')).toBe(true);
    expect(scopeIncludes(tenantScope('payments'), 'mobile')).toBe(false);
    expect(scopeIncludes(tenantScope('payments'), undefined)).toBe(false);
  });

  it('refuses to store a record without a valid tenant', () => {
    expect(recordTenantId({ tenantId: 'Payments' })).toBe('payments');
    expect(() => recordTenantId({})).toThrow(/valid tenantId/);
    expect(() => recordTenantId({ tenantId: '../x' })).toThrow(/valid tenantId/);
  });
});

describe('configuration', () => {
  it('is off by default', () => {
    expect(buildTenancyConfig({})).toEqual({ enabled: false });
    expect(buildTenancyConfig({ SSI_MULTI_TENANCY: 'false' })).toEqual({ enabled: false });
  });

  it('switches on with SSI_MULTI_TENANCY=true alone (the obsolete preview switch is ignored)', () => {
    expect(buildTenancyConfig({ SSI_MULTI_TENANCY: 'true' })).toEqual({ enabled: true });
    expect(buildTenancyConfig({ SSI_MULTI_TENANCY: 'true', SSI_MULTI_TENANCY_PREVIEW: 'false' })).toEqual({ enabled: true });
  });

  it('refuses to start enabled without RBAC enforcement', () => {
    expect(() => buildTenancyConfig({ SSI_MULTI_TENANCY: 'true' }, { rbacEnforced: false })).toThrow(
      /requires SSI_RBAC_ENFORCED=true/,
    );
  });
});

describe('resolveTenantContext', () => {
  it('changes nothing while multi-tenancy is off: default team, every record, global role', () => {
    const context = resolveTenantContext({ config: { enabled: false }, identity: user(['operator']), getTenant });
    expect(context).toMatchObject({ enabled: false, tenantId: 'default', scope: ALL_TENANTS, roles: ['operator'] });
  });

  it('ignores the team header while multi-tenancy is off', () => {
    const context = resolveTenantContext({
      config: { enabled: false },
      identity: user(['viewer']),
      requested: 'payments',
      getTenant,
    });
    expect(context.scope).toBe(ALL_TENANTS);
  });

  it('uses the role of the selected team, not the global role', () => {
    const context = resolve({
      identity: user(['viewer']),
      requested: 'payments',
      memberships: [
        { tenantId: 'payments', role: 'approver' },
        { tenantId: 'mobile', role: 'viewer' },
      ],
    });
    expect(context).toMatchObject({ tenantId: 'payments', roles: ['approver'], platformAdmin: false });
    expect(context.scope).toEqual({ all: false, tenantIds: ['payments'] });
  });

  it('selects the only active team when no header is sent', () => {
    const context = resolve({
      memberships: [
        { tenantId: 'payments', role: 'operator' },
        { tenantId: 'legacy', role: 'approver' },
      ],
    });
    expect(context).toMatchObject({ tenantId: 'payments', roles: ['operator'] });
  });

  it('gives no team permissions when several teams match and none is selected', () => {
    const context = resolve({
      memberships: [
        { tenantId: 'payments', role: 'operator' },
        { tenantId: 'mobile', role: 'viewer' },
      ],
    });
    expect(context).toMatchObject({ scope: null, roles: [], selectionRequired: true });
    expect(refusal(() => assertTenantSelected(context))).toMatchObject({ statusCode: 400 });
  });

  it('gives no access to a user without an active team', () => {
    const context = resolve({ memberships: [{ tenantId: 'legacy', role: 'approver' }] });
    expect(context).toMatchObject({ scope: null, roles: [], selectionRequired: false });
    expect(refusal(() => assertTenantSelected(context))).toMatchObject({ statusCode: 403 });
  });

  it('answers the same for an unknown team and a team the caller is not in (no team names leak)', () => {
    const memberships = [{ tenantId: 'payments', role: 'operator' }];
    const unknown = refusal(() => resolve({ requested: 'no-such-team', memberships }));
    const foreign = refusal(() => resolve({ requested: 'mobile', memberships }));
    const disabled = refusal(() => resolve({ requested: 'legacy', memberships: [{ tenantId: 'legacy', role: 'viewer' }] }));
    for (const error of [unknown, foreign, disabled]) {
      expect(error).toMatchObject({ name: 'TenancyError', statusCode: 403, message: unknown.message });
    }
  });

  it('refuses a malformed team header', () => {
    expect(refusal(() => resolve({ requested: 'a/b' }))).toMatchObject({ statusCode: 400 });
  });

  it('lets a platform administrator act in every team, or in the selected one', () => {
    const admin = user(['admin']);
    expect(resolve({ identity: admin })).toMatchObject({
      tenantId: null,
      scope: ALL_TENANTS,
      roles: ['admin'],
      platformAdmin: true,
    });
    const selected = resolve({ identity: admin, requested: 'legacy' });
    expect(selected).toMatchObject({ tenantId: 'legacy', roles: ['admin'] });
    expect(selected.scope).toEqual({ all: false, tenantIds: ['legacy'] });
    expect(refusal(() => resolve({ identity: admin, requested: 'missing' }))).toMatchObject({ statusCode: 404 });
  });

  it('requires a single team for an action that creates a record', () => {
    expect(requireSingleTenant({ tenantId: 'payments' })).toBe('payments');
    expect(refusal(() => requireSingleTenant({ tenantId: null }))).toMatchObject({ statusCode: 400 });
  });
});

describe('team records', () => {
  it('validates a new team and its optional Harbor target', () => {
    expect(
      validateNewTenant({
        id: 'Payments',
        displayName: ' Payments Team ',
        harbor: { project: 'payments', onboardPrefix: '/onboarded/', registry: '' },
      }),
    ).toEqual({
      id: 'payments',
      displayName: 'Payments Team',
      status: 'active',
      harbor: { project: 'payments', onboardPrefix: 'onboarded' },
    });
  });

  it.each([
    [{ id: 'ok', displayName: '' }, /name is required/],
    [{ id: 'ok', displayName: 'x'.repeat(129) }, /up to 128/],
    [{ id: 'ok', displayName: 'line\nbreak' }, /one line/],
    [{ id: 'ok', displayName: 'Team', harbor: 'project' }, /must be an object/],
    [{ id: 'ok', displayName: 'Team', harbor: { project: 'Bad Project' } }, /Harbor project is invalid/],
    [{ id: 'ok', displayName: 'Team', harbor: { approvedPrefix: 'approved/../x' } }, /Approved prefix is invalid/],
  ])('refuses %j', (input, message) => {
    expect(() => validateNewTenant(input)).toThrow(message);
  });

  it('accepts partial changes and refuses an empty or invalid change', () => {
    expect(validateTenantChanges({ status: 'disabled' })).toEqual({ status: 'disabled' });
    expect(() => validateTenantChanges({})).toThrow(/Nothing to change/);
    expect(() => validateTenantChanges({ status: 'archived' })).toThrow(/active or disabled/);
  });

  it('never disables the default team', () => {
    expect(refusal(() => assertTenantChangeAllowed('default', { status: 'disabled' }))).toMatchObject({
      statusCode: 409,
    });
    expect(() => assertTenantChangeAllowed('payments', { status: 'disabled' })).not.toThrow();
  });

  it('accepts only team roles (platform admins are set in Users)', () => {
    expect(assertTenantRole('approver')).toBe('approver');
    expect(() => assertTenantRole('admin')).toThrow(/Platform admins are set in Users/);
  });

  it('inherits the platform default for every Harbor field a team leaves empty', () => {
    const defaults = { registry: 'harbor.example', project: 'ssi-images', onboardPrefix: 'onboarded', approvedPrefix: 'approved' };
    expect(resolveHarborTarget({ harbor: {} }, defaults)).toEqual(defaults);
    expect(resolveHarborTarget({ harbor: { project: 'payments' } }, defaults)).toEqual({ ...defaults, project: 'payments' });
    expect(validateHarborTarget(null)).toEqual({});
  });
});
