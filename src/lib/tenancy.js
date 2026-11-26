// SSI — Multi-tenancy: teams ("tenants"), team roles and the tenant scope of every request.
//
// A tenant is a team. Team-owned records (onboarding, remediation jobs, publish requests,
// risk acceptances, audit) carry a tenant id; the data store only reads and writes inside
// a tenant scope (ALL_TENANTS or a list of tenant ids), and a call without a scope fails
// (fail-closed), so a route cannot forget the tenant filter.
//
// Who may act in a team: platform administrators (users.role = 'admin') act in every team;
// everyone else acts through a team membership whose role (viewer / operator / approver)
// replaces the global role for that request. While SSI_MULTI_TENANCY is off, everything is
// the 'default' team and the global role applies, exactly as before.
//
// Pure: no I/O.

export const DEFAULT_TENANT_ID = 'default';
export const TENANT_ROLES = ['viewer', 'operator', 'approver'];
export const TENANT_STATUSES = ['active', 'disabled'];
export const MEMBERSHIP_SOURCES = ['manual', 'directory'];
// Request header the console sends with the selected team (lower case: Node's header keys).
export const TENANT_HEADER = 'x-ssi-tenant';
export const PLATFORM_ADMIN_ROLE = 'admin';

const TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$/;
const REGISTRY_PATTERN = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?$/;
const PROJECT_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const PREFIX_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/;
const CONTROL_CHARACTER = /[\p{Cc}\p{Cf}\u2028\u2029]/u;
const MAX_DISPLAY_NAME_LENGTH = 128;

export class TenancyError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = 'TenancyError';
    this.statusCode = statusCode;
  }
}

function text(value) {
  return value == null ? '' : String(value).trim();
}

function booleanFromEnvironment(value, fallback = false) {
  if (value == null || text(value) === '') return fallback;
  return text(value).toLowerCase() === 'true';
}

export function normalizeTenantId(value) {
  return text(value).toLowerCase();
}

export function isValidTenantId(value) {
  return TENANT_ID_PATTERN.test(value);
}

export function assertTenantId(value) {
  const id = normalizeTenantId(value);
  if (!isValidTenantId(id)) {
    throw new TenancyError(
      400,
      'A team id uses lower-case letters, digits and "-" (2 to 40 characters, starting and ending with a letter or digit).',
    );
  }
  return id;
}

// ---- Scopes ----------------------------------------------------------------------------

export const ALL_TENANTS = Object.freeze({ all: true, tenantIds: Object.freeze([]) });

export function tenantScope(tenantIds) {
  const ids = [...new Set((Array.isArray(tenantIds) ? tenantIds : [tenantIds]).map(normalizeTenantId))];
  if (ids.length === 0 || !ids.every(isValidTenantId)) {
    throw new TenancyError(500, 'A tenant scope needs at least one valid team id.');
  }
  return Object.freeze({ all: false, tenantIds: Object.freeze(ids) });
}

export function isScope(scope) {
  return (
    Boolean(scope) &&
    (scope.all === true ||
      (scope.all === false && Array.isArray(scope.tenantIds) && scope.tenantIds.length > 0))
  );
}

// Every data-store read and write calls this first.
export function assertScope(scope) {
  if (!isScope(scope)) throw new Error('A tenant scope is required for this data operation (fail-closed).');
  return scope;
}

export function scopeIncludes(scope, tenantId) {
  assertScope(scope);
  return scope.all === true || scope.tenantIds.includes(normalizeTenantId(tenantId));
}

// The tenant a new record is written to; a record without one is refused.
export function recordTenantId(record) {
  const id = normalizeTenantId(record?.tenantId);
  if (!isValidTenantId(id)) throw new Error('A record must carry a valid tenantId before it is stored.');
  return id;
}

// ---- Configuration ---------------------------------------------------------------------

// rbacEnforced: team permissions mean nothing while RBAC is off (every caller is admin), so
// multi-tenancy refuses to start without it.
export function buildTenancyConfig(environment = {}, { rbacEnforced = true } = {}) {
  const enabled = booleanFromEnvironment(environment.SSI_MULTI_TENANCY, false);
  if (enabled && !rbacEnforced) {
    throw new Error('Refusing to start: SSI_MULTI_TENANCY=true requires SSI_RBAC_ENFORCED=true.');
  }
  return Object.freeze({ enabled });
}

// ---- Request context -------------------------------------------------------------------

// Resolves the team a request acts in and the roles that apply there.
//   identity     — resolved caller (subject, roles: the global user role)
//   requested    — the X-SSI-Tenant header value ('' when absent)
//   memberships  — the caller's memberships [{ tenantId, role }]
//   getTenant(id)— tenant record or null
// Returns { enabled, tenantId (null = no single team), scope, roles, platformAdmin,
// selectionRequired } — scope null means the request may not read or write team data.
// Refusals are TenancyError(403); the caller audits them.
export function resolveTenantContext({ config, identity, requested = '', memberships = [], getTenant }) {
  const globalRoles = Array.isArray(identity?.roles) ? identity.roles : [];
  const platformAdmin = globalRoles.includes(PLATFORM_ADMIN_ROLE);

  if (!config?.enabled) {
    return {
      enabled: false,
      tenantId: DEFAULT_TENANT_ID,
      scope: ALL_TENANTS,
      roles: globalRoles,
      platformAdmin,
      selectionRequired: false,
    };
  }

  const requestedId = normalizeTenantId(requested);
  const active = memberships.filter((item) => getTenant(item.tenantId)?.status === 'active');

  if (requestedId) {
    if (!isValidTenantId(requestedId)) throw new TenancyError(400, 'The selected team id is invalid.');
    const tenant = getTenant(requestedId);
    if (platformAdmin) {
      if (!tenant) throw new TenancyError(404, 'Team not found.');
      return {
        enabled: true,
        tenantId: requestedId,
        scope: tenantScope([requestedId]),
        roles: [PLATFORM_ADMIN_ROLE],
        platformAdmin,
        selectionRequired: false,
      };
    }
    // Same answer for "no such team" and "not a member": team names do not leak.
    const membership = active.find((item) => item.tenantId === requestedId);
    if (!tenant || !membership) throw new TenancyError(403, 'You are not a member of the selected team.');
    return {
      enabled: true,
      tenantId: requestedId,
      scope: tenantScope([requestedId]),
      roles: [membership.role],
      platformAdmin,
      selectionRequired: false,
    };
  }

  if (platformAdmin) {
    return {
      enabled: true,
      tenantId: null,
      scope: ALL_TENANTS,
      roles: [PLATFORM_ADMIN_ROLE],
      platformAdmin,
      selectionRequired: false,
    };
  }
  if (active.length === 1) {
    const [only] = active;
    return {
      enabled: true,
      tenantId: only.tenantId,
      scope: tenantScope([only.tenantId]),
      roles: [only.role],
      platformAdmin,
      selectionRequired: false,
    };
  }
  // Several teams and none selected, or no team at all: no team permissions.
  return { enabled: true, tenantId: null, scope: null, roles: [], platformAdmin, selectionRequired: active.length > 1 };
}

// A request that reads or writes team data needs a scope. Answers why it has none: a member
// of several teams must pick one; a user with no active team has no access at all.
export function assertTenantSelected(tenancy) {
  if (isScope(tenancy?.scope)) return tenancy.scope;
  if (tenancy?.selectionRequired) {
    throw new TenancyError(400, 'Select a team for this request (X-SSI-Tenant header).');
  }
  throw new TenancyError(403, 'You are not a member of an active team. Ask a platform administrator to add you to one.');
}

// The single team a create action writes to; a request that spans teams must pick one.
export function requireSingleTenant(tenancy) {
  const id = normalizeTenantId(tenancy?.tenantId);
  if (!isValidTenantId(id)) throw new TenancyError(400, 'Select a team for this action.');
  return id;
}

// ---- Tenant records --------------------------------------------------------------------

function validDisplayName(value) {
  const name = text(value);
  if (!name) throw new TenancyError(400, 'A team name is required.');
  if (name.length > MAX_DISPLAY_NAME_LENGTH) {
    throw new TenancyError(400, `A team name can be up to ${MAX_DISPLAY_NAME_LENGTH} characters.`);
  }
  if (CONTROL_CHARACTER.test(name)) throw new TenancyError(400, 'A team name must be one line of visible text.');
  return name;
}

function optionalField(value, pattern, label) {
  if (value == null || text(value) === '') return undefined;
  const normalized = text(value).toLowerCase().replace(/^\/+|\/+$/g, '');
  if (!pattern.test(normalized)) throw new TenancyError(400, `${label} is invalid.`);
  return normalized;
}

// A team's Harbor target. Every field is optional: an empty field inherits the platform
// default (today's single project), so the default team needs no configuration.
export function validateHarborTarget(value = {}) {
  if (value == null) return {};
  if (typeof value !== 'object' || Array.isArray(value)) throw new TenancyError(400, 'harbor must be an object.');
  const target = {
    registry: optionalField(value.registry, REGISTRY_PATTERN, 'Harbor registry'),
    project: optionalField(value.project, PROJECT_PATTERN, 'Harbor project'),
    onboardPrefix: optionalField(value.onboardPrefix, PREFIX_PATTERN, 'Onboard prefix'),
    approvedPrefix: optionalField(value.approvedPrefix, PREFIX_PATTERN, 'Approved prefix'),
  };
  return Object.fromEntries(Object.entries(target).filter(([, field]) => field !== undefined));
}

export function resolveHarborTarget(tenant, defaults = {}) {
  const harbor = tenant?.harbor || {};
  return {
    registry: harbor.registry || defaults.registry || '',
    project: harbor.project || defaults.project || '',
    onboardPrefix: harbor.onboardPrefix || defaults.onboardPrefix || '',
    approvedPrefix: harbor.approvedPrefix || defaults.approvedPrefix || '',
  };
}

export function validateNewTenant(input = {}) {
  return {
    id: assertTenantId(input.id),
    displayName: validDisplayName(input.displayName),
    status: 'active',
    harbor: validateHarborTarget(input.harbor),
  };
}

export function validateTenantChanges(changes = {}) {
  const next = {};
  if (changes.displayName !== undefined) next.displayName = validDisplayName(changes.displayName);
  if (changes.status !== undefined) {
    if (!TENANT_STATUSES.includes(changes.status)) throw new TenancyError(400, 'status must be active or disabled.');
    next.status = changes.status;
  }
  if (changes.harbor !== undefined) next.harbor = validateHarborTarget(changes.harbor);
  if (Object.keys(next).length === 0) throw new TenancyError(400, 'Nothing to change.');
  return next;
}

export function assertTenantRole(role) {
  if (!TENANT_ROLES.includes(role)) {
    throw new TenancyError(400, `A team role is one of: ${TENANT_ROLES.join(', ')}. Platform admins are set in Users.`);
  }
  return role;
}

// The default team cannot be disabled: the records that predate multi-tenancy live there.
export function assertTenantChangeAllowed(tenantId, changes) {
  if (tenantId === DEFAULT_TENANT_ID && changes.status === 'disabled') {
    throw new TenancyError(409, 'The default team cannot be disabled.');
  }
}
