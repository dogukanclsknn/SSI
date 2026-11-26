// SSI — Identity resolution (Phase 5: identity & authorization)
//
// Resolves the caller's identity (subject + roles + permissions) from a request.
// Where identity comes from is isolated here so enforcement and UI code never change
// when a new source is added (Open/Closed). `resolveIdentity` always returns the same
// shape, plus `source` so callers can tell how the subject was established.
//
// Identity sources, in precedence order (RBAC enforced):
//  1. session    — signed SSI session cookie (LDAP or local-admin sign-in). Roles and
//                  status are re-read live from the user store on every request; a
//                  token revoked at sign-out is ignored.
//  2. proxy      — authenticating reverse proxy (oauth2-proxy / Entra ID), only when
//                  SSI_TRUST_ACTOR_HEADER=true. Subject from X-Forwarded-User; roles are
//                  derived SERVER-SIDE from X-Forwarded-Groups (SSI_RBAC_GROUP_ROLE_MAP)
//                  or SSI_RBAC_ROLE_BINDINGS. A client-supplied role list is never read.
//  3. dev-login  — the demo identity picker, only when SSI_DEV_LOGIN=true. Honours
//                  X-SSI-Actor-Id / X-SSI-Actor-Roles. This is NOT authentication.
//  4. anonymous  — nothing trusted: no permissions (401 at the choke-point).
//
// With RBAC enforcement off every caller gets the default roles and a wildcard
// permission; the subject from a trusted source is still carried for the audit trail.

import { parseRoles, permissionsForRoles } from '../lib/rbac.js';
import { readSessionCookie, verifySession } from './session.js';

export const IDENTITY_SOURCE = Object.freeze({
  SESSION: 'session',
  PROXY: 'proxy',
  DEV_LOGIN: 'dev-login',
  DEFAULT: 'default',
  ANONYMOUS: 'anonymous',
});

const TRUSTED_SOURCES = new Set([IDENTITY_SOURCE.SESSION, IDENTITY_SOURCE.PROXY, IDENTITY_SOURCE.DEV_LOGIN]);
const MAX_SUBJECT_LENGTH = 200;

function headerValue(request, name) {
  const headers = request?.headers || {};
  const value = headers[name];
  return String(Array.isArray(value) ? value[0] : value || '').trim();
}

function rolesFromGroups(groupsHeader, groupRoleMap) {
  const groups = groupsHeader
    .split(',')
    .map((group) => group.trim().toLowerCase())
    .filter(Boolean);
  return [...new Set(groups.flatMap((group) => groupRoleMap[group] || []))];
}

function boundRoles(subject, roleBindings) {
  return roleBindings[subject.toLowerCase()] || [];
}

// Returns the identity asserted by request headers, or null when no header source is
// trusted. The proxy path wins over dev-login: if both are (mis)configured, the
// identity the proxy authenticated is the one that counts.
function headerClaim(request, { trustActorHeader, devLogin, roleBindings, groupRoleMap }) {
  if (trustActorHeader) {
    const forwardedUser = headerValue(request, 'x-forwarded-user');
    if (forwardedUser) {
      const subject = forwardedUser.slice(0, MAX_SUBJECT_LENGTH);
      const groupsHeader = headerValue(request, 'x-forwarded-groups');
      let roles = groupsHeader ? rolesFromGroups(groupsHeader, groupRoleMap) : [];
      if (roles.length === 0) roles = boundRoles(subject, roleBindings);
      return { source: IDENTITY_SOURCE.PROXY, subject, roles };
    }
  }

  if (devLogin) {
    const actorId = headerValue(request, 'x-ssi-actor-id');
    if (actorId) {
      const subject = actorId.slice(0, MAX_SUBJECT_LENGTH);
      let roles = parseRoles(headerValue(request, 'x-ssi-actor-roles'));
      if (roles.length === 0) roles = boundRoles(subject, roleBindings);
      return { source: IDENTITY_SOURCE.DEV_LOGIN, subject, roles };
    }
  }

  return null;
}

function anonymousIdentity() {
  return {
    subject: 'anonymous',
    roles: [],
    permissions: [],
    authenticated: false,
    enforced: true,
    source: IDENTITY_SOURCE.ANONYMOUS,
  };
}

export function isTrustedIdentity(identity) {
  return TRUSTED_SOURCES.has(identity?.source);
}

export function resolveIdentity(
  request,
  {
    enforced = false,
    trustActorHeader = false,
    devLogin = false,
    defaultActorId = 'ssi-api',
    defaultRoles = ['admin'],
    roleBindings = {},
    groupRoleMap = {},
    sessionSecret = '',
    resolveUser = null,
    isSessionRevoked = null,
  } = {},
) {
  const claim = headerClaim(request, { trustActorHeader, devLogin, roleBindings, groupRoleMap });

  if (!enforced) {
    return {
      subject: claim ? claim.subject : defaultActorId,
      roles: [...defaultRoles],
      permissions: ['*'],
      authenticated: false,
      enforced: false,
      source: claim ? claim.source : IDENTITY_SOURCE.DEFAULT,
    };
  }

  const sessionToken = readSessionCookie(headerValue(request, 'cookie'));
  const verified = sessionToken ? verifySession(sessionToken, sessionSecret) : null;
  // A signed-out (revoked) token is treated exactly like no token at all.
  const session = verified && !(isSessionRevoked && isSessionRevoked(verified.jti)) ? verified : null;
  if (session && session.sub) {
    // Role and status are verified live: if an admin changes a user's role or disables
    // the account, the existing cookie reflects it immediately.
    let roles = session.roles;
    if (resolveUser) {
      const current = resolveUser(session.sub);
      if (!current || current.status !== 'active') return anonymousIdentity();
      roles = [current.role];
    }
    return {
      subject: session.sub.slice(0, MAX_SUBJECT_LENGTH),
      roles,
      permissions: permissionsForRoles(roles),
      authenticated: true,
      enforced: true,
      source: IDENTITY_SOURCE.SESSION,
    };
  }

  if (!claim) return anonymousIdentity();

  return {
    subject: claim.subject,
    roles: claim.roles,
    permissions: permissionsForRoles(claim.roles),
    authenticated: true,
    enforced: true,
    source: claim.source,
  };
}
