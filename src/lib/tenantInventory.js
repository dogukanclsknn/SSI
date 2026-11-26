// SSI — Multi-tenancy, phase 2: which team a Harbor image belongs to, and who may see it.
//
// Option A of the design (shared Harbor project, one folder per team): a team's images live
// under its onboard folder (default `onboarded/<team>`) and its published images under its
// approved folder (default `approved/<team>`). The 'default' team keeps today's folders
// (`onboarded/`, `approved/`). Folders nest, so an image belongs to the team with the
// longest matching folder: `onboarded/payments/redis` is the payments team's, not the
// default team's. An image outside every team's folders stays with the default team.
// Option B (one Harbor project per team) only changes the values in the team record.
//
// Visibility: a team sees its own images and scans; published (approved) images form the
// shared catalog and are visible to every team, labelled with the team that published them.
//
// Pure: no I/O.

import { DEFAULT_TENANT_ID, scopeIncludes, TenancyError } from './tenancy.js';

export const TENANT_AREAS = Object.freeze({ ONBOARDED: 'onboarded', APPROVED: 'approved' });

function text(value) {
  return value == null ? '' : String(value).trim();
}

function trimSlashes(value) {
  return text(value).toLowerCase().replace(/^\/+|\/+$/g, '');
}

// defaults: the platform targets of today's configuration
//   { onboarding: { registry, project, repositoryPrefix }, publish: { registry, project, repositoryPrefix } }
// Returns the team's onboarding and publish targets in the same shape. An empty field of
// the team's Harbor target inherits the platform value. A team other than 'default' that
// shares the platform project gets its own folder, `<platform folder>/<team id>`; a team
// with a project of its own (option B) keeps the plain platform folder names there.
export function teamTargets(tenant, defaults) {
  const harbor = tenant?.harbor || {};
  const target = (platform, configuredPrefix) => {
    const project = text(harbor.project) || text(platform?.project);
    const base = trimSlashes(platform?.repositoryPrefix);
    const sharesPlatformProject = project.toLowerCase() === text(platform?.project).toLowerCase();
    const derived =
      tenant?.id === DEFAULT_TENANT_ID || !sharesPlatformProject ? base : [base, tenant?.id].filter(Boolean).join('/');
    return {
      registry: text(harbor.registry) || text(platform?.registry),
      project,
      repositoryPrefix: trimSlashes(configuredPrefix) || derived,
    };
  };
  return {
    onboarding: target(defaults?.onboarding, harbor.onboardPrefix),
    publish: target(defaults?.publish, harbor.approvedPrefix),
  };
}

// Every team's two Harbor folders: [{ tenantId, displayName, area, project, prefix }].
export function teamHarborAreas(tenants, defaults) {
  const areas = [];
  for (const tenant of Array.isArray(tenants) ? tenants : []) {
    const targets = teamTargets(tenant, defaults);
    for (const [area, target] of [
      [TENANT_AREAS.ONBOARDED, targets.onboarding],
      [TENANT_AREAS.APPROVED, targets.publish],
    ]) {
      if (!target.project || !target.repositoryPrefix) continue;
      areas.push({
        tenantId: tenant.id,
        displayName: tenant.displayName || tenant.id,
        area,
        project: target.project.toLowerCase(),
        prefix: target.repositoryPrefix,
      });
    }
  }
  return areas;
}

// Two teams can never share a folder (one image, one owner). Nested folders are allowed:
// the longest match decides.
export function assertDistinctHarborAreas(areas) {
  const seen = new Map();
  for (const item of areas) {
    const key = `${item.project}/${item.prefix}`;
    const other = seen.get(key);
    if (other && other.tenantId !== item.tenantId) {
      throw new TenancyError(409, `The Harbor folder ${key}/ is already used by team ${other.tenantId}.`);
    }
    if (other && other.area !== item.area) {
      throw new TenancyError(409, `A team's onboard and approved folders must differ (${key}/).`);
    }
    seen.set(key, item);
  }
}

function inFolder(repository, prefix) {
  return repository === prefix || repository.startsWith(`${prefix}/`);
}

// The team and area of a Harbor repository ({ project, repository } with the repository
// relative to its project). Falls back to the default team with no area.
export function ownerOfRepository({ project, repository } = {}, areas = []) {
  const projectName = text(project).toLowerCase();
  const repositoryName = trimSlashes(repository);
  let best = null;
  for (const item of areas) {
    if (item.project !== projectName || !inFolder(repositoryName, item.prefix)) continue;
    if (!best || item.prefix.length > best.prefix.length) best = item;
  }
  if (!best) {
    const fallback = areas.find((item) => item.tenantId === DEFAULT_TENANT_ID);
    return { tenantId: DEFAULT_TENANT_ID, tenantName: fallback?.displayName || DEFAULT_TENANT_ID, tenantArea: null };
  }
  return { tenantId: best.tenantId, tenantName: best.displayName, tenantArea: best.area };
}

// Adds { tenantId, tenantName, tenantArea } to every item; `locate(item)` returns its
// { project, repository }.
export function annotateOwnership(items, areas, locate) {
  return (Array.isArray(items) ? items : []).map((item) => ({ ...item, ...ownerOfRepository(locate(item), areas) }));
}

// Inventory: the scope's own images plus the shared catalog of published images.
export function isVisibleImage(image, scope) {
  return scopeIncludes(scope, image?.tenantId) || image?.tenantArea === TENANT_AREAS.APPROVED;
}

// Scan results (and the CVE queue built from them) stay inside the team.
export function isVisibleScanReport(report, scope) {
  return scopeIncludes(scope, report?.tenantId);
}
