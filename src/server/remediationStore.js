import { randomUUID } from 'node:crypto';
import { createPostgresPool } from './database.js';
import { exceptionScopesOverlap, isExceptionOpen } from '../lib/policyExceptions.js';
import { assertScope, isValidTenantId, normalizeTenantId, recordTenantId, scopeIncludes } from '../lib/tenancy.js';
import {
  AUDIT_CATEGORIES,
  AUDIT_OTHER_CATEGORY,
  auditCategoryOf,
  auditSqlConditions,
  auditSqlCursorCondition,
  compareAuditEvents,
  encodeAuditCursor,
  isBeforeCursor,
  matchesAuditFilters,
  micros,
} from '../lib/auditQuery.js';

// Tenant scope (src/lib/tenancy.js). Every read and write of a team-owned record takes the
// request's scope as its last argument and refuses to run without one (fail-closed). Reads
// return only records inside the scope; a record is written only to its own tenant, which
// must be inside the scope, and a stored record never moves to another tenant. In Postgres
// the tenant_id column is the single source of truth: it is not duplicated into the JSON
// document and is mapped back to `tenantId` on read. ID sequences and appendAuditEvent are
// platform-wide and take no scope.

const digestPattern = /^sha256:[a-f0-9]{64}$/;
const sensitiveKeyPattern = /(authorization|cookie|password|secret|token|credential)/i;

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

export function redactAuditMetadata(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object') return value;
  if (seen.has(value)) return '[Circular]';
  seen.add(value);

  if (Array.isArray(value)) return value.map((item) => redactAuditMetadata(item, seen));

  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      sensitiveKeyPattern.test(key) ? '[REDACTED]' : redactAuditMetadata(item, seen),
    ]),
  );
}

export function buildAuditEvent({
  tenantId = null,
  eventType,
  action,
  actorId,
  resourceType,
  resourceId,
  correlationId,
  outcome = 'success',
  severity = 'info',
  summary,
  metadata = {},
  occurredAt = new Date().toISOString(),
}) {
  return {
    id: randomUUID(),
    tenantId,
    eventType,
    action,
    actorId,
    resourceType,
    resourceId,
    correlationId,
    outcome,
    severity,
    summary,
    metadata: redactAuditMetadata(metadata),
    occurredAt,
  };
}

export class RemediationStoreConflictError extends Error {
  constructor(message) {
    super(message);
    this.statusCode = 409;
  }
}

// Onboarding requests a worker may still pick up or finish (src/lib/onboarding.js).
const OPEN_ONBOARDING_STATUSES = ['Requested', 'Importing'];

function openOnboardingConflict(existingId, targetReference) {
  const error = new RemediationStoreConflictError(
    `An open onboarding request (${existingId}) already exists for ${targetReference}. Wait for it to finish or cancel it first.`,
  );
  error.existingId = existingId;
  return error;
}

// A write outside the request's scope is a programming error, never a client error: it is
// answered as an unexpected 500 and logged under the correlation ID.
function writableTenantId(scope, record) {
  assertScope(scope);
  const tenantId = recordTenantId(record);
  if (!scopeIncludes(scope, tenantId)) {
    throw new Error(`Refusing to write a record of team ${tenantId} outside the request's tenant scope.`);
  }
  return tenantId;
}

function assertSameTenant(current, next, label) {
  if (recordTenantId(next) !== recordTenantId(current)) {
    throw new Error(`A ${label} update must not change the record's team`);
  }
}

function scopeFilter(scope) {
  assertScope(scope);
  return (record) => scopeIncludes(scope, record?.tenantId);
}

// The tenant of an audit event: the explicit one, else the tenant of the record it is
// written with. Platform events (sign-in, user management) carry none.
function auditForTenant(event, tenantId) {
  if (!event) return event;
  return { ...event, tenantId: event.tenantId ?? tenantId ?? null };
}

function auditTenantId(event) {
  if (event?.tenantId == null) return null;
  const tenantId = normalizeTenantId(event.tenantId);
  if (!isValidTenantId(tenantId)) throw new Error('An audit event carries an invalid tenantId');
  return tenantId;
}

function overlappingOpenException(exceptions, candidate) {
  return exceptions.find(
    (item) => item.id !== candidate.id && isExceptionOpen(item) && exceptionScopesOverlap(item, candidate),
  );
}

function openExceptionConflict(existing) {
  return new RemediationStoreConflictError(
    `${existing.id} already covers ${existing.cve} in ${existing.repository} (${existing.status}).`,
  );
}

class MemoryRemediationStore {
  constructor() {
    this.driver = 'memory';
    this.jobs = [];
    this.publishRequests = [];
    this.onboardingRequests = [];
    this.exceptions = [];
    this.auditEvents = [];
    this.evidenceByOutput = new Map();
    this.imageInspections = new Map(); // scan reference → ssi.image-inspection/v1 record
    this.resourceRuns = new Map(); // "<type>:<id>" → Azure DevOps run records, newest first
    this.osTemplateBuilds = []; // OS template build requests (OST-…), newest first
    this.sequences = { dry: 1, execution: 1, publish: 1, onboarding: 1, exception: 1, osTemplate: 1 };
    // Per-job promise queue: serializes updateJobWith like the Postgres row lock does.
    this.jobLocks = new Map();
  }

  async initialize() {}
  async close() {}

  async health() {
    return { status: 'ok', driver: this.driver };
  }

  async nextJobId(kind) {
    const prefix = kind === 'execution' ? 'RM-EXEC' : 'RM-DRY';
    const key = kind === 'execution' ? 'execution' : 'dry';
    const value = this.sequences[key];
    this.sequences[key] += 1;
    return `${prefix}-${String(value).padStart(4, '0')}`;
  }

  async nextPublishRequestId() {
    const value = this.sequences.publish;
    this.sequences.publish += 1;
    return `PUB-${String(value).padStart(4, '0')}`;
  }

  async nextOnboardingId() {
    const value = this.sequences.onboarding;
    this.sequences.onboarding += 1;
    return `ONB-${String(value).padStart(4, '0')}`;
  }

  async listOnboardingRequests(scope) {
    return clone(this.onboardingRequests.filter(scopeFilter(scope)));
  }

  async nextExceptionId() {
    const value = this.sequences.exception;
    this.sequences.exception += 1;
    return `EXC-${String(value).padStart(4, '0')}`;
  }

  async listExceptions(scope) {
    return clone(this.exceptions.filter(scopeFilter(scope)));
  }

  async getException(id, scope) {
    const visible = scopeFilter(scope);
    return clone(this.exceptions.find((item) => item.id === id && visible(item)) || null);
  }

  async createException(exception, auditEvent, scope) {
    const tenantId = writableTenantId(scope, exception);
    if (this.exceptions.some((item) => item.id === exception.id)) {
      throw new RemediationStoreConflictError(`Exception ${exception.id} already exists`);
    }
    // Risk acceptances belong to a team: only the team's own open exceptions overlap.
    const existing = overlappingOpenException(
      this.exceptions.filter((item) => item.tenantId === tenantId),
      exception,
    );
    if (existing) throw openExceptionConflict(existing);
    const stored = { ...clone(exception), tenantId, rowVersion: 1 };
    this.exceptions.unshift(stored);
    if (auditEvent) this.auditEvents.unshift(clone(auditForTenant(auditEvent, tenantId)));
    return clone(stored);
  }

  async updateException(exception, auditEvent, scope) {
    const tenantId = writableTenantId(scope, exception);
    const index = this.exceptions.findIndex((item) => item.id === exception.id && item.tenantId === tenantId);
    if (index === -1) return null;
    if (Number(exception.rowVersion) !== Number(this.exceptions[index].rowVersion)) {
      throw new RemediationStoreConflictError(`Exception ${exception.id} changed while this operation was in progress`);
    }
    const stored = { ...clone(exception), tenantId, rowVersion: Number(this.exceptions[index].rowVersion) + 1 };
    this.exceptions[index] = stored;
    if (auditEvent) this.auditEvents.unshift(clone(auditForTenant(auditEvent, tenantId)));
    return clone(stored);
  }

  async getOnboardingRequest(id, scope) {
    const visible = scopeFilter(scope);
    return clone(this.onboardingRequests.find((request) => request.id === id && visible(request)) || null);
  }

  async createOnboardingRequest(request, auditEvent, scope) {
    const tenantId = writableTenantId(scope, request);
    if (this.onboardingRequests.some((item) => item.id === request.id)) {
      throw new RemediationStoreConflictError(`Onboarding request ${request.id} already exists`);
    }
    const open = this.onboardingRequests.find(
      (item) =>
        item.tenantId === tenantId &&
        item.target?.tagReference === request.target?.tagReference &&
        OPEN_ONBOARDING_STATUSES.includes(item.status),
    );
    if (open) throw openOnboardingConflict(open.id, request.target.tagReference);
    const stored = { ...clone(request), tenantId };
    this.onboardingRequests.unshift(stored);
    if (auditEvent) this.auditEvents.unshift(clone(auditForTenant(auditEvent, tenantId)));
    return clone(stored);
  }

  // Read-decide-write of one onboarding request, serialized per request like the Postgres row
  // lock: decide(current) returns { request, auditEvent } or null (nothing to change).
  async updateOnboardingRequestWith(id, decide, scope) {
    return this.withJobLock(`onboarding:${id}`, async () => {
      const current = await this.getOnboardingRequest(id, scope);
      if (!current) return null;
      const outcome = await decide(current);
      if (!outcome) return { request: current, changed: false };
      if (outcome.request.id !== id) throw new Error('An onboarding update must not change the request ID');
      const stored = await this.updateOnboardingRequest(outcome.request, outcome.auditEvent, scope);
      return { request: stored, changed: true };
    });
  }

  async updateOnboardingRequest(request, auditEvent, scope) {
    const tenantId = writableTenantId(scope, request);
    const index = this.onboardingRequests.findIndex((item) => item.id === request.id && item.tenantId === tenantId);
    if (index === -1) return null;
    const stored = { ...clone(request), tenantId };
    this.onboardingRequests[index] = stored;
    if (auditEvent) this.auditEvents.unshift(clone(auditForTenant(auditEvent, tenantId)));
    return clone(stored);
  }

  async listJobs(scope) {
    return clone(this.jobs.filter(scopeFilter(scope)));
  }

  async getJob(id, scope) {
    const visible = scopeFilter(scope);
    return clone(this.jobs.find((job) => job.id === id && visible(job)) || null);
  }

  async listPublishRequests(scope) {
    return clone(this.publishRequests.filter(scopeFilter(scope)));
  }

  async getPublishRequest(id, scope) {
    const visible = scopeFilter(scope);
    return clone(this.publishRequests.find((request) => request.id === id && visible(request)) || null);
  }

  async createPublishRequest(request, auditEvent, scope) {
    const tenantId = writableTenantId(scope, request);
    if (this.publishRequests.some((item) => item.id === request.id)) {
      throw new RemediationStoreConflictError(`Publish request ${request.id} already exists`);
    }
    if (
      this.publishRequests.some(
        (item) => item.jobId === request.jobId && item.target?.tagReference === request.target?.tagReference,
      )
    ) {
      throw new RemediationStoreConflictError(
        'A publish request already exists for this remediation job and target reference.',
      );
    }
    const stored = { ...clone(request), tenantId, rowVersion: 1 };
    this.publishRequests.unshift(stored);
    if (auditEvent) this.auditEvents.unshift(clone(auditForTenant(auditEvent, tenantId)));
    return clone(stored);
  }

  async updatePublishRequest(request, auditEvent, scope) {
    const tenantId = writableTenantId(scope, request);
    const index = this.publishRequests.findIndex((item) => item.id === request.id && item.tenantId === tenantId);
    if (index === -1) return null;
    if (Number(request.rowVersion) !== Number(this.publishRequests[index].rowVersion)) {
      throw new RemediationStoreConflictError(
        `Publish request ${request.id} changed while this operation was in progress`,
      );
    }
    const stored = {
      ...clone(request),
      tenantId,
      rowVersion: Number(this.publishRequests[index].rowVersion || 0) + 1,
    };
    this.publishRequests[index] = stored;
    if (auditEvent) this.auditEvents.unshift(clone(auditForTenant(auditEvent, tenantId)));
    return clone(stored);
  }

  async createJob(job, auditEvent, scope) {
    const tenantId = writableTenantId(scope, job);
    if (this.jobs.some((item) => item.id === job.id)) {
      throw new RemediationStoreConflictError(`Remediation job ${job.id} already exists`);
    }
    const stored = { ...clone(job), tenantId };
    this.jobs.unshift(stored);
    if (auditEvent) this.auditEvents.unshift(clone(auditForTenant(auditEvent, tenantId)));
    return clone(stored);
  }

  async updateJob(job, auditEvent, scope) {
    const tenantId = writableTenantId(scope, job);
    const index = this.jobs.findIndex((item) => item.id === job.id && item.tenantId === tenantId);
    if (index === -1) return null;
    const stored = { ...clone(job), tenantId };
    this.jobs[index] = stored;
    if (auditEvent) this.auditEvents.unshift(clone(auditForTenant(auditEvent, tenantId)));
    return clone(stored);
  }

  // Atomic read-modify-write (see PostgresRemediationStore.updateJobWith). Updates of the
  // same job run one after another, as under the Postgres row lock.
  async withJobLock(id, operation) {
    const previous = this.jobLocks.get(id) || Promise.resolve();
    let release;
    const turn = previous.then(() => new Promise((resolve) => (release = resolve)));
    this.jobLocks.set(id, turn);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (this.jobLocks.get(id) === turn) this.jobLocks.delete(id);
    }
  }

  async updateJobWith(id, mutate, scope) {
    const visible = scopeFilter(scope);
    return this.withJobLock(id, async () => {
      const current = this.jobs.find((item) => item.id === id && visible(item));
      if (!current) return null;
      const result = await mutate(clone(current));
      // Look the job up again: other writes may have shifted the array during the await.
      const index = this.jobs.findIndex((item) => item.id === id);
      if (!result?.job) return clone(this.jobs[index]);
      if (result.job.id !== id) throw new Error('A job update must not change the job ID');
      assertSameTenant(current, result.job, 'job');
      this.jobs[index] = clone(result.job);
      if (result.auditEvent) this.auditEvents.unshift(clone(auditForTenant(result.auditEvent, current.tenantId)));
      return clone(result.job);
    });
  }

  // Same contract as PostgresRemediationStore.updateJobAndPublishRequests. The decision runs
  // under the job lock; every row version is checked before anything is written, so a
  // conflict leaves no partial update behind.
  async updateJobAndPublishRequests(jobId, decide, scope) {
    const visible = scopeFilter(scope);
    return this.withJobLock(jobId, async () => {
      const current = this.jobs.find((item) => item.id === jobId && visible(item)) || null;
      const loadPublishRequests = async ({ digest, statuses = [], ids } = {}) =>
        clone(
          this.publishRequests
            .filter(visible)
            .filter((item) =>
              Array.isArray(ids)
                ? ids.includes(item.id)
                : item.source?.digest === digest && statuses.includes(item.status),
            )
            .sort((left, right) => left.id.localeCompare(right.id)),
        );
      const outcome = await decide(current ? clone(current) : null, loadPublishRequests);
      if (outcome?.job && outcome.job.id !== jobId) throw new Error('A job update must not change the job ID');
      if (outcome?.job) {
        if (!current) throw new Error('A job update needs the job to exist in the tenant scope');
        assertSameTenant(current, outcome.job, 'job');
      }
      const requests = outcome?.requests || [];
      const indexes = requests.map(({ request }) => {
        const tenantId = writableTenantId(scope, request);
        const index = this.publishRequests.findIndex((item) => item.id === request.id && item.tenantId === tenantId);
        if (index === -1 || Number(request.rowVersion) !== Number(this.publishRequests[index].rowVersion)) {
          throw new RemediationStoreConflictError(`Publish request ${request.id} changed while this operation was in progress`);
        }
        return index;
      });

      let job = current ? clone(current) : null;
      if (outcome?.job) {
        const jobIndex = this.jobs.findIndex((item) => item.id === jobId);
        this.jobs[jobIndex] = clone(outcome.job);
        if (outcome.jobAuditEvent) this.auditEvents.unshift(clone(auditForTenant(outcome.jobAuditEvent, current.tenantId)));
        job = clone(outcome.job);
      }
      const stored = requests.map(({ request, auditEvent }, position) => {
        const index = indexes[position];
        const next = { ...clone(request), rowVersion: Number(this.publishRequests[index].rowVersion || 0) + 1 };
        this.publishRequests[index] = next;
        if (auditEvent) this.auditEvents.unshift(clone(auditForTenant(auditEvent, next.tenantId)));
        return clone(next);
      });
      for (const event of outcome?.auditEvents || []) {
        this.auditEvents.unshift(clone(auditForTenant(event, current?.tenantId)));
      }
      return { job, requests: stored };
    });
  }

  async acceptVerifiedEvidence({ dryRunJob, verifiedJob, evidence, evidenceDigest, auditEvent }, scope) {
    const tenantId = writableTenantId(scope, verifiedJob);
    const outputDigest = String(evidence.output?.digest || '').trim().toLowerCase();
    if (!digestPattern.test(outputDigest)) {
      throw new Error('Verification evidence output digest is invalid');
    }
    if (!dryRunJob || !this.jobs.some((job) => job.id === dryRunJob.id && job.tenantId === tenantId)) {
      throw new Error('Verification evidence references an unknown dry-run job');
    }
    const existing = this.evidenceByOutput.get(outputDigest);
    if (existing) {
      const registered = await this.getJob(existing.jobId, scope);
      if (existing.evidenceDigest !== evidenceDigest || !registered) {
        throw new RemediationStoreConflictError(
          'A different verification evidence document is already registered for this output digest.',
        );
      }
      return { job: registered, created: false };
    }

    const stored = { ...clone(verifiedJob), tenantId };
    this.jobs.unshift(stored);
    this.evidenceByOutput.set(outputDigest, {
      evidenceDigest,
      jobId: verifiedJob.id,
      evidence: clone(evidence),
    });
    if (auditEvent) this.auditEvents.unshift(clone(auditForTenant(auditEvent, tenantId)));
    return { job: clone(stored), created: true };
  }

  // Image inspections (src/lib/imageInspection.js): keyed by scan reference, no tenant of their
  // own; callers only read inspections of scans the request can see.
  async getImageInspections(references) {
    return new Map(
      references
        .filter((reference) => this.imageInspections.has(reference))
        .map((reference) => [reference, clone(this.imageInspections.get(reference))]),
    );
  }

  // apply(current, record) decides (applyImageInspection); the record and its audit event are
  // stored together or not at all.
  async saveImageInspection(record, apply, auditEvent) {
    const current = this.imageInspections.get(record.reference) || null;
    const result = apply(clone(current), record);
    if (!result.changed) return { record: clone(current), changed: false };
    this.imageInspections.set(record.reference, clone(result.record));
    if (auditEvent) this.auditEvents.unshift({ ...clone(auditEvent), tenantId: auditTenantId(auditEvent) });
    return { record: clone(result.record), changed: true };
  }

  // Azure DevOps runs of a record without a document of its own (migration 012). Same contract
  // as PostgresRemediationStore: `decide(runs)` returns { runs: [new or changed run], auditEvent }
  // or null; the runs of one resource are decided one at a time.
  async listResourceRuns(resourceType, resourceId, { limit = 20 } = {}) {
    return clone((this.resourceRuns.get(`${resourceType}:${resourceId}`) || []).slice(0, limit));
  }

  async updateResourceRunsWith(resourceType, resourceId, decide) {
    const key = `${resourceType}:${resourceId}`;
    return this.withJobLock(`runs:${key}`, async () => {
      const current = clone(this.resourceRuns.get(key) || []);
      const outcome = await decide(current);
      if (!outcome?.runs?.length) return current;
      const byId = new Map(current.map((run) => [run.runId, run]));
      for (const run of outcome.runs) byId.set(run.runId, clone(run));
      const next = [...byId.values()].sort((left, right) =>
        String(right.requestedAt).localeCompare(String(left.requestedAt)),
      );
      this.resourceRuns.set(key, next);
      if (outcome.auditEvent) this.auditEvents.unshift(clone(outcome.auditEvent));
      return clone(next);
    });
  }

  // OS template build requests (src/lib/osTemplate.js, migration 013): platform-wide, no tenant.
  // Same contract as PostgresRemediationStore: `decide(current)` returns { build, auditEvent }
  // or null (nothing to write); one request is decided at a time.
  async nextOsTemplateBuildId() {
    const value = this.sequences.osTemplate;
    this.sequences.osTemplate += 1;
    return `OST-${String(value).padStart(4, '0')}`;
  }

  async listOsTemplateBuilds({ limit = 200 } = {}) {
    return clone(this.osTemplateBuilds.slice(0, limit));
  }

  async getOsTemplateBuild(id) {
    return clone(this.osTemplateBuilds.find((build) => build.id === id) || null);
  }

  async createOsTemplateBuild(build, auditEvent) {
    if (this.osTemplateBuilds.some((item) => item.id === build.id)) {
      throw new RemediationStoreConflictError(`OS template build ${build.id} already exists`);
    }
    this.osTemplateBuilds.unshift(clone(build));
    if (auditEvent) this.auditEvents.unshift({ ...clone(auditEvent), tenantId: auditTenantId(auditEvent) });
    return clone(build);
  }

  async updateOsTemplateBuildWith(id, decide) {
    return this.withJobLock(`os-template:${id}`, async () => {
      const current = await this.getOsTemplateBuild(id);
      const outcome = await decide(current);
      if (!outcome?.build) return current;
      if (outcome.build.id !== id) throw new Error('An OS template update must not change the build ID');
      const index = this.osTemplateBuilds.findIndex((item) => item.id === id);
      if (index === -1) throw new RemediationStoreConflictError(`OS template build ${id} no longer exists`);
      this.osTemplateBuilds[index] = clone(outcome.build);
      if (outcome.auditEvent) {
        this.auditEvents.unshift({ ...clone(outcome.auditEvent), tenantId: auditTenantId(outcome.auditEvent) });
      }
      return clone(outcome.build);
    });
  }

  async appendAuditEvent(event) {
    const stored = { ...clone(event), tenantId: auditTenantId(event) };
    this.auditEvents.unshift(stored);
    return clone(stored);
  }

  async listAuditEvents({ limit = 100 } = {}, scope) {
    return (await this.queryAuditEvents({ limit }, scope)).events;
  }

  // A page of the log, newest first, after `before` (src/lib/auditQuery.js). nextCursor is
  // null on the last page.
  async queryAuditEvents({ limit = 100, before = null, filters = {} } = {}, scope) {
    const inScope = scopeFilter(scope);
    const matching = this.auditEvents
      .filter((event) => inScope(event) && matchesAuditFilters(event, filters) && isBeforeCursor(event, before))
      .sort(compareAuditEvents);
    const events = matching.slice(0, limit);
    const last = events[events.length - 1];
    const nextCursor =
      matching.length > limit && last ? encodeAuditCursor({ occurredMicros: micros(last.occurredAt), id: last.id }) : null;
    return { events: clone(events), nextCursor };
  }

  // How many events match, in total and per category (the category filter itself is ignored).
  async summarizeAuditEvents({ filters = {} } = {}, scope) {
    const inScope = scopeFilter(scope);
    const categories = Object.fromEntries([...AUDIT_CATEGORIES, AUDIT_OTHER_CATEGORY].map((item) => [item.key, 0]));
    for (const event of this.auditEvents) {
      if (!inScope(event) || !matchesAuditFilters(event, filters, { ignoreCategory: true })) continue;
      categories.all += 1;
      categories[auditCategoryOf(event.eventType).key] += 1;
    }
    return { total: categories.all, categories };
  }

  async countAuditEvents({ filters = {} } = {}, scope) {
    const inScope = scopeFilter(scope);
    return this.auditEvents.filter((event) => inScope(event) && matchesAuditFilters(event, filters)).length;
  }
}

function jobKind(job) {
  return job.mode === 'execution' ? 'execution' : 'dry-run';
}

// The JSON document stored for a record: tenantId lives in its column, rowVersion in its own.
function documentOf(record) {
  const data = { ...record };
  delete data.tenantId;
  delete data.rowVersion;
  return data;
}

// A stored document back into a record, with the tenant from its column.
function withTenant(data, tenantId) {
  return data ? { ...data, tenantId } : null;
}

// " WHERE <conditions> AND tenant_id = ANY($n)" for a scope; the tenant condition is left
// out for ALL_TENANTS. `params` receives the scope's tenant ids.
function whereInScope(scope, conditions, params) {
  assertScope(scope);
  const all = [...conditions];
  if (!scope.all) {
    params.push([...scope.tenantIds]);
    all.push(`tenant_id = ANY($${params.length}::text[])`);
  }
  return all.length > 0 ? ` WHERE ${all.join(' AND ')}` : '';
}

function jobValues(job, tenantId) {
  return [
    job.id,
    jobKind(job),
    job.parentJobId || null,
    job.sourceDigest,
    job.patchedImageDigest || null,
    job.status,
    job.lifecycleState || String(job.status || 'unknown').toLowerCase(),
    documentOf(job),
    job.createdAt || new Date().toISOString(),
    job.verifiedAt || job.createdAt || new Date().toISOString(),
    tenantId,
  ];
}

async function insertJob(client, job, tenantId) {
  await client.query(
    `INSERT INTO remediation_jobs
      (id, job_kind, parent_job_id, source_digest, output_digest, status, lifecycle_state, job_data, created_at, updated_at, tenant_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::timestamptz, $10::timestamptz, $11)`,
    jobValues(job, tenantId),
  );
}

async function insertAuditEvent(client, event) {
  if (!event) return;
  await client.query(
    `INSERT INTO audit_events
      (id, event_type, action, actor_id, resource_type, resource_id, correlation_id, outcome, severity, summary, metadata, occurred_at, tenant_id)
     VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid, $8, $9, $10, $11::jsonb, $12::timestamptz, $13)`,
    [
      event.id,
      event.eventType,
      event.action,
      event.actorId,
      event.resourceType,
      event.resourceId || null,
      event.correlationId,
      event.outcome,
      event.severity,
      event.summary,
      event.metadata,
      event.occurredAt,
      auditTenantId(event),
    ],
  );
}

async function insertPublishRequest(client, request, tenantId) {
  await client.query(
    `INSERT INTO publish_requests
      (id, remediation_job_id, source_digest, target_reference, status, policy_version,
       request_data, created_at, updated_at, tenant_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::timestamptz, $9::timestamptz, $10)`,
    [
      request.id,
      request.jobId,
      request.source.digest,
      request.target.tagReference,
      request.status,
      request.policyVersion,
      documentOf(request),
      request.createdAt,
      request.updatedAt,
      tenantId,
    ],
  );
}

async function insertOnboardingRequest(client, request, tenantId) {
  await client.query(
    `INSERT INTO onboarding_requests
      (id, source_reference, target_reference, status, request_data, created_at, updated_at, tenant_id)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::timestamptz, $7::timestamptz, $8)`,
    [
      request.id,
      request.source.reference,
      request.target.tagReference,
      request.status,
      documentOf(request),
      request.createdAt,
      request.updatedAt,
      tenantId,
    ],
  );
}

// Optimistic update of one publish request row (row_version must still match). The row is
// only updated inside its own tenant.
async function updatePublishRequestRow(client, request, tenantId) {
  const result = await client.query(
    `UPDATE publish_requests
        SET status = $2, request_data = $3::jsonb, updated_at = $4::timestamptz,
            row_version = row_version + 1
      WHERE id = $1 AND row_version = $5 AND tenant_id = $6
      RETURNING row_version`,
    [request.id, request.status, documentOf(request), request.updatedAt, request.rowVersion, tenantId],
  );
  if (result.rowCount === 0) {
    throw new RemediationStoreConflictError(`Publish request ${request.id} changed while this operation was in progress`);
  }
  return { ...request, tenantId, rowVersion: Number(result.rows[0].row_version) };
}

async function updateJobRow(client, id, job, tenantId) {
  const result = await client.query(
    `UPDATE remediation_jobs
        SET status = $2, lifecycle_state = $3, job_data = $4::jsonb,
            updated_at = $5::timestamptz, row_version = row_version + 1
      WHERE id = $1 AND tenant_id = $6`,
    [
      id,
      job.status,
      job.lifecycleState || String(job.status || 'unknown').toLowerCase(),
      documentOf(job),
      new Date().toISOString(),
      tenantId,
    ],
  );
  return result.rowCount > 0;
}

async function withTransaction(pool, operation) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

class PostgresRemediationStore {
  constructor(pool) {
    this.driver = 'postgres';
    this.pool = pool;
  }

  async initialize() {
    try {
      await this.pool.query('SELECT 1 FROM remediation_jobs LIMIT 1');
      await this.pool.query('SELECT 1 FROM audit_events LIMIT 1');
      await this.pool.query('SELECT 1 FROM publish_requests LIMIT 1');
      // Migration 009 (multi-tenancy): every team-owned table carries tenant_id.
      await this.pool.query('SELECT tenant_id FROM remediation_jobs LIMIT 1');
    } catch (error) {
      throw new Error(`PostgreSQL persistence is not initialized. Run npm run db:migrate first. ${error.message}`, {
        cause: error,
      });
    }
  }

  async close() {
    await this.pool.end();
  }

  async health() {
    await this.pool.query('SELECT 1');
    return { status: 'ok', driver: this.driver };
  }

  async nextJobId(kind) {
    const sequence = kind === 'execution' ? 'remediation_execution_seq' : 'remediation_dry_run_seq';
    const prefix = kind === 'execution' ? 'RM-EXEC' : 'RM-DRY';
    const result = await this.pool.query(`SELECT nextval('${sequence}') AS value`);
    return `${prefix}-${String(result.rows[0].value).padStart(4, '0')}`;
  }

  async nextPublishRequestId() {
    const result = await this.pool.query("SELECT nextval('publish_request_seq') AS value");
    return `PUB-${String(result.rows[0].value).padStart(4, '0')}`;
  }

  async nextOnboardingId() {
    const result = await this.pool.query("SELECT nextval('onboarding_request_seq') AS value");
    return `ONB-${String(result.rows[0].value).padStart(4, '0')}`;
  }

  async listOnboardingRequests(scope) {
    const params = [];
    const where = whereInScope(scope, [], params);
    const result = await this.pool.query(
      `SELECT request_data, tenant_id FROM onboarding_requests${where} ORDER BY created_at DESC, id DESC`,
      params,
    );
    return result.rows.map((row) => withTenant(row.request_data, row.tenant_id));
  }

  async nextExceptionId() {
    const result = await this.pool.query("SELECT nextval('policy_exception_seq') AS value");
    return `EXC-${String(result.rows[0].value).padStart(4, '0')}`;
  }

  async listExceptions(scope) {
    const params = [];
    const where = whereInScope(scope, [], params);
    const result = await this.pool.query(
      `SELECT exception_data, row_version, tenant_id FROM policy_exceptions${where} ORDER BY created_at DESC, id DESC`,
      params,
    );
    return result.rows.map((row) => ({ ...withTenant(row.exception_data, row.tenant_id), rowVersion: Number(row.row_version) }));
  }

  async getException(id, scope) {
    const params = [id];
    const where = whereInScope(scope, ['id = $1'], params);
    const result = await this.pool.query(
      `SELECT exception_data, row_version, tenant_id FROM policy_exceptions${where}`,
      params,
    );
    const row = result.rows[0];
    if (!row) return null;
    return { ...withTenant(row.exception_data, row.tenant_id), rowVersion: Number(row.row_version) };
  }

  async createException(exception, auditEvent, scope) {
    const tenantId = writableTenantId(scope, exception);
    const data = documentOf(exception);
    try {
      await withTransaction(this.pool, async (client) => {
        // Serialize requests for the same team + CVE + repository so two open exceptions
        // cannot be created for overlapping scopes concurrently.
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
          `policy-exception:${tenantId}|${data.cve}|${data.repository}`,
        ]);
        const open = await client.query(
          `SELECT exception_data FROM policy_exceptions
            WHERE cve = $1 AND repository = $2 AND status IN ('Requested', 'Approved') AND tenant_id = $3`,
          [data.cve, data.repository, tenantId],
        );
        const existing = overlappingOpenException(
          open.rows.map((row) => row.exception_data),
          data,
        );
        if (existing) throw openExceptionConflict(existing);
        await client.query(
          `INSERT INTO policy_exceptions
            (id, cve, repository, package, digest, reason_code, justification, status, expires_at,
             requested_by, decided_by, exception_data, created_at, updated_at, tenant_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10, $11, $12::jsonb, $13::timestamptz, $14::timestamptz, $15)`,
          [
            data.id,
            data.cve,
            data.repository,
            data.package,
            data.digest,
            data.reasonCode,
            data.justification,
            data.status,
            data.expiresAt,
            data.requestedBy,
            data.decidedBy,
            data,
            data.createdAt,
            data.updatedAt,
            tenantId,
          ],
        );
        await insertAuditEvent(client, auditForTenant(auditEvent, tenantId));
      });
    } catch (error) {
      if (error.code === '23505') {
        throw new RemediationStoreConflictError(`Exception ${data.id} already exists`);
      }
      throw error;
    }
    return { ...data, tenantId, rowVersion: 1 };
  }

  async updateException(exception, auditEvent, scope) {
    const tenantId = writableTenantId(scope, exception);
    const data = documentOf(exception);
    return withTransaction(this.pool, async (client) => {
      const result = await client.query(
        `UPDATE policy_exceptions
            SET status = $2, decided_by = $3, exception_data = $4::jsonb, updated_at = $5::timestamptz,
                row_version = row_version + 1
          WHERE id = $1 AND row_version = $6 AND tenant_id = $7
          RETURNING row_version`,
        [data.id, data.status, data.decidedBy, data, data.updatedAt, exception.rowVersion, tenantId],
      );
      if (result.rowCount === 0) {
        throw new RemediationStoreConflictError(`Exception ${data.id} changed while this operation was in progress`);
      }
      await insertAuditEvent(client, auditForTenant(auditEvent, tenantId));
      return { ...data, tenantId, rowVersion: Number(result.rows[0].row_version) };
    });
  }

  async getOnboardingRequest(id, scope) {
    const params = [id];
    const where = whereInScope(scope, ['id = $1'], params);
    const result = await this.pool.query(`SELECT request_data, tenant_id FROM onboarding_requests${where}`, params);
    const row = result.rows[0];
    return row ? withTenant(row.request_data, row.tenant_id) : null;
  }

  async createOnboardingRequest(request, auditEvent, scope) {
    const tenantId = writableTenantId(scope, request);
    try {
      await withTransaction(this.pool, async (client) => {
        // One open request per quarantine target: concurrent creates for the same target
        // queue on this lock, so the second one sees the first.
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`onboarding:${tenantId}:${request.target.tagReference}`]);
        const open = await client.query(
          `SELECT id FROM onboarding_requests
            WHERE tenant_id = $1 AND target_reference = $2 AND status = ANY($3::text[])
            ORDER BY created_at LIMIT 1`,
          [tenantId, request.target.tagReference, OPEN_ONBOARDING_STATUSES],
        );
        if (open.rows[0]) throw openOnboardingConflict(open.rows[0].id, request.target.tagReference);
        await insertOnboardingRequest(client, request, tenantId);
        await insertAuditEvent(client, auditForTenant(auditEvent, tenantId));
      });
    } catch (error) {
      if (error.code === '23505') {
        throw new RemediationStoreConflictError(`Onboarding request ${request.id} already exists`);
      }
      throw error;
    }
    return { ...request, tenantId };
  }

  // Read-decide-write of one onboarding request under its row lock, so a cancellation, a worker
  // handoff and an import receipt never overwrite one another.
  async updateOnboardingRequestWith(id, decide, scope) {
    assertScope(scope);
    return withTransaction(this.pool, async (client) => {
      const params = [id];
      const where = whereInScope(scope, ['id = $1'], params);
      const locked = await client.query(`SELECT request_data, tenant_id FROM onboarding_requests${where} FOR UPDATE`, params);
      const row = locked.rows[0];
      if (!row) return null;
      const current = withTenant(row.request_data, row.tenant_id);
      const outcome = await decide(current);
      if (!outcome) return { request: current, changed: false };
      const next = outcome.request;
      if (next.id !== id) throw new Error('An onboarding update must not change the request ID');
      await client.query(
        `UPDATE onboarding_requests
            SET status = $2, target_reference = $3, request_data = $4::jsonb,
                updated_at = $5::timestamptz, row_version = row_version + 1
          WHERE id = $1 AND tenant_id = $6`,
        [id, next.status, next.target.tagReference, documentOf(next), next.updatedAt, row.tenant_id],
      );
      await insertAuditEvent(client, auditForTenant(outcome.auditEvent, row.tenant_id));
      return { request: { ...next, tenantId: row.tenant_id }, changed: true };
    });
  }

  async updateOnboardingRequest(request, auditEvent, scope) {
    const tenantId = writableTenantId(scope, request);
    return withTransaction(this.pool, async (client) => {
      const result = await client.query(
        `UPDATE onboarding_requests
            SET status = $2, target_reference = $3, request_data = $4::jsonb,
                updated_at = $5::timestamptz, row_version = row_version + 1
          WHERE id = $1 AND tenant_id = $6`,
        [request.id, request.status, request.target.tagReference, documentOf(request), request.updatedAt, tenantId],
      );
      if (result.rowCount === 0) return null;
      await insertAuditEvent(client, auditForTenant(auditEvent, tenantId));
      return { ...request, tenantId };
    });
  }

  async listJobs(scope) {
    const params = [];
    const where = whereInScope(scope, [], params);
    const result = await this.pool.query(
      `SELECT job_data, tenant_id FROM remediation_jobs${where} ORDER BY created_at DESC, id DESC`,
      params,
    );
    return result.rows.map((row) => withTenant(row.job_data, row.tenant_id));
  }

  async getJob(id, scope) {
    const params = [id];
    const where = whereInScope(scope, ['id = $1'], params);
    const result = await this.pool.query(`SELECT job_data, tenant_id FROM remediation_jobs${where}`, params);
    const row = result.rows[0];
    return row ? withTenant(row.job_data, row.tenant_id) : null;
  }

  async listPublishRequests(scope) {
    const params = [];
    const where = whereInScope(scope, [], params);
    const result = await this.pool.query(
      `SELECT request_data, row_version, tenant_id FROM publish_requests${where} ORDER BY created_at DESC, id DESC`,
      params,
    );
    return result.rows.map((row) => ({ ...withTenant(row.request_data, row.tenant_id), rowVersion: Number(row.row_version) }));
  }

  async getPublishRequest(id, scope) {
    const params = [id];
    const where = whereInScope(scope, ['id = $1'], params);
    const result = await this.pool.query(
      `SELECT request_data, row_version, tenant_id FROM publish_requests${where}`,
      params,
    );
    const row = result.rows[0];
    if (!row) return null;
    return { ...withTenant(row.request_data, row.tenant_id), rowVersion: Number(row.row_version) };
  }

  async createPublishRequest(request, auditEvent, scope) {
    const tenantId = writableTenantId(scope, request);
    try {
      await withTransaction(this.pool, async (client) => {
        await insertPublishRequest(client, request, tenantId);
        await insertAuditEvent(client, auditForTenant(auditEvent, tenantId));
      });
    } catch (error) {
      if (error.code === '23505') {
        throw new RemediationStoreConflictError(
          'A publish request already exists for this remediation job and target reference.',
        );
      }
      throw error;
    }
    return { ...request, tenantId, rowVersion: 1 };
  }

  async updatePublishRequest(request, auditEvent, scope) {
    const tenantId = writableTenantId(scope, request);
    return withTransaction(this.pool, async (client) => {
      const stored = await updatePublishRequestRow(client, request, tenantId);
      await insertAuditEvent(client, auditForTenant(auditEvent, tenantId));
      return stored;
    });
  }

  // One transaction around a job and the publish requests of its output digest (withdrawal,
  // and a publish receipt that may arrive after one). The job row is locked first and the
  // requests `decide` loads are locked too (same order everywhere, so no deadlock), so the
  // set of requests cannot change underneath the decision. `decide(job, loadPublishRequests)`
  // returns { job?, jobAuditEvent?, requests: [{ request, auditEvent }], auditEvents? }; every
  // request is written with its optimistic row version. Any error rolls back all of it. The
  // job and the requests are read and written inside the tenant scope only.
  async updateJobAndPublishRequests(jobId, decide, scope) {
    assertScope(scope);
    return withTransaction(this.pool, async (client) => {
      const jobParams = [jobId];
      const jobWhere = whereInScope(scope, ['id = $1'], jobParams);
      const locked = await client.query(`SELECT job_data, tenant_id FROM remediation_jobs${jobWhere} FOR UPDATE`, jobParams);
      const current = locked.rows[0] ? withTenant(locked.rows[0].job_data, locked.rows[0].tenant_id) : null;
      const loadPublishRequests = async ({ digest, statuses, ids } = {}) => {
        const params = Array.isArray(ids) ? [ids] : [digest, statuses];
        const conditions = Array.isArray(ids) ? ['id = ANY($1::text[])'] : ['source_digest = $1', 'status = ANY($2::text[])'];
        const where = whereInScope(scope, conditions, params);
        const result = await client.query(
          `SELECT request_data, row_version, tenant_id FROM publish_requests${where} ORDER BY id FOR UPDATE`,
          params,
        );
        return result.rows.map((row) => ({ ...withTenant(row.request_data, row.tenant_id), rowVersion: Number(row.row_version) }));
      };
      const outcome = await decide(current, loadPublishRequests);
      let job = current;
      if (outcome?.job) {
        if (outcome.job.id !== jobId) throw new Error('A job update must not change the job ID');
        if (!current) throw new Error('A job update needs the job to exist in the tenant scope');
        assertSameTenant(current, outcome.job, 'job');
        await updateJobRow(client, jobId, outcome.job, current.tenantId);
        await insertAuditEvent(client, auditForTenant(outcome.jobAuditEvent, current.tenantId));
        job = outcome.job;
      }
      const stored = [];
      for (const item of outcome?.requests || []) {
        const tenantId = writableTenantId(scope, item.request);
        stored.push(await updatePublishRequestRow(client, item.request, tenantId));
        await insertAuditEvent(client, auditForTenant(item.auditEvent, tenantId));
      }
      for (const event of outcome?.auditEvents || []) {
        await insertAuditEvent(client, auditForTenant(event, current?.tenantId));
      }
      return { job, requests: stored };
    });
  }

  async createJob(job, auditEvent, scope) {
    const tenantId = writableTenantId(scope, job);
    await withTransaction(this.pool, async (client) => {
      await insertJob(client, job, tenantId);
      await insertAuditEvent(client, auditForTenant(auditEvent, tenantId));
    });
    return { ...job, tenantId };
  }

  async updateJob(job, auditEvent, scope) {
    const tenantId = writableTenantId(scope, job);
    return withTransaction(this.pool, async (client) => {
      if (!(await updateJobRow(client, job.id, job, tenantId))) return null;
      await insertAuditEvent(client, auditForTenant(auditEvent, tenantId));
      return { ...job, tenantId };
    });
  }

  // Atomic read-modify-write of one job: the row is locked (SELECT ... FOR UPDATE) while
  // `mutate(current)` derives the new state, so concurrent evidence intakes cannot overwrite
  // each other. `mutate` returns { job, auditEvent }, or { job: null } for "no change"; a
  // thrown error rolls the transaction back.
  async updateJobWith(id, mutate, scope) {
    assertScope(scope);
    return withTransaction(this.pool, async (client) => {
      const params = [id];
      const where = whereInScope(scope, ['id = $1'], params);
      const locked = await client.query(`SELECT job_data, tenant_id FROM remediation_jobs${where} FOR UPDATE`, params);
      if (!locked.rows[0]) return null;
      const current = withTenant(locked.rows[0].job_data, locked.rows[0].tenant_id);
      const result = await mutate(current);
      if (!result?.job) return current;
      const job = result.job;
      if (job.id !== id) throw new Error('A job update must not change the job ID');
      assertSameTenant(current, job, 'job');
      await updateJobRow(client, id, job, current.tenantId);
      await insertAuditEvent(client, auditForTenant(result.auditEvent, current.tenantId));
      return job;
    });
  }

  async acceptVerifiedEvidence({ dryRunJob, verifiedJob, evidence, evidenceDigest, auditEvent }, scope) {
    const tenantId = writableTenantId(scope, verifiedJob);
    if (recordTenantId(dryRunJob) !== tenantId) {
      throw new Error('Verified evidence must be stored in the team of its dry-run job');
    }
    const outputDigest = String(evidence.output?.digest || '').trim().toLowerCase();
    if (!digestPattern.test(outputDigest)) {
      throw new Error('Verification evidence output digest is invalid');
    }

    return withTransaction(this.pool, async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [outputDigest]);
      const existing = await client.query(
        `SELECT evidence_digest, execution_job_id
           FROM remediation_evidence
          WHERE output_digest = $1`,
        [outputDigest],
      );

      if (existing.rowCount > 0) {
        const params = [existing.rows[0].execution_job_id];
        const where = whereInScope(scope, ['id = $1'], params);
        const job = await client.query(`SELECT job_data, tenant_id FROM remediation_jobs${where}`, params);
        if (existing.rows[0].evidence_digest !== evidenceDigest || !job.rows[0]) {
          throw new RemediationStoreConflictError(
            'A different verification evidence document is already registered for this output digest.',
          );
        }
        return { job: withTenant(job.rows[0].job_data, job.rows[0].tenant_id), created: false };
      }

      await insertJob(client, verifiedJob, tenantId);
      await client.query(
        `INSERT INTO remediation_evidence
          (evidence_digest, output_digest, dry_run_job_id, execution_job_id, contract_version, evidence_data, accepted_at)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::timestamptz)`,
        [
          evidenceDigest,
          outputDigest,
          dryRunJob.id,
          verifiedJob.id,
          evidence.contractVersion,
          evidence,
          verifiedJob.verifiedAt || new Date().toISOString(),
        ],
      );
      await insertAuditEvent(client, auditForTenant(auditEvent, tenantId));
      return { job: { ...verifiedJob, tenantId }, created: true };
    });
  }

  // Image inspections: the row and its audit event in one transaction. The upsert only
  // replaces an older inspection, so of two concurrent first deliveries the older one can
  // never win (it gets a conflict).
  async getImageInspections(references) {
    if (references.length === 0) return new Map();
    const result = await this.pool.query(
      'SELECT reference, inspection_data FROM image_inspections WHERE reference = ANY($1::text[])',
      [references],
    );
    return new Map(result.rows.map((row) => [row.reference, row.inspection_data]));
  }

  async saveImageInspection(record, apply, auditEvent) {
    return withTransaction(this.pool, async (client) => {
      const existing = await client.query(
        'SELECT inspection_data FROM image_inspections WHERE reference = $1 FOR UPDATE',
        [record.reference],
      );
      const current = existing.rows[0]?.inspection_data || null;
      const result = apply(current, record);
      if (!result.changed) return { record: current, changed: false };
      const written = await client.query(
        `INSERT INTO image_inspections (reference, digest, generated_at, evidence_digest, inspection_data, updated_at)
         VALUES ($1, $2, $3::timestamptz, $4, $5::jsonb, now())
         ON CONFLICT (reference) DO UPDATE
            SET digest = EXCLUDED.digest, generated_at = EXCLUDED.generated_at,
                evidence_digest = EXCLUDED.evidence_digest, inspection_data = EXCLUDED.inspection_data,
                updated_at = now()
          WHERE image_inspections.generated_at < EXCLUDED.generated_at`,
        [record.reference, record.digest, record.generatedAt, record.evidenceDigest, JSON.stringify(result.record)],
      );
      if (written.rowCount === 0) {
        throw new RemediationStoreConflictError(`A newer inspection of ${record.reference} was recorded concurrently`);
      }
      await insertAuditEvent(client, auditEvent);
      return { record: result.record, changed: true };
    });
  }

  async listResourceRuns(resourceType, resourceId, { limit = 20 } = {}) {
    const result = await this.pool.query(
      `SELECT run_data FROM pipeline_runs WHERE resource_type = $1 AND resource_id = $2
        ORDER BY created_at DESC, run_id DESC LIMIT $3`,
      [resourceType, resourceId, limit],
    );
    return result.rows.map((row) => row.run_data);
  }

  // The runs of one resource are decided under a transaction-scoped advisory lock, so two
  // requests can never both see "no run in progress" and start two runs.
  async updateResourceRunsWith(resourceType, resourceId, decide) {
    return withTransaction(this.pool, async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`pipeline-runs:${resourceType}:${resourceId}`]);
      const read = async () =>
        (
          await client.query(
            `SELECT run_data FROM pipeline_runs WHERE resource_type = $1 AND resource_id = $2
              ORDER BY created_at DESC, run_id DESC LIMIT 50`,
            [resourceType, resourceId],
          )
        ).rows.map((row) => row.run_data);
      const current = await read();
      const outcome = await decide(current);
      if (!outcome?.runs?.length) return current;
      for (const run of outcome.runs) {
        await client.query(
          `INSERT INTO pipeline_runs (resource_type, resource_id, run_id, run_data, created_at, updated_at)
           VALUES ($1, $2, $3, $4::jsonb, $5::timestamptz, now())
           ON CONFLICT (resource_type, resource_id, run_id) DO UPDATE
              SET run_data = EXCLUDED.run_data, updated_at = now()`,
          [resourceType, resourceId, run.runId, JSON.stringify(run), run.requestedAt],
        );
      }
      if (outcome.auditEvent) await insertAuditEvent(client, outcome.auditEvent);
      return read();
    });
  }

  // OS template build requests (migration 013): the row lock serializes decisions on one
  // request; the new document and its audit event are written in one transaction.
  async nextOsTemplateBuildId() {
    const result = await this.pool.query("SELECT nextval('os_template_build_seq') AS value");
    return `OST-${String(result.rows[0].value).padStart(4, '0')}`;
  }

  async listOsTemplateBuilds({ limit = 200 } = {}) {
    const result = await this.pool.query(
      'SELECT build_data FROM os_template_builds ORDER BY created_at DESC, id DESC LIMIT $1',
      [limit],
    );
    return result.rows.map((row) => row.build_data);
  }

  async getOsTemplateBuild(id) {
    const result = await this.pool.query('SELECT build_data FROM os_template_builds WHERE id = $1', [id]);
    return result.rows[0]?.build_data || null;
  }

  async createOsTemplateBuild(build, auditEvent) {
    return withTransaction(this.pool, async (client) => {
      const inserted = await client.query(
        `INSERT INTO os_template_builds (id, template_name, status, build_data, created_at, updated_at)
         VALUES ($1, $2, $3, $4::jsonb, $5::timestamptz, $6::timestamptz)
         ON CONFLICT (id) DO NOTHING`,
        [build.id, build.request.templateName, build.status, JSON.stringify(build), build.createdAt, build.updatedAt],
      );
      if (inserted.rowCount === 0) throw new RemediationStoreConflictError(`OS template build ${build.id} already exists`);
      await insertAuditEvent(client, auditEvent);
      return build;
    });
  }

  async updateOsTemplateBuildWith(id, decide) {
    return withTransaction(this.pool, async (client) => {
      const locked = await client.query('SELECT build_data FROM os_template_builds WHERE id = $1 FOR UPDATE', [id]);
      const current = locked.rows[0]?.build_data || null;
      const outcome = await decide(current);
      if (!outcome?.build) return current;
      if (outcome.build.id !== id) throw new Error('An OS template update must not change the build ID');
      if (!current) throw new RemediationStoreConflictError(`OS template build ${id} no longer exists`);
      await client.query(
        `UPDATE os_template_builds
            SET status = $2, build_data = $3::jsonb, updated_at = $4::timestamptz, row_version = row_version + 1
          WHERE id = $1`,
        [id, outcome.build.status, JSON.stringify(outcome.build), outcome.build.updatedAt],
      );
      await insertAuditEvent(client, outcome.auditEvent);
      return outcome.build;
    });
  }

  async appendAuditEvent(event) {
    await insertAuditEvent(this.pool, event);
    return { ...event, tenantId: auditTenantId(event) };
  }

  // Platform events and audit rows older than migration 009 have no tenant: they are
  // visible to ALL_TENANTS (platform administrators) only.
  async listAuditEvents({ limit = 100 } = {}, scope) {
    return (await this.queryAuditEvents({ limit }, scope)).events;
  }

  // A page of the log, newest first, after `before`; keyset on (occurred_at, id), which the
  // occurred_at indexes serve. One row more than the page tells whether another page exists.
  async queryAuditEvents({ limit = 100, before = null, filters = {} } = {}, scope) {
    const params = [];
    const conditions = auditSqlConditions(filters, params);
    const cursor = auditSqlCursorCondition(before, params);
    if (cursor) conditions.push(cursor);
    const where = whereInScope(scope, conditions, params);
    params.push(limit + 1);
    const result = await this.pool.query(
      `SELECT id, event_type, action, actor_id, resource_type, resource_id, correlation_id,
              outcome, severity, summary, metadata, occurred_at, tenant_id,
              (extract(epoch FROM occurred_at) * 1000000)::bigint::text AS occurred_micros
         FROM audit_events${where}
        ORDER BY occurred_at DESC, id DESC
        LIMIT $${params.length}`,
      params,
    );
    const rows = result.rows.slice(0, limit);
    const last = rows[rows.length - 1];
    return {
      events: rows.map(auditEventFromRow),
      nextCursor:
        result.rows.length > limit && last ? encodeAuditCursor({ occurredMicros: last.occurred_micros, id: last.id }) : null,
    };
  }

  // How many events match, in total and per category (the category filter itself is ignored).
  async summarizeAuditEvents({ filters = {} } = {}, scope) {
    const params = [];
    const where = whereInScope(scope, auditSqlConditions(filters, params, { ignoreCategory: true }), params);
    const prefixed = AUDIT_CATEGORIES.filter((item) => item.prefix);
    const buckets = prefixed.map((item) => {
      params.push(`${item.prefix}%`);
      return `count(*) FILTER (WHERE event_type LIKE $${params.length})::int AS "${item.key}"`;
    });
    const result = await this.pool.query(
      `SELECT count(*)::int AS "all", ${buckets.join(', ')} FROM audit_events${where}`,
      params,
    );
    const row = result.rows[0] || {};
    const categories = Object.fromEntries(AUDIT_CATEGORIES.map((item) => [item.key, Number(row[item.key] || 0)]));
    categories[AUDIT_OTHER_CATEGORY.key] =
      categories.all - prefixed.reduce((sum, item) => sum + categories[item.key], 0);
    return { total: categories.all, categories };
  }

  async countAuditEvents({ filters = {} } = {}, scope) {
    const params = [];
    const where = whereInScope(scope, auditSqlConditions(filters, params), params);
    const result = await this.pool.query(`SELECT count(*)::int AS total FROM audit_events${where}`, params);
    return Number(result.rows[0]?.total || 0);
  }
}

function auditEventFromRow(row) {
  return {
    id: row.id,
    tenantId: row.tenant_id ?? null,
    eventType: row.event_type,
    action: row.action,
    actorId: row.actor_id,
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    correlationId: row.correlation_id,
    outcome: row.outcome,
    severity: row.severity,
    summary: row.summary,
    metadata: row.metadata,
    occurredAt:
      row.occurred_at instanceof Date ? row.occurred_at.toISOString() : new Date(row.occurred_at).toISOString(),
  };
}

// pool: opsiyonel paylaşılan havuz. server.js postgres modunda havuzu bir kez
// oluşturup hem bu depo hem de kullanıcı deposuyla paylaşır (tek havuz). Verilmezse
// geriye dönük uyumluluk için kendi havuzunu oluşturur.
export async function createRemediationStore({ pool = null } = {}) {
  const driver = String(process.env.PERSISTENCE_DRIVER || 'memory').trim().toLowerCase();
  if (driver === 'memory') return new MemoryRemediationStore();
  if (driver !== 'postgres') {
    throw new Error('PERSISTENCE_DRIVER must be memory or postgres');
  }
  return new PostgresRemediationStore(pool || (await createPostgresPool()));
}

export { MemoryRemediationStore, PostgresRemediationStore };
