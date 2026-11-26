import {
  auditSeed,
  cveTrend,
  remediationHistory,
  remediationJobs,
  scanReports,
  seedImages,
  sbomReports,
} from '../data/platformData.js';
import { auditFilterParams } from './auditQuery.js';
import { createDryRunRemediationJob } from './remediation.js';
import { buildExecutionReadiness, buildWorkerHandoffManifest } from './remediationLifecycle.js';

const apiMode = import.meta.env.VITE_API_MODE || 'api';
const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || '/api/v1';

// Dev/demo login identity (SSI_DEV_LOGIN). When set, every request carries
// X-SSI-Actor-Id/Roles; the server honours them only while SSI_DEV_LOGIN=true.
// In production identity comes from the signed session or the authenticating proxy.
const DEV_IDENTITY_KEY = 'ssi-dev-identity';

function readStoredIdentity() {
  try {
    const raw = typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(DEV_IDENTITY_KEY) : null;
    const parsed = raw ? JSON.parse(raw) : null;
    return parsed && parsed.subject ? { subject: parsed.subject, roles: parsed.roles || [] } : null;
  } catch {
    return null;
  }
}

// sessionStorage'dan başlatılır: refresh sonrası kimlik korunur ve İLK istekten
// itibaren header gönderilir (aksi halde ilk yüklemeler 401 olurdu).
let clientIdentity = readStoredIdentity();

export function getClientIdentity() {
  return clientIdentity;
}

export function setClientIdentity(identity) {
  clientIdentity =
    identity && identity.subject ? { subject: identity.subject, roles: identity.roles || [] } : null;
  try {
    if (clientIdentity) sessionStorage.setItem(DEV_IDENTITY_KEY, JSON.stringify(clientIdentity));
    else sessionStorage.removeItem(DEV_IDENTITY_KEY);
  } catch {
    /* sessionStorage kullanılamıyorsa yoksay */
  }
}

function clientIdentityHeaders() {
  if (!clientIdentity) return {};
  return {
    'X-SSI-Actor-Id': clientIdentity.subject,
    'X-SSI-Actor-Roles': (clientIdentity.roles || []).join(','),
  };
}

// Selected team (multi-tenancy). Kept per browser tab, so two tabs can work in two teams;
// sent as X-SSI-Tenant on every request. The server ignores it while multi-tenancy is off
// and answers 403 for a team the caller is not a member of.
const TENANT_KEY = 'ssi-tenant';
const TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$/;

function readStoredTenant() {
  try {
    const value = typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(TENANT_KEY) : '';
    return value && TENANT_ID_PATTERN.test(value) ? value : '';
  } catch {
    return '';
  }
}

let selectedTenant = readStoredTenant();

export function getSelectedTenant() {
  return selectedTenant;
}

// '' clears the selection (a platform administrator's "All teams").
export function setSelectedTenant(tenantId) {
  selectedTenant = tenantId && TENANT_ID_PATTERN.test(tenantId) ? tenantId : '';
  try {
    if (selectedTenant) sessionStorage.setItem(TENANT_KEY, selectedTenant);
    else sessionStorage.removeItem(TENANT_KEY);
  } catch {
    /* sessionStorage kullanılamıyorsa yoksay */
  }
}

function tenantHeaders() {
  return selectedTenant ? { 'X-SSI-Tenant': selectedTenant } : {};
}

// Mock mode (VITE_API_MODE=mock) is an explicit UI-development build. Sample data is
// only ever returned there.
function fallback(data) {
  return { data, source: 'mock', error: '' };
}

// Live mode: when the API cannot be reached the UI shows an EMPTY, clearly labelled
// state — never sample data that could be mistaken for real inventory, scans or audit.
function unavailable(data, error) {
  return { data, source: 'unavailable', error: error?.message || 'The SSI API is unavailable.' };
}

const EMPTY_REMEDIATION_REPORT = {
  generatedAt: '',
  summary: { totalJobs: 0, verifiedJobs: 0, plannedJobs: 0, blockedJobs: 0, cvesRemediated: 0, publishBlocked: 0 },
  history: [],
  trend: [],
};

function fallbackRemediationReport() {
  const verified = remediationHistory.filter((item) => item.status === 'Verified');

  return {
    generatedAt: '',
    summary: {
      totalJobs: remediationHistory.length,
      verifiedJobs: verified.length,
      plannedJobs: remediationHistory.filter((item) => item.status === 'Planned').length,
      blockedJobs: remediationHistory.filter((item) => item.status === 'Blocked').length,
      cvesRemediated: verified.reduce((total, item) => total + item.cvesFixed, 0),
      publishBlocked: 0,
    },
    history: remediationHistory,
    trend: cveTrend,
  };
}

function fallbackAuditEvents() {
  return auditSeed.map((summary, index) => ({
    id: `fixture-${index + 1}`,
    correlationId: '',
    actorId: 'fixture',
    action: 'fixture.event',
    outcome: 'success',
    severity: 'info',
    resourceType: 'fixture',
    resourceId: '',
    summary,
    metadata: {},
    occurredAt: '',
  }));
}

async function requestJson(path, options = {}) {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...clientIdentityHeaders(),
      ...tenantHeaders(),
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    const message = error.message || `API ${response.status}: ${response.statusText}`;
    // Unexpected server errors carry a correlation ID that operators can find in the logs.
    throw new Error(error.correlationId ? `${message} (ref: ${error.correlationId})` : message);
  }

  return {
    data: await response.json(),
    source: response.headers.get('x-ssi-data-source') || 'api',
    error: response.headers.get('x-ssi-data-error') || '',
    headers: response.headers,
  };
}

export async function listImages() {
  if (apiMode === 'mock') {
    return fallback(seedImages);
  }

  try {
    const result = await requestJson('/images');
    return {
      data: result.data,
      source: result.source,
      error: result.error,
    };
  } catch (error) {
    return unavailable([], error);
  }
}

export async function getImageSbom(imageId) {
  const mockComponents = sbomReports[imageId] || [];

  if (apiMode === 'mock') {
    return fallback(mockComponents);
  }

  try {
    const result = await requestJson(`/images/${encodeURIComponent(imageId)}/sbom`);
    return {
      data: result.data,
      source: result.source,
      error: result.error,
    };
  } catch (error) {
    return unavailable([], error);
  }
}

export async function listScanReports() {
  if (apiMode === 'mock') {
    return fallback(scanReports);
  }

  try {
    const result = await requestJson('/scans');
    return {
      data: result.data,
      source: result.source,
      error: result.error,
    };
  } catch (error) {
    return unavailable([], error);
  }
}

export async function listRemediationJobs() {
  if (apiMode === 'mock') {
    return fallback(remediationJobs);
  }

  try {
    const result = await requestJson('/remediation');
    return {
      data: result.data,
      source: result.source,
      error: result.error,
    };
  } catch (error) {
    return unavailable([], error);
  }
}

export async function getRemediationReport() {
  const mockReport = fallbackRemediationReport();
  if (apiMode === 'mock') {
    return fallback(mockReport);
  }

  try {
    return await requestJson('/reports/remediation');
  } catch (error) {
    return unavailable(EMPTY_REMEDIATION_REPORT, error);
  }
}

// Builds the URL of the printable single-job remediation report document served
// by GET /reports/remediation/{jobId}/document. The document is HTML (not JSON),
// so the UI opens/downloads it directly rather than through requestJson.
// A plain link cannot carry X-SSI-Tenant, so the selected team travels as ?tenant=.
export function remediationReportDocumentUrl(jobId, { download = false } = {}) {
  const query = new URLSearchParams();
  if (download) query.set('download', 'true');
  if (selectedTenant) query.set('tenant', selectedTenant);
  const base = `${apiBaseUrl}/reports/remediation/${encodeURIComponent(jobId)}/document`;
  const search = query.toString();
  return search ? `${base}?${search}` : base;
}

// A page of the audit log, newest first, filtered on the server (src/lib/auditQuery.js).
// nextCursor is the `before` of the next page, '' on the last one.
export async function listAuditEvents(limit = 100, { before = '', filters = {} } = {}) {
  const mockEvents = fallbackAuditEvents();
  if (apiMode === 'mock') {
    return { ...fallback(mockEvents), nextCursor: '' };
  }

  const query = auditFilterParams(filters);
  query.set('limit', String(limit));
  if (before) query.set('before', before);
  try {
    const result = await requestJson(`/audit-events?${query.toString()}`);
    return { ...result, nextCursor: result.headers.get('x-ssi-next-cursor') || '' };
  } catch (error) {
    return { ...unavailable([], error), nextCursor: '' };
  }
}

// How many events the filters match, in total and per category.
export async function summarizeAuditEvents(filters = {}) {
  if (apiMode === 'mock') return fallback(null);
  try {
    return await requestJson(`/audit-events/summary?${auditFilterParams(filters).toString()}`);
  } catch (error) {
    return unavailable(null, error);
  }
}

// The CSV of every event the filters match between filters.from and filters.to. Fetched with the
// caller's identity and team headers (a plain link could not carry them) and handed back as a
// Blob for the browser to save. Throws with the server's message when the export is refused.
export async function exportAuditEvents(filters) {
  const query = auditFilterParams(filters);
  query.set('format', 'csv');
  const response = await fetch(`${apiBaseUrl}/audit-events/export?${query.toString()}`, {
    headers: { Accept: 'text/csv', ...clientIdentityHeaders(), ...tenantHeaders() },
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || `API ${response.status}: ${response.statusText}`);
  }
  const disposition = response.headers.get('content-disposition') || '';
  return {
    blob: await response.blob(),
    filename: disposition.match(/filename="([^"]+)"/)?.[1] || 'ssi-audit.csv',
    rows: Number(response.headers.get('x-ssi-audit-rows') || 0),
  };
}

// What changed between the source and the patched image (ssi.image-comparison/v1).
export async function getRemediationComparison(jobId) {
  return requestJson(`/remediation/${encodeURIComponent(jobId)}/comparison`);
}

// base / head: immutable scan references (<project>/<repository>@sha256:…, scanReportReference).
export async function compareScannedImages(base, head) {
  return requestJson(`/scans/compare?${new URLSearchParams({ base, head }).toString()}`);
}

export async function getRemediationExecutionReadiness(job) {
  if (apiMode === 'mock') {
    return fallback(buildExecutionReadiness(job));
  }

  try {
    const result = await requestJson(
      `/remediation/${encodeURIComponent(job.id)}/execution-readiness`,
    );
    return {
      data: result.data,
      source: result.source,
      error: result.error,
    };
  } catch (error) {
    return unavailable(null, error);
  }
}

export async function getRemediationWorkerHandoff(job) {
  if (apiMode === 'mock') {
    return fallback(buildWorkerHandoffManifest(job));
  }

  const result = await requestJson(`/remediation/${encodeURIComponent(job.id)}/worker-handoff`);
  return {
    data: result.data,
    source: result.source,
    error: result.error,
  };
}

function mockReportForRemediation(scanReportId) {
  const report = scanReports.find((item) => item.id === scanReportId) || scanReports[0];

  return {
    ...report,
    findings: report.findings.map((finding) => ({
      ...finding,
      class: finding.class || 'os-pkgs',
      type: finding.type || 'fixture',
    })),
  };
}

export async function createRemediationDryRun(scanReportId) {
  if (apiMode === 'mock') {
    return fallback(
      createDryRunRemediationJob({
        id: `RM-DRY-MOCK-${Date.now()}`,
        report: mockReportForRemediation(scanReportId),
      }),
    );
  }

  const result = await requestJson(`/images/${encodeURIComponent(scanReportId)}/remediation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scanReportId, dryRun: true }),
  });

  return {
    data: result.data,
    source: result.source,
    error: result.error,
  };
}

export async function attachCanonicalTrivyReport(jobId, report) {
  const result = await requestJson(`/remediation/${encodeURIComponent(jobId)}/canonical-report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof report === 'string' ? report : JSON.stringify(report),
  });

  return {
    data: result.data,
    source: result.source,
    error: result.error,
  };
}

export async function attachSupplyChainEvidence(jobId, evidence) {
  const result = await requestJson(`/remediation/${encodeURIComponent(jobId)}/supply-chain-evidence`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof evidence === 'string' ? evidence : JSON.stringify(evidence),
  });

  return {
    data: result.data,
    source: result.source,
    error: result.error,
  };
}

// Pre-release testing: the candidate test worker's result (manual upload of its artifact).
export async function attachCandidateTestEvidence(jobId, evidence) {
  const result = await requestJson(`/remediation/${encodeURIComponent(jobId)}/candidate-test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof evidence === 'string' ? evidence : JSON.stringify(evidence),
  });

  return {
    data: result.data,
    source: result.source,
    error: result.error,
  };
}

// Azure DevOps worker pipelines of a remediation job: the actions that can start now and the
// runs with their live state. Automation off (or mock mode) → { enabled: false }.
const NO_PIPELINE_RUNS = { enabled: false, actions: [], runs: [] };

export async function getPipelineRuns(jobId) {
  if (apiMode === 'mock') {
    return fallback(NO_PIPELINE_RUNS);
  }
  try {
    const result = await requestJson(`/remediation/${encodeURIComponent(jobId)}/pipeline-runs`);
    return { data: result.data, source: result.source, error: result.error };
  } catch (error) {
    return unavailable(NO_PIPELINE_RUNS, error);
  }
}

// Starts a worker pipeline ({ action, canonicalBuildId? }); SSI derives every parameter.
// Returns { job, run }; throws with the server's reason when the run cannot start.
export async function startPipelineRun(jobId, payload) {
  const result = await requestJson(`/remediation/${encodeURIComponent(jobId)}/pipeline-runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return { data: result.data, source: result.source, error: result.error };
}

// The same for an onboarding request ('onboarding') or a publish request ('publish-requests'),
// and for a scanned image (<project>/<repository>@sha256:<digest>, image inspection).
const RECORD_COLLECTIONS = new Set(['onboarding', 'publish-requests', 'os-templates']);

function recordRunsPath(collection, id) {
  if (!RECORD_COLLECTIONS.has(collection)) throw new Error(`Unknown record collection: ${collection}`);
  return `/${collection}/${encodeURIComponent(id)}/pipeline-runs`;
}

export async function getRecordPipelineRuns(collection, id) {
  if (apiMode === 'mock') return fallback(NO_PIPELINE_RUNS);
  try {
    const result = await requestJson(recordRunsPath(collection, id));
    return { data: result.data, source: result.source, error: result.error };
  } catch (error) {
    return unavailable(NO_PIPELINE_RUNS, error);
  }
}

export async function startRecordPipelineRun(collection, id, payload) {
  const result = await requestJson(recordRunsPath(collection, id), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return { data: result.data, source: result.source, error: result.error };
}

export async function getImagePipelineRuns(reference) {
  if (apiMode === 'mock') return fallback(NO_PIPELINE_RUNS);
  try {
    const result = await requestJson(`/scans/pipeline-runs?${new URLSearchParams({ reference }).toString()}`);
    return { data: result.data, source: result.source, error: result.error };
  } catch (error) {
    return unavailable(NO_PIPELINE_RUNS, error);
  }
}

export async function startImagePipelineRun(reference, payload) {
  const result = await requestJson('/scans/pipeline-runs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...payload, reference }),
  });
  return { data: result.data, source: result.source, error: result.error };
}

// Pre-release testing: a consumer team's decision ({ decision, environment, note }). The
// decider is taken from the signed-in session on the server.
export async function recordConsumerAcceptance(jobId, payload) {
  const result = await requestJson(`/remediation/${encodeURIComponent(jobId)}/consumer-acceptance`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  return {
    data: result.data,
    source: result.source,
    error: result.error,
  };
}

export async function attachRemediationVerificationEvidence(jobId, evidence) {
  const result = await requestJson(`/remediation/${encodeURIComponent(jobId)}/verification-evidence`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(evidence),
  });

  return {
    data: result.data,
    source: result.source,
    error: result.error,
  };
}

export async function listOnboardingRequests() {
  if (apiMode === 'mock') {
    return fallback([]);
  }

  try {
    return await requestJson('/onboarding');
  } catch (error) {
    return unavailable([], error);
  }
}

export async function createOnboardingRequest(sourceReference) {
  const result = await requestJson('/onboarding', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sourceReference }),
  });

  return { data: result.data, source: result.source, error: result.error };
}

// OS templates (src/lib/osTemplate.js): platform-wide build requests for Windows template ISOs.
export async function listOsTemplates() {
  if (apiMode === 'mock') return fallback([]);
  try {
    return await requestJson('/os-templates');
  } catch (error) {
    return unavailable([], error);
  }
}

export async function getOsTemplate(id) {
  const result = await requestJson(`/os-templates/${encodeURIComponent(id)}`);
  return { data: result.data, source: result.source, error: result.error };
}

// { isoFile, isoSha256, imageIndex, product, templateName }; the requester comes from the session.
export async function createOsTemplate(request) {
  const result = await requestJson('/os-templates', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  return { data: result.data, source: result.source, error: result.error };
}

// decision: 'approve' | 'reject' (a rejection needs a reason); the approver comes from the session.
export async function decideOsTemplate(id, decision, reason = '') {
  if (!['approve', 'reject'].includes(decision)) throw new Error(`Unknown decision: ${decision}`);
  const result = await requestJson(`/os-templates/${encodeURIComponent(id)}/${decision}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  });
  return { data: result.data, source: result.source, error: result.error };
}

// A one-time link to one download of a built OS template (src/lib/osTemplateDownloads.js).
// The browser then saves it from the plain link: gigabytes never pass through this page.
export async function createOsTemplateDownload(id, download) {
  const result = await requestJson(`/os-templates/${encodeURIComponent(id)}/download-tickets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ download }),
  });
  return result.data;
}

// Closes an open onboarding request that no worker will finish. The server takes the actor
// from the signed-in session and records the reason in the audit log.
export async function cancelOnboardingRequest(requestId, reason) {
  const result = await requestJson(`/onboarding/${encodeURIComponent(requestId)}/cancel`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  });

  return { data: result.data, source: result.source, error: result.error };
}

export async function getSession() {
  const permissiveFallback = {
    subject: 'poc',
    roles: ['admin'],
    permissions: ['*'],
    authenticated: false,
    enforced: false,
  };
  if (apiMode === 'mock') {
    return fallback(permissiveFallback);
  }

  try {
    return await requestJson('/session');
  } catch (error) {
    // Fail closed: without a session the UI grants nothing (the server enforces anyway).
    return unavailable(
      { subject: '', roles: [], permissions: [], authenticated: false, enforced: true, passwordLogin: false, devLogin: false },
      error,
    );
  }
}

// --- Kimlik: LDAP / lokal admin girişi (imzalı oturum çerezi sunucuda set edilir) ---
export async function loginWithPassword(username, password) {
  return requestJson('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
}

export async function logout() {
  return requestJson('/auth/logout', { method: 'POST' });
}

// --- Kullanıcı yönetimi (yalnızca admin) ---
export async function listUsers() {
  return requestJson('/users');
}

export async function createUser(payload) {
  return requestJson('/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function updateUser(username, changes) {
  return requestJson(`/users/${encodeURIComponent(username)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(changes),
  });
}

export async function deleteUser(username) {
  return requestJson(`/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
}

// --- Teams and team memberships (platform administrators only) ---
function jsonBody(method, payload) {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) };
}

export async function listTenants() {
  return requestJson('/tenants');
}

export async function createTenant(payload) {
  return requestJson('/tenants', jsonBody('POST', payload));
}

export async function updateTenant(tenantId, changes) {
  return requestJson(`/tenants/${encodeURIComponent(tenantId)}`, jsonBody('PATCH', changes));
}

export async function listTenantMembers(tenantId) {
  return requestJson(`/tenants/${encodeURIComponent(tenantId)}/members`);
}

export async function setTenantMembership(tenantId, username, role) {
  return requestJson(
    `/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(username)}`,
    jsonBody('PUT', { role }),
  );
}

export async function removeTenantMembership(tenantId, username) {
  return requestJson(`/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(username)}`, {
    method: 'DELETE',
  });
}

export async function getPublishPolicy() {
  if (apiMode === 'mock') {
    return fallback({
      version: 'ssi.publish-policy/v1.4',
      thresholds: { maxCritical: 0, maxHigh: 0 },
      requirements: { sbom: false, signature: false, provenance: false, consumerAcceptance: true },
      target: {
        registry: 'registry.example.com',
        project: 'ssi-images',
        repositoryPrefix: 'approved',
      },
      approval: { required: true, trustedIdentityEnabled: false, approverCount: 0, configured: false },
      riskAcceptance: {
        maxDays: 90,
        maxDaysCritical: 30,
        twoPersonRule: true,
        appliesTo: ['critical-threshold', 'high-threshold'],
      },
    });
  }
  return requestJson('/publish-policy');
}

// --- Risk acceptance (policy exceptions). Requester and approver come from the session. ---
export async function listExceptions() {
  if (apiMode === 'mock') return fallback([]);
  try {
    return await requestJson('/exceptions');
  } catch (error) {
    return unavailable([], error);
  }
}

export async function requestException(payload) {
  return requestJson('/exceptions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function decideException(exceptionId, decision, note) {
  return requestJson(`/exceptions/${encodeURIComponent(exceptionId)}/${encodeURIComponent(decision)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note }),
  });
}

export async function listPublishRequests() {
  if (apiMode === 'mock') return fallback([]);
  return requestJson('/publish-requests');
}

// Requester and approver are taken server-side from the trusted identity (session,
// proxy or dev login); the client never asserts who is acting.
export async function createPublishRequest(jobId, target) {
  return requestJson('/publish-requests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jobId, target }),
  });
}

export async function approvePublishRequest(requestId, reason) {
  return requestJson(`/publish-requests/${encodeURIComponent(requestId)}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  });
}

export async function rejectPublishRequest(requestId, reason) {
  return requestJson(`/publish-requests/${encodeURIComponent(requestId)}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  });
}

export async function withdrawPublishRequest(requestId, { reason, category }) {
  return requestJson(`/publish-requests/${encodeURIComponent(requestId)}/withdraw`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason, category }),
  });
}

export async function getPublishWorkerHandoff(requestId) {
  return requestJson(`/publish-requests/${encodeURIComponent(requestId)}/worker-handoff`);
}
