import { createReadStream, existsSync, readFileSync, statSync } from 'node:fs';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { extname, join, normalize } from 'node:path';
import { pipeline as streamPipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { scanReports, seedImages, sbomReports, trivyScanSamples } from './src/data/platformData.js';
import {
  collectAllPages,
  HARBOR_VULNERABILITY_REPORT_MIME,
  encodeHarborRepositoryName,
  findHarborScanOverview,
  harborRelativeRepositoryName,
  harborScanStatus,
  isCosignAccessoryArtifact,
  isHarborScanComplete,
  mapHarborArtifact,
  normalizeHarborVulnerabilityReport,
  parseHarborProjects,
} from './src/lib/harbor.js';
import {
  createDryRunRemediationJob,
  replanDryRunFromCanonicalReport,
  assertRemediationInScope,
  isReportOnlyJob,
  RemediationScopeError,
} from './src/lib/remediation.js';
import {
  createVerifiedRemediationJob,
  RemediationEvidenceValidationError,
} from './src/lib/remediationEvidence.js';
import { buildExecutionReadiness, buildWorkerHandoffManifest } from './src/lib/remediationLifecycle.js';
import { normalizeTrivyScan } from './src/lib/trivy.js';
import { CanonicalTrivyValidationError, validateCanonicalTrivyReport } from './src/lib/canonicalTrivy.js';
import { SupplyChainEvidenceValidationError, validateSupplyChainEvidence } from './src/lib/supplyChainEvidence.js';
import {
  applyCandidateTest,
  applyConsumerAcceptance,
  CandidateTestValidationError,
  createConsumerAcceptance,
  validateCandidateTestEvidence,
} from './src/lib/candidateTestEvidence.js';
import {
  acceptPublishReceipt,
  approvePublishRequest,
  buildPublishPolicyConfig,
  buildPublishWorkerHandoff,
  evaluatePublishPolicy,
  isPublishReceiptReplay,
  publicPublishPolicyConfig,
  PUBLISH_POLICY_VERSION,
  PublishPolicyValidationError,
} from './src/lib/publishPolicy.js';
import {
  buildWithdrawalDecision,
  decideDigestWithdrawal,
  decidePublishReceipt,
  OPEN_PUBLISH_STATUSES,
  receiptBaseline,
  rejectPublishRequest,
  withdrawPublishedRequest,
} from './src/lib/publishLifecycle.js';
import {
  buildExceptionAdjustment,
  createExceptionRecord,
  decideException,
  effectiveExceptionStatus,
  ExceptionValidationError,
  isExceptionActive,
  repositoryFromReference,
  severityForScope,
  validateExceptionRequest,
} from './src/lib/policyExceptions.js';
import { sanitizeHeaderValue, sanitizeHeaders } from './src/server/httpHeaders.js';
import {
  AUDIT_CSV_COLUMNS,
  AUDIT_EXPORT_MAX_ROWS,
  AuditQueryError,
  auditCsvLine,
  auditCsvRow,
  auditExportFilename,
  parseAuditExport,
  parseAuditFilters,
  parseAuditPage,
} from './src/lib/auditQuery.js';
import { applySecurityHeaders, DOCUMENT_CSP } from './src/server/securityHeaders.js';
import { derivePublishGateView } from './src/lib/publishGateView.js';
import { buildImageComparison, buildImageDiff, findScanReport, ImageComparisonError } from './src/lib/imageComparison.js';
import { applyImageInspection, ImageInspectionError, validateImageInspectionEvidence } from './src/lib/imageInspection.js';
import {
  applyOsTemplateResult,
  createOsTemplateBuild,
  decideOsTemplate,
  describeBuildRequest,
  OS_TEMPLATE_BUILD_ID,
  OsTemplateError,
  osTemplateArtifacts,
  osTemplateResultAudit,
  osTemplateRetentionTarget,
  osTemplateSummary,
  validateOsTemplateEvidence,
} from './src/lib/osTemplate.js';
import { findOsTemplateDownload, OsTemplateDownloadError } from './src/lib/osTemplateDownloads.js';
import { createDownloadTickets, DownloadTicketError } from './src/server/downloadTickets.js';
import { applySupplyChainEvidence } from './src/lib/supplyChainCoverage.js';
import { buildRemediationReport } from './src/server/remediationReporting.js';
import {
  buildRemediationReportDocumentModel,
  remediationReportDocumentFilename,
  renderRemediationReportDocumentHtml,
} from './src/lib/remediationReportDocument.js';
import {
  applyImportReceipt,
  cancelOnboardingRequest,
  isImportReceiptReplay,
  buildOnboardingRequest,
  buildOnboardingWorkerHandoff,
  parseAllowedRegistries,
  ONBOARDING_STATES,
  OnboardingValidationError,
} from './src/lib/onboarding.js';
import {
  authorizePermission,
  parseRoleBindings,
  parseRoles,
  permissionForRoute,
  permissionsForRoles,
  RbacError,
} from './src/lib/rbac.js';
import {
  ALL_TENANTS,
  assertTenantSelected,
  buildTenancyConfig,
  DEFAULT_TENANT_ID,
  isValidTenantId,
  normalizeTenantId,
  PLATFORM_ADMIN_ROLE,
  requireSingleTenant,
  resolveTenantContext,
  TENANT_HEADER,
  TenancyError,
  tenantScope,
  validateNewTenant,
  validateTenantChanges,
} from './src/lib/tenancy.js';
import {
  annotateOwnership,
  assertDistinctHarborAreas,
  isVisibleImage,
  isVisibleScanReport,
  ownerOfRepository,
  teamHarborAreas,
  teamTargets,
} from './src/lib/tenantInventory.js';
import { createTenantStore } from './src/server/tenantStore.js';
import { isTrustedIdentity, resolveIdentity } from './src/server/identity.js';
import { authenticateUser, isLdapConfigured, LdapAuthError } from './src/server/ldap.js';
import {
  buildClearCookie,
  buildSessionCookie,
  readSessionCookie,
  sessionSecretProblem,
  signSession,
  verifySession,
} from './src/server/session.js';
import { createSessionRevocations } from './src/server/sessionRevocations.js';
import { createLoginThrottle } from './src/server/loginThrottle.js';
import { assertNotSelfLockout, createUserStore, UserStoreError } from './src/server/userStore.js';
import {
  isLocalAdminUsername,
  parseLocalAdmin,
  verifyDecoyPassword,
  verifyPassword,
} from './src/server/localAdmin.js';
import {
  EVIDENCE_PURPOSE,
  sha256ContentDigest,
  verifyWorkerEvidenceRequest,
  WorkerEvidenceAuthenticationError,
} from './src/lib/workerEvidenceAuth.js';
import {
  assertReceiptSigner,
  authenticateWorkerReceipt,
  describeReceiptAuthentication,
  RECEIPT_AUTHENTICATION,
} from './src/lib/workerReceiptAuth.js';
import {
  buildAuditEvent,
  createRemediationStore,
  RemediationStoreConflictError,
} from './src/server/remediationStore.js';
import { createPostgresPool } from './src/server/database.js';
import { AzureDevOpsError, buildAzureDevOpsConfig, describeAzureDevOpsConfig } from './src/lib/azureDevOps.js';
import { PipelineRunError } from './src/lib/pipelineRuns.js';
import { createPipelineRunService } from './src/server/pipelineRunService.js';
import { createAzureDevOpsClient } from './src/server/azureDevOpsClient.js';

const port = Number(process.env.PORT || 5021);
const root = join(fileURLToPath(new URL('.', import.meta.url)), 'dist');

// Kalıcılık sürücüsü. postgres modunda TEK bağlantı havuzu oluşturulur ve hem
// remediation hem kullanıcı deposuyla paylaşılır (bağlantı israfını önler). memory
// modunda havuz yoktur (null).
const persistenceDriver = String(process.env.PERSISTENCE_DRIVER || 'memory').trim().toLowerCase();
const databasePool = persistenceDriver === 'postgres' ? await createPostgresPool() : null;
const remediationStore = await createRemediationStore({ pool: databasePool });
const publishPolicyConfig = buildPublishPolicyConfig(process.env);
const maxRequestBodyBytes = 64 * 1024;
const maxCanonicalTrivyReportBytes = 2 * 1024 * 1024;
const maxSupplyChainEvidenceBytes = 2 * 1024 * 1024;
const maxRemediationEvidenceBytes = 2 * 1024 * 1024;
// Up to 5000 package changes plus image facts of both images (bounded in candidateTestEvidence.js).
const maxCandidateTestEvidenceBytes = 2 * 1024 * 1024;
// Up to 10000 OS packages plus the image facts (bounded in imageInspection.js).
const maxImageInspectionEvidenceBytes = 2 * 1024 * 1024;
// One template manifest and its location: a few kilobytes.
const maxOsTemplateEvidenceBytes = 256 * 1024;
const maxConsumerAcceptanceBytes = 16 * 1024;
const maxPublishDecisionBytes = 16 * 1024;
const configuredEvidenceMaxAge = Number(process.env.SSI_REMEDIATION_EVIDENCE_MAX_AGE_SECONDS || 300);
const workerEvidenceMaxAgeSeconds =
  Number.isSafeInteger(configuredEvidenceMaxAge) && configuredEvidenceMaxAge >= 60 && configuredEvidenceMaxAge <= 900
    ? configuredEvidenceMaxAge
    : 300;
// Fixture (sample) data is a development aid only. Off unless explicitly enabled; when
// off, an unconfigured or failing Harbor yields an empty, clearly labelled result —
// never sample data that could be mistaken for real inventory or scans.
const fixturesEnabled = String(process.env.SSI_FIXTURES || '').toLowerCase() === 'true';
const FIXTURE_SOURCES = new Set(['fixture', 'trivy-fixture']);
const HARBOR_NOT_CONFIGURED =
  'Harbor is not configured (HARBOR_URL, HARBOR_PROJECTS, HARBOR_ROBOT_USERNAME, HARBOR_ROBOT_SECRET).';

const harborProjects = parseHarborProjects(process.env.HARBOR_PROJECTS, process.env.HARBOR_PROJECT);
const harbor = {
  url: process.env.HARBOR_URL || '',
  project: harborProjects[0] || '',
  projects: harborProjects,
  username: process.env.HARBOR_ROBOT_USERNAME || process.env.HARBOR_USERNAME || '',
  secret:
    process.env.HARBOR_ROBOT_SECRET ||
    process.env.HARBOR_ROBOT_TOKEN ||
    process.env.HARBOR_ROBOT_PASSWORD ||
    process.env.HARBOR_SECRET ||
    '',
  tlsVerify: process.env.HARBOR_TLS_VERIFY !== 'false',
};

// Onboarding hedefi: dış imajlar Harbor'da ayrı bir KARANTİNA prefix'ine iner
// (approved/ ile yan yana durmaz). SSI yalnızca isteği orkestre eder; asıl
// pull/copy/scan işini izole import worker yapar. İstekler remediationStore'da
// tutulur (postgres modunda kalıcı; publish request'leriyle aynı desen).
const onboarding = {
  targetRegistry: process.env.ONBOARD_TARGET_REGISTRY || process.env.PUBLISH_TARGET_REGISTRY || '',
  targetProject: process.env.ONBOARD_TARGET_PROJECT || process.env.PUBLISH_TARGET_PROJECT || harbor.projects[0] || '',
  targetRepositoryPrefix: process.env.ONBOARD_TARGET_REPOSITORY_PREFIX || 'onboarded',
  // Approved intake sources. Fail-closed: without a list nothing is onboarded (an external
  // image could otherwise come from any registry on the internet).
  allowedRegistries: parseAllowedRegistries(process.env.ONBOARD_ALLOWED_REGISTRIES),
};

// Azure DevOps (Phase 1 of the automation): SSI may start only the configured worker
// pipelines (src/lib/azureDevOps.js). Not configured → everything stays manual.
const azureDevOpsConfig = buildAzureDevOpsConfig(process.env);
const azureDevOps = createAzureDevOpsClient(azureDevOpsConfig);
// OS template downloads (src/lib/osTemplateDownloads.js): links carry a one-time ticket.
const osTemplateDownloadTickets = createDownloadTickets();
// A download whose bytes stop moving for this long is aborted (Azure DevOps or the client).
const DOWNLOAD_IDLE_TIMEOUT_MS = 120000;

// The hosts of the SSI Harbor: the registry name images are pulled by, and the API host.
// The first one is the reference the image inspection pipeline is given (docker pull).
const harborRegistryHosts = [
  ...new Set(
    [onboarding.targetRegistry, process.env.PUBLISH_TARGET_REGISTRY, harborApiHost(harbor.url)]
      .map((value) => String(value || '').trim().toLowerCase())
      .filter(Boolean),
  ),
];

// The worker pipelines read images from one Harbor project (their HARBOR_PROJECT variable),
// the first of HARBOR_PROJECTS.
const pipelineRuns = createPipelineRunService({
  azureDevOps,
  config: azureDevOpsConfig,
  harborProject: harbor.project,
  publishPrefix: publishPolicyConfig.target.repositoryPrefix,
  quarantinePrefix: onboarding.targetRepositoryPrefix,
  registryHost: harborRegistryHosts[0] || '',
  store: remediationStore,
});

function harborApiHost(value) {
  try {
    return value ? new URL(value).host : '';
  } catch {
    return '';
  }
}

// The platform's Harbor targets (today's configuration). The 'default' team uses them as
// they are; every other team inherits them for the fields its own Harbor target leaves
// empty (src/lib/tenantInventory.js).
const platformHarborTargets = Object.freeze({
  onboarding: Object.freeze({
    registry: onboarding.targetRegistry,
    project: onboarding.targetProject,
    repositoryPrefix: onboarding.targetRepositoryPrefix,
  }),
  publish: Object.freeze({ ...publishPolicyConfig.target }),
});

// RBAC config. Identity sources and their precedence live in src/server/identity.js.
//  - SSI_TRUST_ACTOR_HEADER: trust X-Forwarded-User/Groups from an authenticating proxy;
//    roles are always derived server-side (group map / role bindings).
//  - SSI_DEV_LOGIN: demo identity picker (X-SSI-Actor-*). Not authentication.
const rbacConfig = {
  // Secure by default: RBAC is enforced unless explicitly disabled (SSI_RBAC_ENFORCED=false).
  enforced: String(process.env.SSI_RBAC_ENFORCED || 'true').toLowerCase() !== 'false',
  trustActorHeader: String(process.env.SSI_TRUST_ACTOR_HEADER || '').toLowerCase() === 'true',
  devLogin: String(process.env.SSI_DEV_LOGIN || '').toLowerCase() === 'true',
  defaultActorId: String(process.env.SSI_AUDIT_ACTOR_ID || 'ssi-api'),
  defaultRoles: parseRoles(process.env.SSI_RBAC_DEFAULT_ROLES || 'admin'),
  roleBindings: parseRoleBindings(process.env.SSI_RBAC_ROLE_BINDINGS || ''),
  // oauth2-proxy/Entra ID: X-Forwarded-Groups → SSI rolleri (ör. "SSI-Approvers:approver").
  groupRoleMap: parseRoleBindings(process.env.SSI_RBAC_GROUP_ROLE_MAP || ''),
};

// Dev/demo login: yalnızca SSI_DEV_LOGIN=true iken. Gerçek kimlik doğrulama DEĞİLDİR;
// UI bir kullanıcı+rol seçtirir ve api.js kimlik header'ı gönderir — RBAC'ı canlı
// göstermek/demolamak için. Production'da KAPALI; kimlik SSO/proxy'den gelir.
const devLoginEnabled = rbacConfig.devLogin;

// Multi-tenancy (src/lib/tenancy.js). Off by default: every record is in the 'default' team
// and the global user role applies. Refuses to start when enabled without RBAC enforcement.
const tenancyConfig = buildTenancyConfig(process.env, { rbacEnforced: rbacConfig.enforced });
// Token/HMAC-authenticated worker callbacks act on the record their authenticated request
// names, in whichever team it belongs to.
const WORKER_SCOPE = ALL_TENANTS;

// Oturum imzalama sırrı + çerez güvenliği. Çerezler HTTPS arkasında Secure olmalı;
// yalnızca izole yerel testte SSI_SESSION_COOKIE_SECURE=false ile kapatılır.
const sessionSecret = String(process.env.SSI_SESSION_SECRET || '');
const secureCookies = String(process.env.SSI_SESSION_COOKIE_SECURE || 'true').toLowerCase() !== 'false';

// Lokal admin (LDAP'sız bootstrap yönetici) + kullanıcı deposu (rol yönetimi).
const localAdmin = parseLocalAdmin(process.env);
const userStore = createUserStore({ driver: persistenceDriver, pool: databasePool });
const tenantStore = createTenantStore({ driver: persistenceDriver, pool: databasePool });
// Server-side sign-out (revoked session ids) and sign-in throttling.
const sessionRevocations = createSessionRevocations({ driver: persistenceDriver, pool: databasePool });
const loginThrottle = createLoginThrottle();

// LDAP bağlantısı — Casey'ın verdiği env seti. FQDN (sertifika CN'iyle uyumlu) tercih
// edilir; yoksa IP. TLS doğrulaması LDAP_VERIFY ile (iç ortamda kapalı olabilir).
function buildLdapUrl() {
  if (process.env.LDAP_URL) return process.env.LDAP_URL;
  const host = process.env.LDAP_FQDN || process.env.LDAP_SERVER;
  if (!host) return '';
  const port = process.env.LDAP_PORT || '636';
  const scheme = String(process.env.LDAP_SSL || 'true').toLowerCase() === 'false' ? 'ldap' : 'ldaps';
  return `${scheme}://${host}:${port}`;
}
const ldapConfig = {
  url: buildLdapUrl(),
  baseDN: process.env.LDAP_BASE_DN || '',
  bindDN: process.env.LDAP_BIND_DN || '',
  bindPassword: process.env.LDAP_BIND_PASSWORD || '',
  userFilter: process.env.LDAP_USER_FILTER || '(sAMAccountName={username})',
  // Secure by default: verify the directory certificate unless LDAP_VERIFY=false.
  tlsRejectUnauthorized: String(process.env.LDAP_VERIFY || 'true').toLowerCase() !== 'false',
  caCert:
    process.env.LDAP_CA_FILE && existsSync(process.env.LDAP_CA_FILE)
      ? readFileSync(process.env.LDAP_CA_FILE)
      : undefined,
};
const ldapEnabled = isLdapConfigured(ldapConfig);

// resolveIdentity için canlı rol/durum çözücü: lokal admin her zaman admin/aktif;
// diğerleri kullanıcı deposundan (admin rolü değiştirir/pasife alırsa anında yansır).
function resolveUserForIdentity(username) {
  if (isLocalAdminUsername(localAdmin, username)) return { role: 'admin', status: 'active' };
  const user = userStore.get(username);
  return user ? { role: user.role, status: user.status } : null;
}

// UI topbar için görünen ad (yoksa kullanıcı adına düşer).
function sessionDisplayName(username) {
  if (isLocalAdminUsername(localAdmin, username)) return localAdmin.displayName;
  const user = userStore.get(username);
  return user ? user.displayName : username;
}

// Oturum çerezi + canlı rol çözümü RBAC'a bağlanır (kimlik tek noktadan çözülür).
rbacConfig.sessionSecret = sessionSecret;
rbacConfig.resolveUser = resolveUserForIdentity;
rbacConfig.isSessionRevoked = (jti) => sessionRevocations.isRevoked(jti);

// Fail fast on an insecure session configuration: a configured secret must be at least
// 32 bytes, and password sign-in (LDAP / local admin) cannot work without one.
const passwordLoginConfigured = ldapEnabled || Boolean(localAdmin);
if (sessionSecret || passwordLoginConfigured) {
  const problem = sessionSecretProblem(sessionSecret);
  if (problem) throw new Error(`Refusing to start: ${problem}`);
}

const contentTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
};

function isFile(path) {
  return existsSync(path) && statSync(path).isFile();
}

// Browsers cap a cookie at 4096 bytes; a server-built Set-Cookie is never truncated to
// the short dynamic-header limit, because a cut value silently loses its Path/Secure
// attributes and scopes the session to the wrong path.
const MAX_SET_COOKIE_LENGTH = 4096;

function sendJson(response, status, body, headers = {}) {
  // Dinamik başlık değerleri (ör. ham scan hatası) Node'un http modülünü
  // ERR_INVALID_CHAR ile düşürebilir; bu da state değiştikten sonra cevabın
  // yazılamamasına ve çağıranın idempotent olmayan retry'lar denemesine yol açar.
  const { 'Set-Cookie': setCookie, ...dynamicHeaders } = headers;
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...sanitizeHeaders(dynamicHeaders),
    ...(setCookie ? { 'Set-Cookie': sanitizeHeaderValue(setCookie, { maxLength: MAX_SET_COOKIE_LENGTH }) } : {}),
  });
  response.end(JSON.stringify(body));
}

function sendDocument(response, status, html, { disposition = 'inline', filename = 'document.html', dataSource = '' } = {}) {
  const safeName = String(filename).replace(/[^A-Za-z0-9._-]/g, '_') || 'document.html';
  const safeDisposition = disposition === 'attachment' ? 'attachment' : 'inline';
  response.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': DOCUMENT_CSP,
    ...sanitizeHeaders({
      'Content-Disposition': `${safeDisposition}; filename="${safeName}"`,
      'X-SSI-Data-Source': dataSource,
    }),
  });
  response.end(html);
}

class ApiRequestError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function requestContext(request) {
  const requestedCorrelationId = String(request.headers['x-correlation-id'] || '').trim();
  const identity = resolveIdentity(request, rbacConfig);

  return {
    actorId: identity.subject,
    // Trusted actor = the subject came from a signed session, the authenticating proxy or
    // (demo only) dev login. A raw client header on its own is never trusted.
    trustedActor: isTrustedIdentity(identity),
    identity,
    correlationId: uuidPattern.test(requestedCorrelationId) ? requestedCorrelationId : randomUUID(),
  };
}

function auditFor(context, values) {
  return buildAuditEvent({
    actorId: context.actorId,
    correlationId: context.correlationId,
    ...values,
  });
}

// ── Tenant context ─────────────────────────────────────────────────────────────
// The team a request acts in (X-SSI-Tenant header, or the caller's only team) and the
// roles that apply there. Memberships and teams come from the tenantStore mirror (sync).
// A document opened as a plain browser link (the remediation report) cannot send a header;
// that one read-only route also takes the team as ?tenant=.
function requestedTenant(request) {
  const header = String(request.headers[TENANT_HEADER] || '');
  if (header || request.method !== 'GET') return header;
  const url = new URL(request.url || '/', 'http://localhost');
  return /^\/api\/v1\/reports\/remediation\/[^/]+\/document$/.test(url.pathname) ? url.searchParams.get('tenant') || '' : '';
}

function resolveRequestTenancy(request, identity, { ignoreSelection = false } = {}) {
  return resolveTenantContext({
    config: tenancyConfig,
    identity,
    requested: ignoreSelection ? '' : requestedTenant(request),
    memberships: identity?.authenticated ? tenantStore.membershipsForUser(identity.subject) : [],
    getTenant: (id) => tenantStore.getTenant(id),
  });
}

// With multi-tenancy on, the team role replaces the global role for the request; the global
// roles stay visible as globalRoles. Off, the identity is unchanged.
function identityForTenancy(identity, tenancy) {
  if (!tenancy?.enabled) return identity;
  return {
    ...identity,
    globalRoles: identity.roles,
    roles: tenancy.roles,
    permissions: permissionsForRoles(tenancy.roles),
  };
}

// The scope every data-store call of a user request runs in; refuses without one.
function requestScope(context) {
  return assertTenantSelected(context.tenancy);
}

// The single existing team a request acts in (null: platform-wide or none). Used to label
// audit events that are not written with a record.
function contextTenantId(context) {
  const id = context.tenancy?.tenantId;
  return id && isValidTenantId(id) && tenantStore.getTenant(id) ? id : null;
}

// A requested team id as it may appear in an audit record (user input).
function requestedTenantLabel(request) {
  const value = normalizeTenantId(requestedTenant(request));
  if (!value) return '';
  return isValidTenantId(value) ? value : '[invalid]';
}

// ── Team Harbor targets and ownership (multi-tenancy phase 2) ──────────────────
// While multi-tenancy is off every one of these answers today's platform values, so
// targets, policy and inventory are exactly as before.
function tenantHarborAreas(tenants = tenantStore.listTenants()) {
  return teamHarborAreas(tenants, platformHarborTargets);
}

function targetsForTenant(tenantId) {
  if (!tenancyConfig.enabled) return platformHarborTargets;
  const tenant = tenantStore.getTenant(tenantId || DEFAULT_TENANT_ID);
  if (!tenant) throw new TenancyError(404, 'Team not found.');
  return teamTargets(tenant, platformHarborTargets);
}

// The publish policy of a team: the same rules, with the team's approved folder as the
// registry boundary, so a team can never publish into another team's area.
function publishConfigFor(tenantId) {
  if (!tenancyConfig.enabled) return publishPolicyConfig;
  return { ...publishPolicyConfig, target: { ...publishPolicyConfig.target, ...targetsForTenant(tenantId).publish } };
}

// Work orders name the team of their record (multi-tenancy on); workers take every target
// from the work order, never from a parameter.
function withHandoffTenant(handoff, tenantId) {
  return tenancyConfig.enabled ? { ...handoff, tenantId } : handoff;
}

// Scan results the scope may see (multi-tenancy on: the team's own images only).
async function getScanDataInScope(scope) {
  const scans = await getScanData();
  if (!tenancyConfig.enabled) return scans;
  const reports = scans.reports
    .map((report) => (report.tenantId ? report : { ...report, tenantId: DEFAULT_TENANT_ID }))
    .filter((report) => isVisibleScanReport(report, scope));
  return { ...scans, reports };
}

// Two teams never share a Harbor folder: checked against the team list as it would be.
function assertHarborFoldersAvailable(nextTenants) {
  assertDistinctHarborAreas(tenantHarborAreas(nextTenants));
}

// Session view of the caller's teams (the console's team switcher).
function sessionTenancy(context) {
  const tenancy = context.tenancy;
  if (!tenancy?.enabled) {
    return { enabled: false, tenantId: DEFAULT_TENANT_ID, platformAdmin: tenancy?.platformAdmin || false, teams: [] };
  }
  const teams = tenancy.platformAdmin
    ? tenantStore
        .listTenants()
        .map((tenant) => ({ id: tenant.id, displayName: tenant.displayName, status: tenant.status, role: PLATFORM_ADMIN_ROLE }))
    : context.identity.authenticated
      ? tenantStore
          .membershipsForUser(context.identity.subject)
          .map((membership) => ({ membership, tenant: tenantStore.getTenant(membership.tenantId) }))
          .filter(({ tenant }) => tenant?.status === 'active')
          .map(({ membership, tenant }) => ({
            id: tenant.id,
            displayName: tenant.displayName,
            status: tenant.status,
            role: membership.role,
          }))
      : [];
  return {
    enabled: true,
    tenantId: tenancy.tenantId,
    platformAdmin: tenancy.platformAdmin,
    selectionRequired: tenancy.selectionRequired,
    // Set when the requested team was refused: the console drops its selection.
    selectionError: context.tenancySelectionError || '',
    teams,
  };
}

// Errors whose message was written for the caller. Anything else is unexpected: its
// message may carry internals (SQL, hosts, stack details) and is never returned.
const CLIENT_SAFE_ERRORS = [
  ApiRequestError,
  AzureDevOpsError,
  PipelineRunError,
  CanonicalTrivyValidationError,
  RemediationScopeError,
  SupplyChainEvidenceValidationError,
  CandidateTestValidationError,
  RemediationEvidenceValidationError,
  WorkerEvidenceAuthenticationError,
  RemediationStoreConflictError,
  PublishPolicyValidationError,
  OnboardingValidationError,
  ExceptionValidationError,
  UserStoreError,
  TenancyError,
  ImageComparisonError,
  ImageInspectionError,
  OsTemplateError,
  OsTemplateDownloadError,
  DownloadTicketError,
  AuditQueryError,
];

function isClientSafeError(error) {
  return CLIENT_SAFE_ERRORS.some((ErrorType) => error instanceof ErrorType);
}

function errorStatus(error) {
  return isClientSafeError(error) ? error.statusCode || 422 : 500;
}

const UNEXPECTED_ERROR_MESSAGE = 'An unexpected error occurred. Quote the correlation ID when reporting it.';

// Single error response path: client-safe errors keep their message; unexpected ones
// are logged in full under the correlation ID and answered with a generic 500.
function sendError(response, context, error) {
  if (isClientSafeError(error)) {
    sendJson(response, errorStatus(error), { message: error.message });
    return;
  }
  console.error(`[${context.correlationId}] Unexpected error: ${error?.stack || error}`);
  sendJson(response, 500, { message: UNEXPECTED_ERROR_MESSAGE, correlationId: context.correlationId });
}

// Audit actor for a token-authenticated worker callback: the worker id reported in
// its receipt, bounded to the worker-id character set. The token proves the caller is
// the worker; the id says which agent ran it.
function workerActor(kind, workerId) {
  const id = String(workerId || '').replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 128);
  return id ? `${kind}:${id}` : kind;
}

function secureTokenMatches(expected, received) {
  const expectedBuffer = Buffer.from(String(expected || ''), 'utf8');
  const receivedBuffer = Buffer.from(String(received || ''), 'utf8');
  return (
    expectedBuffer.length > 0 &&
    expectedBuffer.length === receivedBuffer.length &&
    timingSafeEqual(expectedBuffer, receivedBuffer)
  );
}

// CSV of every event the filters match in an explicit period (GET /audit-events/export). The
// period ends at the moment of the request at the latest (asOf), so the row count stated in
// X-SSI-Audit-Rows and in the audit record is the file's own, and the export's own audit record
// is not part of it. The count is checked first: a request over the limit is refused before
// anything is sent rather than cut off mid-file. Rows are streamed page by page.
const AUDIT_EXPORT_PAGE = 1000;

async function exportAuditEvents(response, context, searchParams) {
  const scope = requestScope(context);
  let filters = null;
  let total = 0;
  const asOf = new Date().toISOString();
  try {
    filters = parseAuditExport(searchParams);
    if (Date.parse(filters.to) > Date.parse(asOf)) filters = { ...filters, to: asOf };
    if (Date.parse(filters.from) >= Date.parse(filters.to)) {
      throw new ApiRequestError(400, 'The export period starts in the future');
    }
    total = await remediationStore.countAuditEvents({ filters }, scope);
    if (total > AUDIT_EXPORT_MAX_ROWS) {
      throw new ApiRequestError(
        422,
        `${total} events match; one export holds at most ${AUDIT_EXPORT_MAX_ROWS}. Narrow the period or the filters.`,
      );
    }
  } catch (error) {
    await recordRejectedMutation(
      context,
      {
        eventType: 'audit.export.rejected',
        action: 'export-audit-events',
        resourceType: 'audit-log',
        resourceId: 'export',
        summary: 'Audit export refused',
        metadata: filters ? { filters, matching: total } : {},
      },
      error,
    );
    throw error;
  }

  await remediationStore.appendAuditEvent(
    auditFor(context, {
      tenantId: contextTenantId(context),
      eventType: 'audit.exported',
      action: 'export-audit-events',
      resourceType: 'audit-log',
      resourceId: 'export',
      summary: `Audit log exported: ${total} events from ${filters.from} to ${filters.to}`,
      metadata: { filters, rows: total, format: 'csv', asOf },
    }),
  );

  response.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...sanitizeHeaders({
      'Content-Disposition': `attachment; filename="${auditExportFilename(filters)}"`,
      'X-SSI-Data-Source': `audit-${remediationStore.driver}`,
      'X-SSI-Audit-Rows': String(total),
    }),
  });
  // UTF-8 byte order mark: spreadsheet programs then read Turkish characters correctly.
  await writeChunk(response, `\uFEFF${auditCsvLine(AUDIT_CSV_COLUMNS)}`);
  let before = null;
  let written = 0;
  do {
    const page = await remediationStore.queryAuditEvents({ limit: AUDIT_EXPORT_PAGE, before, filters }, scope);
    const rows = page.events.slice(0, AUDIT_EXPORT_MAX_ROWS - written);
    if (rows.length > 0 && !(await writeChunk(response, rows.map(auditCsvRow).join('')))) return;
    written += rows.length;
    before = page.nextCursor;
  } while (before && written < AUDIT_EXPORT_MAX_ROWS);
  response.end();
}

// Writes a chunk and waits while the client's buffer is full; false once the client has gone.
function writeChunk(response, chunk) {
  if (response.destroyed) return Promise.resolve(false);
  if (response.write(chunk)) return Promise.resolve(true);
  return new Promise((resolve) => {
    const done = (value) => () => {
      response.off('drain', onDrain);
      response.off('close', onClose);
      resolve(value);
    };
    const onDrain = done(true);
    const onClose = done(false);
    response.once('drain', onDrain);
    response.once('close', onClose);
  });
}

// Every receipt still accepted with a legacy token is logged, so the end of the migration
// (removing the token) can be timed on evidence rather than guessed.
function warnLegacyReceipt(authentication, what, tokenVariable) {
  if (authentication.method === RECEIPT_AUTHENTICATION.LEGACY_TOKEN) {
    console.warn(`${what} was accepted with the legacy ${tokenVariable}, not a signature.`);
  }
}

// A decoded path segment, or '' when it is not valid percent-encoding (the caller answers
// 400 instead of failing with an unexpected error).
function pathSegment(value) {
  try {
    return decodeURIComponent(String(value || ''));
  } catch {
    return '';
  }
}

function isAuthorizedPublishApprover(context) {
  if (!context.trustedActor) return false;
  const roles = (context.identity?.roles || []).map((role) => String(role).trim().toLowerCase());
  if (roles.some((role) => publishPolicyConfig.approval.approverRoles.includes(role))) return true;
  const actor = String(context.actorId || '').trim().toLowerCase();
  return (
    publishPolicyConfig.approval.approvers.length > 0 &&
    publishPolicyConfig.approval.approvers.includes(actor)
  );
}

// Returns the scope of the handoff read: the approver's own (an approver previews the
// handoff of a request in their team), or every team for the authenticated worker.
function authorizePublishHandoff(request, context) {
  if (isAuthorizedPublishApprover(context)) return requestScope(context);

  const handoffToken = process.env.SSI_PUBLISH_HANDOFF_TOKEN || '';
  if (!handoffToken) {
    throw new ApiRequestError(503, 'Publish worker handoff authentication is not configured');
  }
  if (!secureTokenMatches(handoffToken, request.headers['x-ssi-publish-handoff-token'])) {
    throw new ApiRequestError(403, 'Publish worker handoff authentication failed');
  }
  return WORKER_SCOPE;
}

async function recordRejectedMutation(context, values, error) {
  try {
    await remediationStore.appendAuditEvent(
      auditFor(context, {
        tenantId: contextTenantId(context),
        ...values,
        outcome: errorStatus(error) === 403 ? 'denied' : 'failure',
        severity: 'error',
        summary: `${values.summary}: ${error.message}`,
        metadata: { ...(values.metadata || {}), statusCode: errorStatus(error) },
      }),
    );
  } catch (auditError) {
    console.error(`Audit event could not be persisted: ${auditError.message}`);
  }
}

function readJsonBody(request, { maxBytes = maxRequestBodyBytes, withRawBody = false } = {}) {
  return new Promise((resolve, reject) => {
    const contentType = request.headers['content-type'] || '';
    if (!contentType.includes('application/json')) {
      request.resume();
      reject(new ApiRequestError(415, 'Content-Type must be application/json'));
      return;
    }

    const contentLength = Number(request.headers['content-length'] || 0);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
      request.resume();
      reject(new ApiRequestError(413, 'Request body is too large'));
      return;
    }

    let body = '';
    let size = 0;
    let rejected = false;

    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      size += Buffer.byteLength(chunk, 'utf8');
      if (size > maxBytes) {
        rejected = true;
        request.resume();
        reject(new ApiRequestError(413, 'Request body is too large'));
        return;
      }

      if (!rejected) {
        body += chunk;
      }
    });
    request.on('error', reject);
    request.on('end', () => {
      if (rejected) {
        return;
      }

      if (!body.trim()) {
        resolve(withRawBody ? { data: {}, rawBody: body } : {});
        return;
      }

      try {
        const parsed = JSON.parse(body);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('JSON body must be an object');
        }
        resolve(withRawBody ? { data: parsed, rawBody: body } : parsed);
      } catch (error) {
        reject(new ApiRequestError(400, `Invalid JSON body: ${error.message}`));
      }
    });
  });
}

function hasHarborConfig() {
  return Boolean(harbor.url && harbor.projects.length > 0 && harbor.username && harbor.secret);
}

class HarborApiError extends Error {
  constructor(statusCode, body, statusMessage) {
    super(`Harbor ${statusCode}: ${body || statusMessage || 'Request failed'}`);
    this.statusCode = statusCode;
  }
}

function harborJson(pathname, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(pathname, harbor.url);
    const client = url.protocol === 'https:' ? httpsRequest : httpRequest;
    const auth = Buffer.from(`${harbor.username}:${harbor.secret}`, 'utf8').toString('base64');
    const request = client(
      url,
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: `Basic ${auth}`,
          ...headers,
        },
        rejectUnauthorized: harbor.tlsVerify,
        timeout: 10000,
      },
      (incoming) => {
        let body = '';

        incoming.setEncoding('utf8');
        incoming.on('data', (chunk) => {
          body += chunk;
        });
        incoming.on('end', () => {
          if ((incoming.statusCode || 500) < 200 || (incoming.statusCode || 500) >= 300) {
            reject(new HarborApiError(incoming.statusCode || 500, body, incoming.statusMessage));
            return;
          }

          try {
            resolve(body ? JSON.parse(body) : null);
          } catch (error) {
            reject(new Error(`Harbor JSON parse failed: ${error.message}`));
          }
        });
      },
    );

    request.on('timeout', () => {
      request.destroy(new Error('Harbor request timed out'));
    });
    request.on('error', reject);
    request.end();
  });
}

async function loadHarborArtifacts() {
  const entries = [];

  for (const project of harbor.projects) {
    const repositories = await collectAllPages((page) =>
      harborJson(
        `/api/v2.0/projects/${encodeURIComponent(project)}/repositories?page=${page}&page_size=100`,
      ),
    );

    for (const repository of repositories) {
      const repoName = harborRelativeRepositoryName(project, repository);
      const artifacts = await collectAllPages((page) =>
        harborJson(
          `/api/v2.0/projects/${encodeURIComponent(project)}/repositories/${encodeHarborRepositoryName(
            repoName,
          )}/artifacts?page=${page}&page_size=100&with_tag=true&with_scan_overview=true`,
        ),
      );

      for (const artifact of artifacts) {
        entries.push({ project, repository, repoName, artifact });
      }
    }
  }

  return entries;
}

async function loadHarborImages() {
  const entries = await loadHarborArtifacts();
  return entries.map(({ project, repository, artifact }) =>
    mapHarborArtifact({ project, repository, artifact }),
  );
}

async function getInventoryData() {
  if (!hasHarborConfig()) {
    return fixturesEnabled
      ? { images: seedImages, source: 'fixture', error: '' }
      : { images: [], source: 'unconfigured', error: HARBOR_NOT_CONFIGURED };
  }

  try {
    const images = await loadHarborImages();

    if (images.length === 0) {
      return {
        images: [],
        source: 'harbor-empty',
        error: `Harbor projects (${harbor.projects.join(', ')}) have no repositories/artifacts yet.`,
      };
    }

    return { images, source: 'harbor', error: '' };
  } catch (error) {
    return { images: [], source: 'harbor-error', error: error.message };
  }
}

// Inventory enriched with SSI's verified supply-chain evidence (signature / SBOM /
// provenance by immutable digest) and the approved/ production boundary.
// scope: the request's tenant scope. With multi-tenancy on the caller sees the team's own
// images plus the shared catalog of published (approved) images, each labelled with its
// team. The evidence flags (signature, SBOM, withdrawal) of a published image come from the
// job that produced it, whichever team ran it: a withdrawn image must read "do not use" in
// every team. Only those flags are taken from other teams' jobs.
async function getInventoryWithEvidence(scope) {
  const inventory = await getInventoryData();
  let jobs = [];
  let evidenceError = '';
  try {
    jobs = await remediationStore.listJobs(ALL_TENANTS);
  } catch (error) {
    console.error(`Supply-chain evidence could not be read for the inventory: ${error.message}`);
    evidenceError = 'Supply-chain evidence could not be read.';
  }
  const images = applySupplyChainEvidence(inventory.images, jobs, {
    project: publishPolicyConfig.target.project,
    repositoryPrefix: publishPolicyConfig.target.repositoryPrefix,
  });
  return {
    ...inventory,
    images: tenancyConfig.enabled
      ? annotateOwnership(images, tenantHarborAreas(), (image) => ({ project: image.project, repository: image.repository }))
          .filter((image) => isVisibleImage(image, scope))
      : images,
    error: [inventory.error, evidenceError].filter(Boolean).join(' '),
  };
}

function scanArtifactReference(artifact) {
  return artifact.digest || artifact.tags?.[0]?.name || '';
}

const SCAN_STATE_NAME_LIMIT = 3;

// "2 Harbor artifact scans not finished yet: onboarded/nginx:1.27, approved/app:r1."
// Names tell the operator which artifacts to scan in Harbor; the list is capped so the
// message stays readable (and within the data-error header limit).
function scanStateMessage(count, state, names = []) {
  const head = count === 1 ? `1 Harbor artifact scan ${state}` : `${count} Harbor artifact scans ${state}`;
  if (names.length === 0) return `${head}.`;
  const shown = names.slice(0, SCAN_STATE_NAME_LIMIT).join(', ');
  const more = names.length > SCAN_STATE_NAME_LIMIT ? ` and ${names.length - SCAN_STATE_NAME_LIMIT} more` : '';
  return `${head}: ${shown}${more}.`;
}

function scanArtifactLabel(repoName, artifact) {
  const tag = artifact?.tags?.[0]?.name || String(artifact?.digest || '').slice(7, 19) || 'untagged';
  return `${repoName}:${tag}`;
}

async function loadHarborScanReports() {
  const artifacts = await loadHarborArtifacts();

  if (artifacts.length === 0) {
    return {
      reports: [],
      source: 'harbor-empty',
      error: `Harbor projects (${harbor.projects.join(', ')}) have no repositories/artifacts yet.`,
    };
  }

  // Cosign signatures, attestations and SBOMs are not images: they never have a scan report
  // and must not show up as "could not be read" on every screen.
  const entries = artifacts.filter(({ artifact }) => !isCosignAccessoryArtifact(artifact));
  const reports = [];
  const pending = [];
  const failed = [];
  // The team of each image (multi-tenancy on); filtered per request in getScanDataInScope.
  const areas = tenancyConfig.enabled ? tenantHarborAreas() : null;

  for (const { project, repoName, artifact } of entries) {
    const overview = findHarborScanOverview(artifact);
    const scanStatus = harborScanStatus(overview);

    if (!isHarborScanComplete(overview)) {
      if (['error', 'failed', 'stopped'].includes(scanStatus)) {
        failed.push(scanArtifactLabel(repoName, artifact));
      } else {
        pending.push(scanArtifactLabel(repoName, artifact));
      }
      continue;
    }

    const reference = scanArtifactReference(artifact);
    if (!reference) {
      failed.push(scanArtifactLabel(repoName, artifact));
      continue;
    }

    try {
      const report = await harborJson(
        `/api/v2.0/projects/${encodeURIComponent(project)}/repositories/${encodeHarborRepositoryName(repoName)}/artifacts/${encodeURIComponent(reference)}/additions/vulnerabilities`,
        { 'X-Accept-Vulnerabilities': HARBOR_VULNERABILITY_REPORT_MIME },
      );
      const normalized = normalizeHarborVulnerabilityReport({
        report,
        project,
        repository: repoName,
        artifact,
        overview,
      });
      reports.push(areas ? { ...normalized, ...ownerOfRepository({ project, repository: repoName }, areas) } : normalized);
    } catch (error) {
      console.error(`Harbor scan report for ${scanArtifactLabel(repoName, artifact)} could not be read: ${error.message}`);
      failed.push(scanArtifactLabel(repoName, artifact));
    }
  }

  if (reports.length > 0) {
    const messages = [];
    if (pending.length > 0) messages.push(scanStateMessage(pending.length, 'not finished yet', pending));
    if (failed.length > 0) messages.push(scanStateMessage(failed.length, 'could not be read', failed));

    return {
      reports,
      source: pending.length || failed.length ? 'harbor-partial' : 'harbor',
      error: messages.join(' '),
    };
  }

  if (failed.length > 0) {
    return {
      reports: [],
      source: 'harbor-scan-error',
      error: scanStateMessage(failed.length, 'could not be read', failed),
    };
  }

  return {
    reports: [],
    source: 'harbor-scan-pending',
    error: scanStateMessage(pending.length || entries.length, 'not finished yet', pending),
  };
}

async function getScanData() {
  if (hasHarborConfig()) {
    try {
      return await loadHarborScanReports();
    } catch (error) {
      return { reports: [], source: 'harbor-scan-error', error: error.message };
    }
  }

  if (!fixturesEnabled) {
    return { reports: [], source: 'unconfigured', error: HARBOR_NOT_CONFIGURED };
  }

  const normalizedTrivyReports = trivyScanSamples.map((scan) => normalizeTrivyScan(scan));

  return {
    reports: [...normalizedTrivyReports, ...scanReports],
    source: normalizedTrivyReports.length > 0 ? 'trivy-fixture' : 'fixture',
    error: '',
  };
}

function reportSeveritySummary(report = {}) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };

  for (const finding of report.findings || []) {
    const key = String(finding.severity || 'unknown').trim().toLowerCase();
    summary[Object.hasOwn(summary, key) ? key : 'unknown'] += 1;
  }

  return summary;
}

function scanReportByDigest(reports, digest) {
  const expected = String(digest || '').trim().toLowerCase();
  return reports.find((report) => String(report.digest || '').trim().toLowerCase() === expected);
}

function buildFullImageComparison(reports, evidence) {
  const sourceReport = scanReportByDigest(reports, evidence.source?.digest);
  const outputReport = scanReportByDigest(reports, evidence.output?.digest);

  if (!sourceReport || !outputReport) {
    return {
      status: 'unavailable',
      reason: 'Full-image Harbor scan reports were not available for both immutable digests when evidence was accepted.',
    };
  }

  const sourceFindings = sourceReport.findings?.length || 0;
  const outputFindings = outputReport.findings?.length || 0;
  const canonicalOsRemaining = Number(evidence.verification?.after?.findings) || 0;

  return {
    status: 'available',
    scope: 'full-image',
    scanner: outputReport.scanner || sourceReport.scanner || 'Trivy',
    scannedAt: outputReport.scannedAt || '',
    source: {
      digest: sourceReport.digest,
      findings: sourceFindings,
      severity: reportSeveritySummary(sourceReport),
    },
    output: {
      digest: outputReport.digest,
      findings: outputFindings,
      severity: reportSeveritySummary(outputReport),
    },
    reducedBy: sourceFindings - outputFindings,
    remainingOutsideCanonicalOsScope: Math.max(outputFindings - canonicalOsRemaining, 0),
  };
}

// ── Risk acceptance (policy exceptions) ────────────────────────────────────────
const EXCEPTION_DECISION_EVENTS = {
  approve: { eventType: 'exception.approved', verb: 'approved', noun: 'approval', severity: 'warning' },
  reject: { eventType: 'exception.rejected', verb: 'rejected', noun: 'rejection', severity: 'info' },
  revoke: { eventType: 'exception.revoked', verb: 'revoked', noun: 'revocation', severity: 'info' },
};

// Keeps the Azure DevOps run of an approved template, so its files outlive the retention
// policy. Without the integration the approval is recorded with the run left to be retained
// by hand; with it, a lease that cannot be created stops the approval.
async function retainTemplateRun(target) {
  if (!azureDevOps.enabled) {
    return {
      secured: false,
      runId: target.runId,
      reason: 'Azure DevOps integration is not configured; retain the run in Azure DevOps by hand.',
    };
  }
  const lease = await azureDevOps.addRetentionLease(target);
  return {
    secured: true,
    runId: target.runId,
    leaseId: lease.leaseId,
    validUntil: lease.validUntil,
    securedAt: new Date().toISOString(),
  };
}

// Streams one download of a built OS template from Azure DevOps to the browser. The ticket
// (one use, five minutes) stands for the signed-in user who asked for it; the request is
// checked again here (status, download, run). Nothing is written to SSI's disk.
async function streamOsTemplateDownload(request, response, context, buildId, ticket) {
  let claims = null;
  let download;
  let actorContext = context;
  // What the browser asked for: a resumed download (Chrome "Keep"/"Resume") sends a Range.
  const requested = { use: null, range: String(request.headers.range || '').slice(0, 80) || null };
  const audit = (eventType, summary, metadata, outcome = 'success') =>
    remediationStore
      .appendAuditEvent(
        auditFor(actorContext, {
          tenantId: null,
          eventType,
          action: 'download-os-template',
          resourceType: 'os-template',
          resourceId: buildId.slice(0, 80) || 'unknown',
          outcome,
          summary,
          metadata: { ...requested, ...metadata },
        }),
      )
      .catch((error) => console.error(`Audit event could not be persisted: ${error.message}`));
  try {
    if (!OS_TEMPLATE_BUILD_ID.test(buildId)) throw new ApiRequestError(400, 'Invalid OS template build ID');
    claims = osTemplateDownloadTickets.redeem(ticket, { subject: buildId });
    requested.use = claims.use;
    actorContext = { ...context, actorId: claims.actorId, trustedActor: true };
    const build = await remediationStore.getOsTemplateBuild(buildId);
    if (!build) throw new ApiRequestError(404, 'OS template build request not found');
    download = findOsTemplateDownload(build, claims.downloadId);
  } catch (error) {
    if (claims) {
      await audit('os-template.download.failed', `OS template ${buildId}: download refused`, { reason: error.message?.slice(0, 200) }, 'failure');
    }
    sendError(response, context, error);
    return;
  }

  // Who ended the transfer, for the audit record: the browser closed the connection, Azure
  // DevOps broke off the stream, or nothing moved for DOWNLOAD_IDLE_TIMEOUT_MS.
  let closedBy = null;
  let sourceError = '';
  const abort = new AbortController();
  response.once('close', () => {
    if (!response.writableFinished && !closedBy) closedBy = 'browser';
    abort.abort();
  });
  let source;
  try {
    source = await azureDevOps.openArtifact(download.runId, download.artifact, { signal: abort.signal });
  } catch (error) {
    await audit(
      'os-template.download.failed',
      `OS template ${buildId}: ${download.fileName} could not be read from Azure DevOps`,
      { download: download.id, closedBy: closedBy || 'azure-devops', reason: error.message?.slice(0, 200) },
      'failure',
    );
    if (!response.headersSent && !response.destroyed) sendError(response, context, error);
    return;
  }

  response.writeHead(200, {
    'Content-Type': 'application/zip',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    // Stream through a buffering reverse proxy (nginx) instead of spooling gigabytes to its disk.
    'X-Accel-Buffering': 'no',
    ...(source.contentLength !== null ? { 'Content-Length': String(source.contentLength) } : {}),
    ...sanitizeHeaders({ 'Content-Disposition': `attachment; filename="${download.fileName.replace(/[^A-Za-z0-9._-]/g, '_')}"` }),
  });
  let bytes = 0;
  let idle = null;
  const touch = () => {
    clearTimeout(idle);
    idle = setTimeout(() => {
      closedBy = closedBy || 'idle-timeout';
      abort.abort();
      source.stream.destroy(new Error(`No data for ${DOWNLOAD_IDLE_TIMEOUT_MS / 1000} seconds.`));
    }, DOWNLOAD_IDLE_TIMEOUT_MS);
  };
  touch();
  source.stream.on('data', (chunk) => {
    bytes += chunk.length;
    touch();
  });
  source.stream.once('error', (error) => {
    if (!closedBy) closedBy = 'azure-devops';
    sourceError = String(error?.message || error).slice(0, 200);
  });
  const facts = () => ({
    download: download.id,
    artifact: download.artifact,
    adoRunId: download.runId,
    bytes,
    expectedBytes: source.contentLength,
  });
  try {
    await streamPipeline(source.stream, response);
    if (source.contentLength !== null && bytes !== source.contentLength) {
      await audit('os-template.download.failed', `OS template ${buildId}: ${download.fileName} ended after ${bytes} of ${source.contentLength} bytes`, { ...facts(), closedBy: 'azure-devops' }, 'failure');
    } else {
      await audit('os-template.download.completed', `OS template ${buildId}: ${download.fileName} downloaded (${bytes} bytes)`, facts());
    }
  } catch (error) {
    const by = closedBy || 'unknown';
    await audit(
      'os-template.download.failed',
      `OS template ${buildId}: ${download.fileName} interrupted after ${bytes} bytes (closed by ${by})`,
      { ...facts(), closedBy: by, reason: sourceError || String(error?.code || error?.message || '').slice(0, 200) },
      'failure',
    );
    response.destroy();
  } finally {
    clearTimeout(idle);
  }
}

// Exceptions are always attributed to a signed-in user; without a trusted identity the
// request is refused (fail-closed), even when RBAC is not enforced.
function requireTrustedActor(context, message) {
  if (!context.trustedActor || !String(context.actorId || '').trim()) {
    throw new ApiRequestError(403, message);
  }
}

function exceptionView(exception, now = new Date()) {
  return { ...exception, effectiveStatus: effectiveExceptionStatus(exception, now) };
}

// Gathers the inputs for the publish gate's risk acceptance step; the matching rules are
// in buildExceptionAdjustment (src/lib/policyExceptions.js).
// Risk acceptances are a team's own: only the job's team's exceptions apply to its image.
async function exceptionAdjustmentFor(job) {
  let exceptions;
  try {
    exceptions = await remediationStore.listExceptions(tenantScope([job.tenantId]));
  } catch (error) {
    console.error(`Risk acceptances could not be read for publish evaluation: ${error.message}`);
    return { status: 'unavailable', reason: 'risk acceptances could not be read.' };
  }
  const now = new Date();
  if (!exceptions.some((item) => isExceptionActive(item, now))) return { status: 'none' };
  const scans = await getScanData();
  return buildExceptionAdjustment({ job, reports: scans.reports, exceptions, now });
}

async function activeExceptionIdsFor(publishRequest) {
  if (!publishRequest.decision?.exceptions?.appliedExceptions?.length) return [];
  try {
    const now = new Date();
    return (await remediationStore.listExceptions(tenantScope([publishRequest.tenantId])))
      .filter((item) => isExceptionActive(item, now))
      .map((item) => item.id);
  } catch {
    return undefined;
  }
}

// Evidence provenance. Two authorised intake channels exist for every evidence type:
//  - worker: an isolated pipeline worker signs the body with an HMAC shared secret;
//  - manual: a signed-in user with remediation:manage uploads the worker's artifact.
// Both are validated identically; the channel and actor are stored on the job, shown
// in the publish gate and recorded in the audit trail.
function evidenceIntake(context, { channel, workerId = '' }) {
  return {
    channel,
    actor: String(context.actorId || '').slice(0, 200),
    ...(workerId ? { workerId } : {}),
    receivedAt: new Date().toISOString(),
  };
}

// The verified (RM-EXEC) job belongs to the team of its dry run.
async function acceptRemediationEvidence({ context, dryRunJob, evidence, eventType, action, intake, scope }) {
  const evidenceDigest = `sha256:${createHash('sha256').update(JSON.stringify(evidence)).digest('hex')}`;
  const scans = await getScanData();
  const verifiedJob = {
    ...createVerifiedRemediationJob({
      id: await remediationStore.nextJobId('execution'),
      dryRunJob,
      evidence,
      evidenceDigest,
      // Sample scans are never verification evidence: in fixture mode the full-image
      // comparison is unavailable, so the publish gate's re-scan check fails closed.
      fullImageComparison: buildFullImageComparison(FIXTURE_SOURCES.has(scans.source) ? [] : scans.reports, evidence),
    }),
    evidenceIntake: intake,
    tenantId: dryRunJob.tenantId,
  };
  const accepted = await remediationStore.acceptVerifiedEvidence({
    dryRunJob,
    verifiedJob,
    evidence,
    evidenceDigest,
    auditEvent: auditFor(context, {
      eventType,
      action,
      resourceType: 'remediation-job',
      resourceId: verifiedJob.id,
      summary: `Verified remediation evidence accepted for ${dryRunJob.id}`,
      metadata: {
        parentJobId: dryRunJob.id,
        intakeChannel: intake.channel,
        sourceDigest: verifiedJob.sourceDigest,
        outputDigest: verifiedJob.patchedImageDigest,
        evidenceDigest,
        fixedFindings: verifiedJob.fixed?.length || 0,
        remainingFindings: verifiedJob.remaining?.length || 0,
        publishGate: verifiedJob.publishGate?.status,
      },
    }),
  }, scope);

  return { ...accepted, scanError: scans.error };
}

function filterImages(url, images) {
  const query = url.searchParams;
  const q = (query.get('q') || '').trim().toLowerCase();
  const type = query.get('type');
  const source = query.get('source');
  const status = query.get('status');

  return images.filter((image) => {
    const matchesQuery =
      !q ||
      [image.name, image.version, image.runtime, image.status, image.source, ...image.tags]
        .join(' ')
        .toLowerCase()
        .includes(q);
    const matchesType = !type || type === 'All' || image.type === type;
    const matchesSource = !source || image.source === source;
    const matchesStatus = !status || image.status === status;

    return matchesQuery && matchesType && matchesSource && matchesStatus;
  });
}

// ── Team administration (/api/v1/tenants) ──────────────────────────────────────
// effectiveHarbor: the folders the team actually uses (its own values, else inherited).
function tenantAdminView(tenant) {
  return {
    ...tenant,
    memberCount: tenantStore.listMembers(tenant.id).length,
    effectiveHarbor: teamTargets(tenant, platformHarborTargets),
  };
}

// A team member is a directory user with a non-admin global role. Platform administrators
// (users.role = admin, and the local administrator) act in every team without a membership.
function assertMembershipCandidate(username) {
  if (isLocalAdminUsername(localAdmin, username)) {
    throw new TenancyError(400, 'The local administrator acts in every team; it does not need a membership.');
  }
  const user = userStore.get(username);
  if (!user) throw new TenancyError(404, 'User not found. Add the user in Users first.');
  if (user.role === PLATFORM_ADMIN_ROLE) {
    throw new TenancyError(400, 'Platform administrators act in every team; they do not need a membership.');
  }
  return user;
}

async function auditTenantChange(context, values) {
  await remediationStore
    .appendAuditEvent(auditFor(context, values))
    .catch((error) => console.error(`Audit event could not be persisted: ${error.message}`));
}

async function handleTenantAdministration(request, response, context, parts) {
  const method = request.method;
  const tenantId = parts.length >= 4 ? normalizeTenantId(pathSegment(parts[3])) : '';
  const username = parts.length === 6 ? pathSegment(parts[5]).trim().toLowerCase() : '';
  const rejection = {
    eventType: 'tenant.change.rejected',
    action: `${method.toLowerCase()}-tenant`,
    resourceType: 'tenant',
    resourceId: tenantId && isValidTenantId(tenantId) ? tenantId : 'invalid',
    summary: 'Team change refused',
  };

  try {
    if (parts.length >= 4 && !isValidTenantId(tenantId)) throw new TenancyError(400, 'Invalid team id.');

    if (parts.length === 3 && method === 'GET') {
      sendJson(response, 200, tenantStore.listTenants().map(tenantAdminView), { 'X-SSI-Data-Source': `tenants-${tenantStore.driver}` });
      return;
    }

    if (parts.length === 3 && method === 'POST') {
      const body = await readJsonBody(request);
      const input = { id: body?.id, displayName: body?.displayName, harbor: body?.harbor };
      assertHarborFoldersAvailable([...tenantStore.listTenants(), validateNewTenant(input)]);
      const created = await tenantStore.createTenant(input);
      await auditTenantChange(context, {
        tenantId: created.id,
        eventType: 'tenant.created',
        action: 'create-tenant',
        resourceType: 'tenant',
        resourceId: created.id,
        summary: `Team created: ${created.id} (${created.displayName})`,
        metadata: { displayName: created.displayName, harbor: created.harbor },
      });
      sendJson(response, 201, tenantAdminView(created));
      return;
    }

    if (parts.length === 4 && method === 'GET') {
      const tenant = tenantStore.getTenant(tenantId);
      if (!tenant) throw new TenancyError(404, 'Team not found.');
      sendJson(response, 200, tenantAdminView(tenant), { 'X-SSI-Data-Source': `tenants-${tenantStore.driver}` });
      return;
    }

    if (parts.length === 4 && method === 'PATCH') {
      const body = await readJsonBody(request);
      const before = tenantStore.getTenant(tenantId);
      if (!before) throw new TenancyError(404, 'Team not found.');
      const changes = { displayName: body?.displayName, status: body?.status, harbor: body?.harbor };
      if (changes.harbor !== undefined) {
        const next = { ...before, ...validateTenantChanges(changes) };
        assertHarborFoldersAvailable(tenantStore.listTenants().map((item) => (item.id === tenantId ? next : item)));
      }
      const updated = await tenantStore.updateTenant(tenantId, changes, { expectedRowVersion: body?.rowVersion });
      await auditTenantChange(context, {
        tenantId: updated.id,
        eventType: before.status !== updated.status ? `tenant.${updated.status === 'active' ? 'enabled' : 'disabled'}` : 'tenant.updated',
        action: 'update-tenant',
        resourceType: 'tenant',
        resourceId: updated.id,
        severity: updated.status === 'disabled' && before.status !== 'disabled' ? 'warning' : 'info',
        summary: `Team updated: ${updated.id} (status=${updated.status})`,
        metadata: {
          before: { displayName: before.displayName, status: before.status, harbor: before.harbor },
          after: { displayName: updated.displayName, status: updated.status, harbor: updated.harbor },
        },
      });
      sendJson(response, 200, tenantAdminView(updated));
      return;
    }

    if (parts.length === 5 && parts[4] === 'members' && method === 'GET') {
      sendJson(response, 200, tenantStore.listMembers(tenantId), { 'X-SSI-Data-Source': `tenants-${tenantStore.driver}` });
      return;
    }

    if (parts.length === 6 && parts[4] === 'members' && method === 'PUT') {
      if (!username) throw new TenancyError(400, 'A username is required.');
      const body = await readJsonBody(request);
      assertMembershipCandidate(username);
      const before = tenantStore.listMembers(tenantId).find((item) => item.username === username) || null;
      const { membership, created } = await tenantStore.setMembership({
        tenantId,
        username,
        role: body?.role,
        source: 'manual',
        actorId: context.actorId,
      });
      await auditTenantChange(context, {
        tenantId,
        eventType: created ? 'tenant.membership.added' : 'tenant.membership.updated',
        action: 'set-tenant-membership',
        resourceType: 'tenant-membership',
        resourceId: `${tenantId}/${membership.username}`,
        summary: created
          ? `${membership.username} added to team ${tenantId} as ${membership.role}`
          : `${membership.username} is now ${membership.role} in team ${tenantId}`,
        metadata: { username: membership.username, role: membership.role, previousRole: before?.role || null },
      });
      sendJson(response, created ? 201 : 200, membership);
      return;
    }

    if (parts.length === 6 && parts[4] === 'members' && method === 'DELETE') {
      if (!username) throw new TenancyError(400, 'A username is required.');
      const removed = await tenantStore.removeMembership(tenantId, username);
      await auditTenantChange(context, {
        tenantId,
        eventType: 'tenant.membership.removed',
        action: 'remove-tenant-membership',
        resourceType: 'tenant-membership',
        resourceId: `${tenantId}/${removed.username}`,
        summary: `${removed.username} removed from team ${tenantId}`,
        metadata: { username: removed.username, role: removed.role },
      });
      sendJson(response, 200, { ok: true });
      return;
    }

    sendJson(response, 405, { message: 'Method not allowed' });
  } catch (error) {
    await recordRejectedMutation(context, rejection, error);
    sendError(response, context, error);
  }
}

async function handleApi(request, response, context) {
  const url = new URL(request.url || '/', `http://localhost:${port}`);
  const parts = url.pathname.split('/').filter(Boolean);

  if (parts[0] !== 'api' || parts[1] !== 'v1') {
    return false;
  }

  response.setHeader('X-Correlation-ID', context.correlationId);

  // Tenant context first: with multi-tenancy on, the team role replaces the global role, so
  // RBAC below decides on the permissions the caller has in the selected team.
  try {
    context.tenancy = resolveRequestTenancy(request, context.identity);
  } catch (error) {
    if (!(error instanceof TenancyError)) throw error;
    context.tenancy = null;
    await recordRejectedMutation(
      context,
      {
        eventType: 'tenancy.access.denied',
        action: 'select-tenant',
        resourceType: 'tenant',
        resourceId: requestedTenantLabel(request) || 'none',
        summary: 'Team selection refused',
      },
      error,
    );
    // The session answer still works without the refused selection, so the console can
    // show the caller's teams and pick another one.
    if (!(parts.length === 3 && parts[2] === 'session')) {
      sendJson(response, error.statusCode, { message: error.message });
      return true;
    }
    context.tenancy = resolveRequestTenancy(request, context.identity, { ignoreSelection: true });
    context.tenancySelectionError = error.message;
  }
  context.identity = identityForTenancy(context.identity, context.tenancy);

  // Merkezî RBAC enforcement (tek choke-point). Muaf route'lar (public + makine-arası
  // HMAC/token) permissionForRoute'tan null döner ve atlanır. Enforcement kapalıyken
  // (PoC) hiçbir istek engellenmez; açıkken fail-closed 401/403. Çok kiracılı yapıda yetki
  // isteyen bir route için takım seçimi de burada zorunlu tutulur (400/403).
  const requiredPermission = permissionForRoute(request.method, parts);
  try {
    if (requiredPermission && context.identity.authenticated && context.tenancy.enabled) {
      assertTenantSelected(context.tenancy);
    }
    authorizePermission(context.identity, requiredPermission);
  } catch (error) {
    if (error instanceof RbacError || error instanceof TenancyError) {
      const tenancyRefusal = error instanceof TenancyError;
      await recordRejectedMutation(
        context,
        {
          eventType: tenancyRefusal ? 'tenancy.access.denied' : 'rbac.access.denied',
          action: 'authorize',
          resourceType: 'api-route',
          resourceId: url.pathname,
          summary: tenancyRefusal
            ? `Access denied (${error.statusCode}): no team selected for ${requiredPermission}`
            : `Access denied (${error.statusCode}) for ${requiredPermission}`,
        },
        error,
      );
      sendJson(response, error.statusCode, { message: error.message });
      return true;
    }
    throw error;
  }

  // --- Kimlik: giriş / çıkış (RBAC'tan muaf; kendi doğrulaması LDAP/lokal admin) ---
  if (request.method === 'POST' && parts.length === 4 && parts[2] === 'auth' && parts[3] === 'login') {
    if (!sessionSecret || !passwordLoginConfigured) {
      sendJson(response, 503, { message: 'Sign-in is not configured on this server.' });
      return true;
    }
    let credentials;
    try {
      credentials = await readJsonBody(request);
    } catch (error) {
      sendError(response, context, error);
      return true;
    }
    const username = String(credentials?.username || '').trim().slice(0, 200);
    const password = String(credentials?.password || '');
    const throttleSubject = { username, address: request.socket?.remoteAddress || '' };

    // Brute-force / spraying defence: refuse before spending any credential check.
    const gate = loginThrottle.check(throttleSubject);
    if (!gate.allowed) {
      await remediationStore
        .appendAuditEvent(
          auditFor(
            { ...context, actorId: username || 'unknown' },
            {
              eventType: 'auth.login.throttled',
              action: 'login',
              outcome: 'denied',
              severity: 'warning',
              resourceType: 'session',
              resourceId: username || 'unknown',
              summary: `Sign-in blocked after repeated failures (${gate.scope} limit): ${username || 'unknown'}`,
            },
          ),
        )
        .catch(() => {});
      sendJson(
        response,
        429,
        { message: 'Too many failed sign-in attempts. Try again later.' },
        { 'Retry-After': String(gate.retryAfterSeconds) },
      );
      return true;
    }

    const finishLogin = async (identityUser, roles) => {
      loginThrottle.recordSuccess(throttleSubject);
      const token = signSession({ sub: identityUser.username, roles }, sessionSecret);
      await remediationStore
        .appendAuditEvent(
          auditFor(
            { ...context, actorId: identityUser.username },
            {
              eventType: 'auth.login',
              action: 'login',
              resourceType: 'session',
              resourceId: identityUser.username,
              summary: `Signed in: ${identityUser.username} (${roles.join(', ') || 'no role'}, ${identityUser.loginType})`,
            },
          ),
        )
        .catch(() => {});
      sendJson(
        response,
        200,
        {
          subject: identityUser.username,
          displayName: identityUser.displayName,
          roles,
          role: roles[0] || '',
          authenticated: true,
          loginType: identityUser.loginType,
        },
        { 'Set-Cookie': buildSessionCookie(token, { secure: secureCookies }) },
      );
    };

    // Every credential failure gets the same 401 and message, so the response never
    // reveals whether the username exists or which sign-in path it belongs to.
    const failLogin = async (resourceId) => {
      loginThrottle.recordFailure(throttleSubject);
      await remediationStore
        .appendAuditEvent(
          auditFor(
            { ...context, actorId: resourceId || 'unknown' },
            {
              eventType: 'auth.login.failed',
              action: 'login',
              outcome: 'failure',
              severity: 'warning',
              resourceType: 'session',
              resourceId: resourceId || 'unknown',
              summary: `Sign-in failed: ${resourceId || 'unknown'}`,
            },
          ),
        )
        .catch(() => {});
      sendJson(response, 401, { message: 'Incorrect username or password.' });
    };

    if (!username || !password) {
      await failLogin(username);
      return true;
    }

    // 1) Local admin (bootstrap administrator without LDAP)?
    if (isLocalAdminUsername(localAdmin, username)) {
      if (await verifyPassword(password, localAdmin.passwordHash)) {
        await finishLogin(
          { username: localAdmin.username, displayName: localAdmin.displayName, loginType: 'local' },
          ['admin'],
        );
      } else {
        await failLogin(username);
      }
      return true;
    }

    // 2) LDAP user. Without LDAP, spend the same scrypt cost as a local-admin check and
    // answer with the uniform 401 (no username enumeration by status or timing).
    if (!ldapEnabled) {
      await verifyDecoyPassword(password);
      await failLogin(username);
      return true;
    }
    let ldapIdentity;
    try {
      ldapIdentity = await authenticateUser(username, password, ldapConfig);
    } catch (error) {
      const status = error instanceof LdapAuthError ? error.statusCode : 500;
      if (status >= 500) {
        sendJson(response, status, { message: 'The directory server could not be reached.' });
        return true;
      }
      await failLogin(username);
      return true;
    }
    const user = await userStore.upsertOnLogin({
      username: ldapIdentity.subject,
      displayName: ldapIdentity.displayName,
      email: ldapIdentity.email,
      loginType: 'ldap',
    });
    if (user.status !== 'active') {
      sendJson(response, 403, { message: 'Your account is disabled. Contact your administrator.' });
      return true;
    }
    await finishLogin({ username: user.username, displayName: user.displayName, loginType: 'ldap' }, [user.role]);
    return true;
  }

  if (request.method === 'POST' && parts.length === 4 && parts[2] === 'auth' && parts[3] === 'logout') {
    // Revoke the token server-side so a copied cookie stops working immediately.
    const token = readSessionCookie(String(request.headers.cookie || ''));
    const session = token ? verifySession(token, sessionSecret) : null;
    if (session) {
      let persisted = true;
      try {
        await sessionRevocations.revoke({ jti: session.jti, subject: session.sub, expiresAtSeconds: session.exp });
      } catch (error) {
        persisted = false;
        console.error(`Session revocation could not be persisted: ${error.message}`);
      }
      await remediationStore
        .appendAuditEvent(
          auditFor(
            { ...context, actorId: session.sub },
            {
              eventType: 'auth.logout',
              action: 'logout',
              resourceType: 'session',
              resourceId: session.sub,
              summary: persisted
                ? `Signed out: ${session.sub}`
                : `Signed out: ${session.sub} (revocation held in memory only)`,
            },
          ),
        )
        .catch(() => {});
    }
    sendJson(response, 200, { ok: true }, { 'Set-Cookie': buildClearCookie({ secure: secureCookies }) });
    return true;
  }

  // --- Kullanıcı yönetimi (yalnızca admin; permissionForRoute → 'user:manage') ---
  if (parts.length >= 3 && parts[2] === 'users') {
    if (request.method === 'GET' && parts.length === 3) {
      const rows = userStore.list();
      // Lokal admin'i de salt-okunur bir satır olarak göster (düzenlenemez/silinemez).
      const withLocalAdmin = localAdmin
        ? [
            {
              username: localAdmin.username,
              displayName: localAdmin.displayName,
              email: localAdmin.email,
              role: 'admin',
              status: 'active',
              loginType: 'local',
              lastLoginAt: null,
              protected: true,
            },
            ...rows,
          ]
        : rows;
      sendJson(response, 200, withLocalAdmin, { 'X-SSI-Data-Source': 'api' });
      return true;
    }

    if (request.method === 'POST' && parts.length === 3) {
      try {
        const body = await readJsonBody(request);
        const created = await userStore.create({
          username: body?.username,
          displayName: body?.displayName,
          email: body?.email,
          role: body?.role,
        });
        await remediationStore
          .appendAuditEvent(
            auditFor(context, {
              eventType: 'user.created',
              action: 'create-user',
              resourceType: 'user',
              resourceId: created.username,
              summary: `User created: ${created.username} (${created.role})`,
            }),
          )
          .catch(() => {});
        sendJson(response, 201, created);
      } catch (error) {
        sendError(response, context, error);
      }
      return true;
    }

    if (parts.length === 4) {
      const targetUsername = decodeURIComponent(parts[3]);
      // Lokal admin bu ekrandan değiştirilemez/silinemez (kilitlenmeyi önler).
      if (isLocalAdminUsername(localAdmin, targetUsername)) {
        sendJson(response, 403, { message: 'The local administrator cannot be changed from this screen.' });
        return true;
      }
      if (request.method === 'PUT' || request.method === 'PATCH') {
        try {
          const body = await readJsonBody(request);
          assertNotSelfLockout({
            actorId: context.identity?.subject,
            targetUsername,
            method: request.method,
            changes: { role: body?.role, status: body?.status },
          });
          const updated = await userStore.update(targetUsername, {
            role: body?.role,
            status: body?.status,
            displayName: body?.displayName,
            email: body?.email,
          });
          await remediationStore
            .appendAuditEvent(
              auditFor(context, {
                eventType: 'user.updated',
                action: 'update-user',
                resourceType: 'user',
                resourceId: updated.username,
                summary: `User updated: ${updated.username} (role=${updated.role}, status=${updated.status})`,
              }),
            )
            .catch(() => {});
          sendJson(response, 200, updated);
        } catch (error) {
          sendError(response, context, error);
        }
        return true;
      }
      if (request.method === 'DELETE') {
        try {
          assertNotSelfLockout({ actorId: context.identity?.subject, targetUsername, method: request.method });
          await userStore.remove(targetUsername);
          // Memberships go with the user (ON DELETE CASCADE); drop them from the mirror too.
          tenantStore.forgetUser(targetUsername);
          await remediationStore
            .appendAuditEvent(
              auditFor(context, {
                eventType: 'user.deleted',
                action: 'delete-user',
                resourceType: 'user',
                resourceId: targetUsername,
                summary: `User removed: ${targetUsername}`,
              }),
            )
            .catch(() => {});
          sendJson(response, 200, { ok: true });
        } catch (error) {
          sendError(response, context, error);
        }
        return true;
      }
    }
  }

  // --- Teams (tenants) and team memberships (platform administrators only; 'tenant:manage') ---
  // Available while SSI_MULTI_TENANCY is off too, so teams can be prepared before it is
  // switched on. Every change is audited with the team it concerns.
  if (parts.length >= 3 && parts[2] === 'tenants') {
    await handleTenantAdministration(request, response, context, parts);
    return true;
  }

  // Canonical OS-only Trivy JSON for a Dry Run (src/lib/canonicalTrivy.js); it re-plans the job.
  //  - POST .../canonical-report         manual upload, RBAC remediation:manage
  //  - POST .../worker-canonical-report  canonical scan worker, HMAC (RBAC-exempt)
  // The exact bytes are kept as the content digest the Copa worker verifies later. The same
  // report again changes nothing (X-SSI-Evidence-Replay: true).
  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'remediation' &&
    (parts[4] === 'canonical-report' || parts[4] === 'worker-canonical-report')
  ) {
    const workerChannel = parts[4] === 'worker-canonical-report';
    let intakeContext = context;
    try {
      const jobId = decodeURIComponent(parts[3]);
      const { data: report, rawBody } = await readJsonBody(request, {
        maxBytes: maxCanonicalTrivyReportBytes,
        withRawBody: true,
      });
      let intake = evidenceIntake(context, { channel: 'manual' });
      if (workerChannel) {
        const authentication = verifyWorkerEvidenceRequest({
          jobId,
          rawBody,
          headers: request.headers,
          secret: process.env.SSI_CANONICAL_REPORT_HMAC_SECRET,
          maxAgeSeconds: workerEvidenceMaxAgeSeconds,
          purpose: EVIDENCE_PURPOSE.CANONICAL_REPORT,
        });
        intakeContext = {
          ...context,
          actorId: `canonical-scan-worker:${authentication.workerId}`.slice(0, 200),
          trustedActor: true,
        };
        intake = evidenceIntake(intakeContext, { channel: 'worker', workerId: authentication.workerId });
      }

      let replay = false;
      const scope = workerChannel ? WORKER_SCOPE : requestScope(context);
      const updatedJob = await remediationStore.updateJobWith(
        jobId,
        (existingJob) => {
          if (workerChannel && existingJob.mode !== 'dry-run') {
            throw new ApiRequestError(409, 'A canonical report can only be delivered to a Dry Run job.');
          }
          const canonicalReport = validateCanonicalTrivyReport(report, {
            expectedSourceDigest: existingJob.sourceDigest,
            rawContent: rawBody,
          });
          if (existingJob.canonicalReport?.contentDigest === canonicalReport.receipt.contentDigest) {
            replay = true;
            return { job: null };
          }
          const replanned = replanDryRunFromCanonicalReport({ job: existingJob, canonicalReport });
          const updated = {
            ...replanned,
            canonicalReport: { ...replanned.canonicalReport, intake },
            tenantId: existingJob.tenantId,
          };
          return {
            job: updated,
            auditEvent: auditFor(intakeContext, {
              eventType: 'remediation.canonical-report.accepted',
              action: 'attach-canonical-report',
              resourceType: 'remediation-job',
              resourceId: updated.id,
              summary: `Canonical Trivy report accepted for ${updated.id} (${intake.channel})`,
              metadata: {
                channel: intake.channel,
                ...(intake.workerId ? { workerId: intake.workerId } : {}),
                sourceDigest: updated.sourceDigest,
                contentDigest: updated.canonicalReport?.contentDigest,
                findingCount: updated.canonicalReport?.findingCount,
                plannedFindings: updated.plannedFixes?.length || 0,
              },
            }),
          };
        },
        scope,
      );
      if (!updatedJob) throw new ApiRequestError(404, 'Remediation job not found');

      sendJson(response, 200, updatedJob, {
        'X-SSI-Data-Source': `canonical-trivy-intake-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
        'X-SSI-Evidence-Replay': replay ? 'true' : 'false',
      });
    } catch (error) {
      await recordRejectedMutation(
        intakeContext,
        {
          eventType: 'remediation.canonical-report.rejected',
          action: 'attach-canonical-report',
          resourceType: 'remediation-job',
          resourceId: decodeURIComponent(parts[3]),
          summary: `Canonical Trivy report rejected${workerChannel ? ' (worker)' : ''}`,
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (request.method === 'POST' && parts.length === 5 && parts[2] === 'images' && parts[4] === 'remediation') {
    try {
      const scope = requestScope(context);
      // A new job is created in exactly one team: the selected one.
      const tenantId = requireSingleTenant(context.tenancy);
      const scanReportId = decodeURIComponent(parts[3]);
      const body = await readJsonBody(request);

      if (body.dryRun !== true) {
        throw new ApiRequestError(422, 'Only dryRun=true is supported until the isolated Copa worker is available');
      }

      if (body.scanReportId && body.scanReportId !== scanReportId) {
        throw new ApiRequestError(422, 'scanReportId must match the remediation route');
      }

      const scans = await getScanDataInScope(scope);
      // In-scope reports only: a team plans remediation for its own images.
      const report = scans.reports.find((item) => item.id === scanReportId);
      if (!report) {
        throw new ApiRequestError(404, 'Scan report not found or not ready for remediation planning');
      }

      // Windows images are refused before an id is reserved (not supported yet).
      assertRemediationInScope(report);
      const job = {
        ...createDryRunRemediationJob({
          id: await remediationStore.nextJobId('dry-run'),
          report,
        }),
        tenantId,
      };
      await remediationStore.createJob(
        job,
        auditFor(context, {
          eventType: 'remediation.dry-run.created',
          action: 'create-dry-run',
          resourceType: 'remediation-job',
          resourceId: job.id,
          summary: `Dry Run remediation plan created for ${job.image}`,
          metadata: {
            scanReportId,
            sourceDigest: job.sourceDigest,
            status: job.status,
            plannedFindings: job.plannedFixes?.length || 0,
          },
        }),
        scope,
      );

      sendJson(response, 201, job, {
        'X-SSI-Data-Source': `dry-run-${remediationStore.driver}`,
        'X-SSI-Data-Error': scans.error,
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'remediation.dry-run.rejected',
          action: 'create-dry-run',
          resourceType: 'scan-report',
          resourceId: decodeURIComponent(parts[3]),
          summary: 'Dry Run remediation request rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'remediation' &&
    parts[4] === 'worker-evidence'
  ) {
    let evidenceContext = context;
    try {
      const jobId = decodeURIComponent(parts[3]);
      const { data: evidence, rawBody } = await readJsonBody(request, {
        maxBytes: maxRemediationEvidenceBytes,
        withRawBody: true,
      });
      const authentication = verifyWorkerEvidenceRequest({
        jobId,
        rawBody,
        headers: request.headers,
        secret: process.env.SSI_REMEDIATION_EVIDENCE_HMAC_SECRET,
        maxAgeSeconds: workerEvidenceMaxAgeSeconds,
      });
      evidenceContext = {
        ...context,
        actorId: `remediation-worker:${authentication.workerId}`.slice(0, 200),
        trustedActor: true,
      };
      const dryRunJob = await remediationStore.getJob(jobId, WORKER_SCOPE);
      if (!dryRunJob) {
        throw new ApiRequestError(404, 'Remediation job not found');
      }

      const accepted = await acceptRemediationEvidence({
        context: evidenceContext,
        dryRunJob,
        evidence,
        eventType: 'remediation.worker-evidence.accepted',
        action: 'accept-worker-evidence',
        intake: evidenceIntake(evidenceContext, { channel: 'worker', workerId: authentication.workerId }),
        scope: WORKER_SCOPE,
      });

      sendJson(response, accepted.created ? 201 : 200, accepted.job, {
        'X-SSI-Data-Source': `remediation-worker-evidence-${remediationStore.driver}`,
        'X-SSI-Data-Error': accepted.scanError,
        'X-SSI-Evidence-Replay': accepted.created ? 'false' : 'true',
      });
    } catch (error) {
      await recordRejectedMutation(
        evidenceContext,
        {
          eventType: 'remediation.worker-evidence.rejected',
          action: 'accept-worker-evidence',
          resourceType: 'remediation-job',
          resourceId: decodeURIComponent(parts[3]),
          summary: 'Remediation worker evidence rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'remediation' &&
    parts[4] === 'verification-evidence'
  ) {
    try {
      const scope = requestScope(context);
      const jobId = decodeURIComponent(parts[3]);
      const dryRunJob = await remediationStore.getJob(jobId, scope);
      if (!dryRunJob) {
        throw new ApiRequestError(404, 'Remediation job not found');
      }

      const evidence = await readJsonBody(request, { maxBytes: maxRemediationEvidenceBytes });
      const accepted = await acceptRemediationEvidence({
        context,
        dryRunJob,
        evidence,
        eventType: 'remediation.verification-evidence.accepted',
        action: 'accept-verification-evidence',
        intake: evidenceIntake(context, { channel: 'manual' }),
        scope,
      });

      sendJson(response, accepted.created ? 201 : 200, accepted.job, {
        'X-SSI-Data-Source': `remediation-evidence-${remediationStore.driver}`,
        'X-SSI-Data-Error': accepted.scanError,
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'remediation.verification-evidence.rejected',
          action: 'accept-verification-evidence',
          resourceType: 'remediation-job',
          resourceId: decodeURIComponent(parts[3]),
          summary: 'Remediation verification evidence rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // Supply-chain evidence (Cosign signature + Syft SBOM + provenance) produced by the
  // signing worker on the approved/ digest, bound to the RM-EXEC job's immutable output
  // digest. Two authorised channels (see evidenceIntake):
  //  - POST .../supply-chain-evidence         manual upload, RBAC remediation:manage
  //  - POST .../worker-supply-chain-evidence  signing worker, HMAC (RBAC-exempt)
  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'remediation' &&
    (parts[4] === 'supply-chain-evidence' || parts[4] === 'worker-supply-chain-evidence')
  ) {
    const workerChannel = parts[4] === 'worker-supply-chain-evidence';
    let evidenceContext = context;
    try {
      const jobId = decodeURIComponent(parts[3]);
      const { data: evidence, rawBody } = await readJsonBody(request, {
        maxBytes: maxSupplyChainEvidenceBytes,
        withRawBody: true,
      });
      let intake = evidenceIntake(context, { channel: 'manual' });
      if (workerChannel) {
        const authentication = verifyWorkerEvidenceRequest({
          jobId,
          rawBody,
          headers: request.headers,
          secret: process.env.SSI_SUPPLY_CHAIN_EVIDENCE_HMAC_SECRET,
          maxAgeSeconds: workerEvidenceMaxAgeSeconds,
          purpose: EVIDENCE_PURPOSE.SUPPLY_CHAIN,
        });
        evidenceContext = {
          ...context,
          actorId: `supply-chain-worker:${authentication.workerId}`.slice(0, 200),
          trustedActor: true,
        };
        intake = evidenceIntake(evidenceContext, { channel: 'worker', workerId: authentication.workerId });
      }

      // Atomic read-modify-write: concurrent evidence intakes on the same job (candidate test,
      // consumer decisions) must not be overwritten by a stale copy of the job.
      const scope = workerChannel ? WORKER_SCOPE : requestScope(context);
      const updatedJob = await remediationStore.updateJobWith(jobId, (job) => {
        const outputDigest = job.patchedImageDigest || job.verificationEvidence?.outputDigest || '';
        const validated = validateSupplyChainEvidence(evidence, {
          expectedOutputDigest: outputDigest,
          rawContent: rawBody,
        });
        const supplyChain = { ...validated.supplyChain, intake };
        const updated = { ...job, supplyChain, updatedAt: new Date().toISOString() };
        return {
          job: updated,
          auditEvent: auditFor(evidenceContext, {
            eventType: 'remediation.supply-chain-evidence.accepted',
            action: 'attach-supply-chain-evidence',
            resourceType: 'remediation-job',
            resourceId: updated.id,
            summary: `Supply-chain evidence accepted for ${updated.id} (${intake.channel})`,
            metadata: {
              outputDigest,
              intakeChannel: intake.channel,
              signature: supplyChain.signature,
              sbom: supplyChain.sbom,
              provenance: supplyChain.provenance,
              verifier: supplyChain.verifier,
            },
          }),
        };
      }, scope);
      if (!updatedJob) {
        throw new ApiRequestError(404, 'Remediation job not found');
      }

      sendJson(response, 200, updatedJob, {
        'X-SSI-Data-Source': `supply-chain-evidence-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        evidenceContext,
        {
          eventType: 'remediation.supply-chain-evidence.rejected',
          action: 'attach-supply-chain-evidence',
          resourceType: 'remediation-job',
          resourceId: decodeURIComponent(parts[3]),
          summary: `Supply-chain evidence rejected (${workerChannel ? 'worker' : 'manual'})`,
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // Pre-release testing, step 1: the automatic candidate test result for an RM-EXEC job,
  // bound to its immutable output digest (src/lib/candidateTestEvidence.js).
  //  - POST .../candidate-test         manual upload, RBAC remediation:manage
  //  - POST .../worker-candidate-test  candidate test worker, HMAC (RBAC-exempt)
  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'remediation' &&
    (parts[4] === 'candidate-test' || parts[4] === 'worker-candidate-test')
  ) {
    const workerChannel = parts[4] === 'worker-candidate-test';
    let evidenceContext = context;
    try {
      const jobId = decodeURIComponent(parts[3]);
      const { data: evidence, rawBody } = await readJsonBody(request, {
        maxBytes: maxCandidateTestEvidenceBytes,
        withRawBody: true,
      });
      let intake = evidenceIntake(context, { channel: 'manual' });
      if (workerChannel) {
        const authentication = verifyWorkerEvidenceRequest({
          jobId,
          rawBody,
          headers: request.headers,
          secret: process.env.SSI_CANDIDATE_TEST_EVIDENCE_HMAC_SECRET,
          maxAgeSeconds: workerEvidenceMaxAgeSeconds,
          purpose: EVIDENCE_PURPOSE.CANDIDATE_TEST,
        });
        evidenceContext = {
          ...context,
          actorId: `candidate-test-worker:${authentication.workerId}`.slice(0, 200),
          trustedActor: true,
        };
        intake = evidenceIntake(evidenceContext, { channel: 'worker', workerId: authentication.workerId });
      }

      let replay = false;
      const scope = workerChannel ? WORKER_SCOPE : requestScope(context);
      const updatedJob = await remediationStore.updateJobWith(jobId, (job) => {
        const record = validateCandidateTestEvidence(evidence, {
          job,
          evidenceDigest: sha256ContentDigest(rawBody),
          intake,
        });
        const applied = applyCandidateTest(job, record);
        replay = !applied.changed;
        if (!applied.changed) return { job: null };
        const updated = { ...applied.job, updatedAt: new Date().toISOString() };
        return {
          job: updated,
          auditEvent: auditFor(evidenceContext, {
            eventType: 'remediation.candidate-test.accepted',
            action: 'attach-candidate-test',
            resourceType: 'remediation-job',
            resourceId: updated.id,
            outcome: record.passed ? 'success' : 'denied',
            severity: record.passed ? 'info' : 'warning',
            summary: `Candidate test ${record.passed ? 'passed' : 'failed'} for ${updated.id} (${intake.channel})`,
            metadata: {
              candidateDigest: record.candidateDigest,
              evidenceDigest: record.evidenceDigest,
              intakeChannel: intake.channel,
              passed: record.passed,
              failedChecks: record.checks.filter((item) => item.status === 'fail').map((item) => item.id),
              packageChanges: record.packageChanges.summary,
            },
          }),
        };
      }, scope);
      if (!updatedJob) throw new ApiRequestError(404, 'Remediation job not found');

      sendJson(response, 200, updatedJob, {
        'X-SSI-Data-Source': `candidate-test-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
        'X-SSI-Evidence-Replay': replay ? 'true' : 'false',
      });
    } catch (error) {
      await recordRejectedMutation(
        evidenceContext,
        {
          eventType: 'remediation.candidate-test.rejected',
          action: 'attach-candidate-test',
          resourceType: 'remediation-job',
          resourceId: decodeURIComponent(parts[3]),
          summary: `Candidate test result rejected (${workerChannel ? 'worker' : 'manual'})`,
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // Starts a worker pipeline in Azure DevOps for an onboarding request, a publish request or a
  // scanned image (src/lib/workerPipelineActions.js). The body names only the action (and, for
  // an image, its <project>/<repository>@sha256 reference); SSI derives every parameter.
  //   POST /onboarding/{id}/pipeline-runs         onboarding:create
  //   POST /publish-requests/{id}/pipeline-runs   publish:approve
  //   POST /scans/pipeline-runs                   remediation:manage (scan visible to the team)
  if (
    request.method === 'POST' &&
    ((parts.length === 5 && ['onboarding', 'publish-requests'].includes(parts[2]) && parts[4] === 'pipeline-runs') ||
      (parts.length === 4 && parts[2] === 'scans' && parts[3] === 'pipeline-runs'))
  ) {
    const resourceType = { onboarding: 'onboarding-request', 'publish-requests': 'publish-request', scans: 'image' }[parts[2]];
    let resourceId = parts.length === 5 ? decodeURIComponent(parts[3]) : '';
    try {
      const body = await readJsonBody(request, { maxBytes: 4 * 1024 });
      const action = String(body?.action || '');
      const scope = requestScope(context);
      const audit = (values) => auditFor(context, values);
      let result;
      if (parts[2] === 'onboarding') {
        result = await pipelineRuns.startOnboarding({ requestId: resourceId, action, actorId: context.actorId, scope, audit });
        if (!result) throw new ApiRequestError(404, 'Onboarding request not found');
      } else if (parts[2] === 'publish-requests') {
        result = await pipelineRuns.startPublish({ requestId: resourceId, action, actorId: context.actorId, scope, audit });
        if (!result) throw new ApiRequestError(404, 'Publish request not found');
      } else {
        resourceId = String(body?.reference || '').slice(0, 300);
        const scans = await getScanDataInScope(scope);
        if (!findScanReport(scans.reports, resourceId)) {
          throw new ApiRequestError(404, 'No current Harbor scan of this image is visible to your team.');
        }
        result = await pipelineRuns.startImage({
          reference: resourceId,
          action,
          actorId: context.actorId,
          audit,
          tenantId: contextTenantId(context),
        });
      }
      sendJson(response, 201, result, {
        'X-SSI-Data-Source': `azure-devops-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: `${resourceType === 'image' ? 'scan' : resourceType.split('-')[0]}.pipeline-run.rejected`,
          action: 'start-pipeline-run',
          resourceType,
          resourceId: resourceId || 'unknown',
          summary: 'Pipeline run not started',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // Starts a worker pipeline in Azure DevOps for this job (src/lib/pipelineRuns.js). The body
  // names only the action; SSI derives every pipeline parameter from the job. RBAC
  // remediation:manage, the same permission the manual evidence uploads need.
  if (request.method === 'POST' && parts.length === 5 && parts[2] === 'remediation' && parts[4] === 'pipeline-runs') {
    try {
      const jobId = decodeURIComponent(parts[3]);
      const body = await readJsonBody(request, { maxBytes: 4 * 1024 });
      const canonicalBuildId = body?.canonicalBuildId == null ? undefined : String(body.canonicalBuildId);
      const result = await pipelineRuns.start({
        jobId,
        action: String(body?.action || ''),
        canonicalBuildId,
        actorId: context.actorId,
        scope: requestScope(context),
        audit: (values) => auditFor(context, values),
      });
      if (!result) throw new ApiRequestError(404, 'Remediation job not found');
      sendJson(response, 201, result, {
        'X-SSI-Data-Source': `azure-devops-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'remediation.pipeline-run.rejected',
          action: 'start-pipeline-run',
          resourceType: 'remediation-job',
          resourceId: decodeURIComponent(parts[3]),
          summary: 'Pipeline run not started',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // Pre-release testing, step 2: a consumer team records that it tried the candidate in its
  // own environment ("accepted") or found a problem ("issue-found"). RBAC remediation:accept;
  // the decider is always the trusted session identity, never a value from the body.
  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'remediation' &&
    parts[4] === 'consumer-acceptance'
  ) {
    try {
      const jobId = decodeURIComponent(parts[3]);
      const body = await readJsonBody(request, { maxBytes: maxConsumerAcceptanceBytes });
      const scope = requestScope(context);
      const updatedJob = await remediationStore.updateJobWith(jobId, (job) => {
        const decision = createConsumerAcceptance({
          job,
          body,
          actorId: context.trustedActor ? context.actorId : '',
        });
        const updated = { ...applyConsumerAcceptance(job, decision), updatedAt: decision.decidedAt };
        return {
          job: updated,
          auditEvent: auditFor(context, {
            eventType:
              decision.decision === 'accepted' ? 'remediation.consumer-acceptance.accepted' : 'remediation.consumer-acceptance.issue-reported',
            action: 'record-consumer-acceptance',
            resourceType: 'remediation-job',
            resourceId: updated.id,
            severity: decision.decision === 'accepted' ? 'info' : 'warning',
            summary:
              decision.decision === 'accepted'
                ? `Candidate ${updated.id} accepted in ${decision.environment}`
                : `Issue reported for candidate ${updated.id} in ${decision.environment}`,
            metadata: {
              decision: decision.decision,
              environment: decision.environment,
              note: decision.note,
              candidateDigest: decision.candidateDigest,
              candidateTestEvidenceDigest: decision.candidateTestEvidenceDigest,
            },
          }),
        };
      }, scope);
      if (!updatedJob) throw new ApiRequestError(404, 'Remediation job not found');

      sendJson(response, 200, updatedJob, {
        'X-SSI-Data-Source': `consumer-acceptance-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'remediation.consumer-acceptance.rejected',
          action: 'record-consumer-acceptance',
          resourceType: 'remediation-job',
          resourceId: decodeURIComponent(parts[3]),
          summary: 'Consumer decision rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (request.method === 'POST' && parts.length === 3 && parts[2] === 'publish-requests') {
    try {
      const scope = requestScope(context);
      const body = await readJsonBody(request);
      const job = await remediationStore.getJob(String(body.jobId || '').trim(), scope);
      if (!job) throw new ApiRequestError(404, 'Remediation job not found');

      // A publish request belongs to the team of the job whose image it publishes.
      const evaluated = evaluatePublishPolicy({
        job,
        target: body.target,
        config: publishConfigFor(job.tenantId),
        actorId: context.trustedActor ? context.actorId : '',
        requestId: await remediationStore.nextPublishRequestId(),
        exceptionAdjustment: await exceptionAdjustmentFor(job),
      });
      const publishRequest = { ...evaluated, tenantId: job.tenantId };
      const appliedExceptions = publishRequest.decision.exceptions.appliedExceptions;
      const stored = await remediationStore.createPublishRequest(
        publishRequest,
        auditFor(context, {
          eventType: 'publish.policy.evaluated',
          action: 'evaluate-publish-policy',
          resourceType: 'publish-request',
          resourceId: publishRequest.id,
          outcome: publishRequest.status === 'Blocked' ? 'denied' : 'success',
          severity: publishRequest.status === 'Blocked' ? 'warning' : 'info',
          summary: `Publish policy evaluated for ${job.id}: ${publishRequest.status}`,
          metadata: {
            remediationJobId: job.id,
            sourceDigest: publishRequest.source.digest,
            targetReference: publishRequest.target.tagReference,
            policyVersion: publishRequest.policyVersion,
            failedCheckIds: publishRequest.decision.failedCheckIds,
            appliedExceptions: appliedExceptions.map((item) => item.id),
          },
        }),
        scope,
      );
      if (appliedExceptions.length > 0) {
        await remediationStore
          .appendAuditEvent(
            auditFor(context, {
              tenantId: job.tenantId,
              eventType: 'exception.applied',
              action: 'apply-exception',
              resourceType: 'publish-request',
              resourceId: publishRequest.id,
              severity: 'warning',
              summary: `Risk acceptance ${appliedExceptions.map((item) => item.id).join(', ')} applied to ${publishRequest.id}`,
              metadata: {
                remediationJobId: job.id,
                outputDigest: publishRequest.source.digest,
                appliedExceptions,
                acceptedSeverity: publishRequest.decision.exceptions.acceptedSeverity,
              },
            }),
          )
          .catch((auditError) => console.error(`Audit event could not be persisted: ${auditError.message}`));
      }
      sendJson(response, 201, stored, {
        'X-SSI-Data-Source': `publish-policy-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'publish.policy.rejected',
          action: 'evaluate-publish-policy',
          resourceType: 'publish-request',
          summary: 'Publish policy request rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'publish-requests' &&
    parts[4] === 'approve'
  ) {
    try {
      const scope = requestScope(context);
      const requestId = decodeURIComponent(parts[3]);
      const existing = await remediationStore.getPublishRequest(requestId, scope);
      if (!existing) throw new ApiRequestError(404, 'Publish request not found');
      const body = await readJsonBody(request);
      const approved = approvePublishRequest(existing, {
        actorId: context.trustedActor ? context.actorId : '',
        actorRoles: context.identity?.roles || [],
        reason: body.reason,
        config: publishConfigFor(existing.tenantId),
        activeExceptionIds: await activeExceptionIdsFor(existing),
        // Job-bound checks (config integrity, candidate test, consumer acceptance) are
        // re-evaluated against the job's current state.
        currentJob: await remediationStore.getJob(existing.jobId, scope),
      });
      const stored = await remediationStore.updatePublishRequest(
        approved,
        auditFor(context, {
          eventType: 'publish.approval.granted',
          action: 'approve-publish-request',
          resourceType: 'publish-request',
          resourceId: approved.id,
          summary: `Publish request ${approved.id} approved`,
          metadata: {
            remediationJobId: approved.jobId,
            targetReference: approved.target.tagReference,
            policyVersion: approved.policyVersion,
            approvedBy: approved.approval.approvedBy,
            reason: approved.approval.reason,
          },
        }),
        scope,
      );
      sendJson(response, 200, stored, {
        'X-SSI-Data-Source': `publish-approval-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'publish.approval.rejected',
          action: 'approve-publish-request',
          resourceType: 'publish-request',
          resourceId: decodeURIComponent(parts[3]),
          summary: 'Publish approval rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // An approver closes a request that waits for approval (src/lib/publishLifecycle.js).
  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'publish-requests' &&
    parts[4] === 'reject'
  ) {
    const requestId = pathSegment(parts[3]);
    try {
      if (!requestId) throw new ApiRequestError(400, 'Invalid publish request ID');
      const scope = requestScope(context);
      const existing = await remediationStore.getPublishRequest(requestId, scope);
      if (!existing) throw new ApiRequestError(404, 'Publish request not found');
      const body = await readJsonBody(request, { maxBytes: maxPublishDecisionBytes });
      const rejected = rejectPublishRequest(existing, {
        actorId: context.trustedActor ? context.actorId : '',
        actorRoles: context.identity?.roles || [],
        reason: body.reason,
        config: publishConfigFor(existing.tenantId),
      });
      const stored = await remediationStore.updatePublishRequest(
        rejected,
        auditFor(context, {
          eventType: 'publish.request.rejected',
          action: 'reject-publish-request',
          resourceType: 'publish-request',
          resourceId: rejected.id,
          summary: `Publish request ${rejected.id} rejected`,
          metadata: {
            remediationJobId: rejected.jobId,
            targetReference: rejected.target.tagReference,
            rejectedBy: rejected.rejection.rejectedBy,
            reason: rejected.rejection.reason,
          },
        }),
        scope,
      );
      sendJson(response, 200, stored, {
        'X-SSI-Data-Source': `publish-rejection-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'publish.rejection.failed',
          action: 'reject-publish-request',
          resourceType: 'publish-request',
          resourceId: requestId || 'invalid',
          summary: 'Publish request rejection refused',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // An approver withdraws a published image. The image (digest) is withdrawn, not one tag:
  // every published request for the digest and the job that produced it are updated in one
  // transaction, and the publish policy blocks the digest from then on.
  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'publish-requests' &&
    parts[4] === 'withdraw'
  ) {
    const requestId = pathSegment(parts[3]);
    try {
      if (!requestId) throw new ApiRequestError(400, 'Invalid publish request ID');
      const scope = requestScope(context);
      const existing = await remediationStore.getPublishRequest(requestId, scope);
      if (!existing) throw new ApiRequestError(404, 'Publish request not found');
      const body = await readJsonBody(request, { maxBytes: maxPublishDecisionBytes });
      const decision = buildWithdrawalDecision({
        actorId: context.trustedActor ? context.actorId : '',
        actorRoles: context.identity?.roles || [],
        reason: body.reason,
        category: body.category,
        config: publishConfigFor(existing.tenantId),
      });
      // Fail fast (outside the transaction) when this request is not a published image.
      withdrawPublishedRequest(existing, decision);

      const result = await remediationStore.updateJobAndPublishRequests(existing.jobId, async (job, loadPublishRequests) => {
        // Every published request of the digest, read and locked inside the transaction, so a
        // request published meanwhile cannot be left out.
        const published = await loadPublishRequests({ digest: existing.source.digest, statuses: ['Published'] });
        // The requests of the digest that were not published yet can never happen any more.
        const open = await loadPublishRequests({ digest: existing.source.digest, statuses: OPEN_PUBLISH_STATUSES });
        const {
          job: updatedJob,
          requests: withdrawn,
          cancelled,
        } = decideDigestWithdrawal({ job, published, open, requestId, decision });
        const primary = withdrawn[0];
        const requestIds = withdrawn.map((item) => item.id);
        const metadataFor = (item) => ({
          remediationJobId: item.jobId,
          digest: primary.withdrawal.digest,
          targetReference: item.withdrawal.targetReference,
          withdrawnBy: decision.withdrawnBy,
          category: decision.category,
          reason: decision.reason,
          withdrawnTogether: requestIds,
        });
        return {
          job: updatedJob,
          jobAuditEvent: updatedJob
            ? auditFor(context, {
                eventType: 'remediation.output.withdrawn',
                action: 'withdraw-published-image',
                resourceType: 'remediation-job',
                resourceId: updatedJob.id,
                severity: 'warning',
                summary: `Output ${primary.withdrawal.digest} of ${updatedJob.id} withdrawn; it can no longer be published`,
                metadata: metadataFor(primary),
              })
            : null,
          requests: [
            ...withdrawn.map((item) => ({
              request: item,
              auditEvent: auditFor(context, {
                eventType: 'publish.withdrawn',
                action: 'withdraw-published-image',
                resourceType: 'publish-request',
                resourceId: item.id,
                severity: 'warning',
                summary: `Published image ${item.withdrawal.targetReference} withdrawn (${item.id})`,
                metadata: metadataFor(item),
              }),
            })),
            ...cancelled.map((item) => ({
              request: item,
              auditEvent: auditFor(context, {
                eventType: 'publish.request.cancelled',
                action: 'withdraw-published-image',
                resourceType: 'publish-request',
                resourceId: item.id,
                severity: 'warning',
                summary: `Publish request ${item.id} cancelled: its image was withdrawn (was ${item.cancellation.previousStatus})`,
                metadata: {
                  remediationJobId: item.jobId,
                  digest: item.cancellation.digest,
                  targetReference: item.target?.tagReference || '',
                  previousStatus: item.cancellation.previousStatus,
                  withdrawnWith: requestId,
                  reason: decision.reason,
                },
              }),
            })),
          ],
        };
      }, scope);
      sendJson(response, 200, result.requests[0], {
        'X-SSI-Data-Source': `publish-withdrawal-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'publish.withdrawal.failed',
          action: 'withdraw-published-image',
          resourceType: 'publish-request',
          resourceId: requestId || 'invalid',
          summary: 'Published image withdrawal refused',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'publish-requests' &&
    parts[4] === 'receipt'
  ) {
    const requestId = pathSegment(parts[3]);
    try {
      // Signed with SSI_PUBLISH_RECEIPT_HMAC_SECRET (src/lib/workerReceiptAuth.js); the legacy
      // token is accepted only while it is still configured.
      const { data: receipt, rawBody } = await readJsonBody(request, { withRawBody: true });
      const authentication = authenticateWorkerReceipt({
        label: 'Publish receipt',
        subject: requestId,
        rawBody,
        headers: request.headers,
        purpose: EVIDENCE_PURPOSE.PUBLISH_RECEIPT,
        hmacSecret: process.env.SSI_PUBLISH_RECEIPT_HMAC_SECRET,
        legacyToken: process.env.SSI_PUBLISH_RECEIPT_TOKEN,
        legacyTokenHeader: 'x-ssi-publish-receipt-token',
        maxAgeSeconds: workerEvidenceMaxAgeSeconds,
      });
      assertReceiptSigner(authentication, receipt);
      warnLegacyReceipt(authentication, `Publish receipt for ${requestId}`, 'SSI_PUBLISH_RECEIPT_TOKEN');

      if (!requestId) throw new ApiRequestError(400, 'Invalid publish request ID');
      const existing = await remediationStore.getPublishRequest(requestId, WORKER_SCOPE);
      if (!existing) throw new ApiRequestError(404, 'Publish request not found');
      // A worker retrying a receipt that is already recorded gets the stored request back.
      if (isPublishReceiptReplay(existing, receipt)) {
        sendJson(response, 200, existing, {
          'X-SSI-Data-Source': `publish-receipt-${remediationStore.driver}`,
          'X-SSI-Data-Error': '',
          'X-SSI-Receipt-Replay': 'true',
        });
        return true;
      }
      // Fail fast before taking the job lock. A request approved before its image was
      // withdrawn (now Cancelled) may still have been written by its worker.
      acceptPublishReceipt(receiptBaseline(existing), receipt);

      // Accepted under the job lock: if the image was withdrawn while the worker was
      // writing, the request is recorded as published and withdrawn in the same transaction.
      const result = await remediationStore.updateJobAndPublishRequests(existing.jobId, async (job, loadPublishRequests) => {
        const [current] = await loadPublishRequests({ ids: [requestId] });
        const decided = decidePublishReceipt({ job, request: current, receipt });
        const published = decided.request;
        const workerContext = {
          ...context,
          actorId: workerActor('publish-worker', published.publish?.receipt?.workerId),
        };
        const receiptAudit = auditFor(workerContext, {
          eventType: 'publish.receipt.accepted',
          action: 'accept-publish-receipt',
          resourceType: 'publish-request',
          resourceId: published.id,
          summary: `Controlled publish completed for ${published.id}`,
          metadata: {
            remediationJobId: published.jobId,
            sourceDigest: published.source.digest,
            targetReference: published.target.tagReference,
            targetDigest: published.publish.receipt.targetDigest,
            workerId: published.publish.receipt.workerId,
            authentication: authentication.method,
          },
        });
        if (!decided.withdrawnLate) {
          return { requests: [{ request: published, auditEvent: receiptAudit }] };
        }

        const withdrawn = published;
        const updatedJob = decided.job;
        const lateAudit = auditFor(workerContext, {
          eventType: 'publish.withdrawn',
          action: 'accept-publish-receipt',
          resourceType: 'publish-request',
          resourceId: withdrawn.id,
          severity: 'warning',
          summary: `${withdrawn.id} was written to the registry after its image was withdrawn; recorded as withdrawn`,
          metadata: {
            remediationJobId: withdrawn.jobId,
            digest: withdrawn.withdrawal.digest,
            targetReference: withdrawn.withdrawal.targetReference,
            withdrawnBy: withdrawn.withdrawal.withdrawnBy,
            publishedAfterWithdrawal: true,
          },
        });
        return {
          job: updatedJob,
          jobAuditEvent: null,
          // One request row, two audit events: the receipt and the automatic withdrawal.
          requests: [{ request: withdrawn, auditEvent: receiptAudit }],
          auditEvents: [lateAudit],
        };
      }, WORKER_SCOPE);
      sendJson(response, 200, result.requests[0], {
        'X-SSI-Data-Source': `publish-receipt-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'publish.receipt.rejected',
          action: 'accept-publish-receipt',
          resourceType: 'publish-request',
          resourceId: requestId || 'invalid',
          summary: 'Publish receipt rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // OS templates (src/lib/osTemplate.js): platform-wide records, no team scope.
  //   POST /os-templates                    os-template:build   new build request
  //   POST /os-templates/{id}/pipeline-runs os-template:build   start the worker of the request's OS
  //   POST /os-templates/{id}/approve       os-template:approve accept into the catalog
  //   POST /os-templates/{id}/reject        os-template:approve close, with a reason
  if (request.method === 'POST' && parts.length === 3 && parts[2] === 'os-templates') {
    try {
      requireTrustedActor(context, 'An OS template build is requested by a signed-in user.');
      const body = await readJsonBody(request, { maxBytes: 8 * 1024 });
      const build = createOsTemplateBuild({
        id: await remediationStore.nextOsTemplateBuildId(),
        input: body,
        requestedBy: context.actorId,
      });
      const stored = await remediationStore.createOsTemplateBuild(
        build,
        auditFor(context, {
          tenantId: null,
          eventType: 'os-template.request.created',
          action: 'create-os-template-build',
          resourceType: 'os-template',
          resourceId: build.id,
          summary: describeBuildRequest(build.request),
          metadata: { ...build.request },
        }),
      );
      sendJson(response, 201, osTemplateSummary(stored), {
        'X-SSI-Data-Source': `os-template-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          tenantId: null,
          eventType: 'os-template.request.rejected',
          action: 'create-os-template-build',
          resourceType: 'os-template',
          summary: 'OS template build request rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (request.method === 'POST' && parts.length === 5 && parts[2] === 'os-templates' && parts[4] === 'pipeline-runs') {
    const buildId = pathSegment(parts[3]);
    try {
      if (!OS_TEMPLATE_BUILD_ID.test(buildId)) throw new ApiRequestError(400, 'Invalid OS template build ID');
      const body = await readJsonBody(request, { maxBytes: 4 * 1024 });
      const result = await pipelineRuns.startOsTemplate({
        buildId,
        action: String(body?.action || ''),
        actorId: context.actorId,
        audit: (values) => auditFor(context, { ...values, tenantId: null }),
      });
      sendJson(response, 201, { build: osTemplateSummary(result.build), run: result.run }, {
        'X-SSI-Data-Source': `azure-devops-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          tenantId: null,
          eventType: 'os-template.pipeline-run.rejected',
          action: 'start-pipeline-run',
          resourceType: 'os-template',
          resourceId: buildId.slice(0, 80) || 'unknown',
          summary: 'Pipeline run not started',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // A download of a built template's files (src/lib/osTemplateDownloads.js): the signed-in user
  // gets a one-time ticket here (os-template:download, audited); the browser then fetches
  // GET /os-templates/{id}/downloads?ticket=… as a plain link, streamed from Azure DevOps.
  if (request.method === 'POST' && parts.length === 5 && parts[2] === 'os-templates' && parts[4] === 'download-tickets') {
    const buildId = pathSegment(parts[3]);
    try {
      if (!OS_TEMPLATE_BUILD_ID.test(buildId)) throw new ApiRequestError(400, 'Invalid OS template build ID');
      requireTrustedActor(context, 'An OS template download is made by a signed-in user.');
      const body = await readJsonBody(request, { maxBytes: 1024 });
      const build = await remediationStore.getOsTemplateBuild(buildId);
      if (!build) throw new ApiRequestError(404, 'OS template build request not found');
      const download = findOsTemplateDownload(build, String(body?.download || ''));
      if (!azureDevOps.enabled) {
        throw new ApiRequestError(503, 'Downloads come from Azure DevOps, and the Azure DevOps integration is not configured.');
      }
      await azureDevOps.getArtifact(download.runId, download.artifact);
      const { ticket, expiresAt } = osTemplateDownloadTickets.issue({
        subject: buildId,
        downloadId: download.id,
        actorId: context.actorId,
      });
      await remediationStore.appendAuditEvent(
        auditFor(context, {
          tenantId: null,
          eventType: 'os-template.download.authorized',
          action: 'download-os-template',
          resourceType: 'os-template',
          resourceId: buildId,
          summary: `OS template ${buildId}: download of ${download.fileName} authorized`,
          metadata: {
            download: download.id,
            artifact: download.artifact,
            adoRunId: download.runId,
            files: download.files.map(({ file, sha256 }) => ({ file, sha256 })),
          },
        }),
      );
      sendJson(response, 201, {
        url: `/api/v1/os-templates/${encodeURIComponent(buildId)}/downloads?ticket=${encodeURIComponent(ticket)}`,
        expiresAt,
        fileName: download.fileName,
        files: download.files,
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          tenantId: null,
          eventType: 'os-template.download.rejected',
          action: 'download-os-template',
          resourceType: 'os-template',
          resourceId: buildId.slice(0, 80) || 'unknown',
          summary: 'OS template download refused',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (request.method === 'POST' && parts.length === 5 && parts[2] === 'os-templates' && ['approve', 'reject'].includes(parts[4])) {
    const buildId = pathSegment(parts[3]);
    const decision = parts[4];
    try {
      if (!OS_TEMPLATE_BUILD_ID.test(buildId)) throw new ApiRequestError(400, 'Invalid OS template build ID');
      requireTrustedActor(context, 'An OS template decision is made by a signed-in user.');
      const body = await readJsonBody(request, { maxBytes: 8 * 1024 });
      const decided = await remediationStore.updateOsTemplateBuildWith(buildId, async (current) => {
        if (!current) throw new ApiRequestError(404, 'OS template build request not found');
        const decide = (retention) =>
          decideOsTemplate(current, {
            decision,
            actorId: context.actorId,
            reason: body?.reason,
            requireSeparateApprover: publishPolicyConfig.approval.requireSeparateApprover,
            retention,
          });
        // The rules first; only an approval that will be recorded retains the run.
        let build = decide(null);
        const target = decision === 'approve' ? osTemplateRetentionTarget(current) : null;
        if (target) build = decide(await retainTemplateRun(target));
        return {
          build,
          auditEvent: auditFor(context, {
            tenantId: null,
            eventType: `os-template.${decision === 'approve' ? 'approved' : 'rejected'}`,
            action: `${decision}-os-template`,
            resourceType: 'os-template',
            resourceId: buildId,
            severity: decision === 'approve' ? 'warning' : 'info',
            summary: `OS template build ${buildId} ${decision === 'approve' ? 'approved into the catalog' : 'rejected'}`,
            metadata: {
              requestedBy: current.requestedBy,
              reason: build.decision.reason,
              os: current.request?.os || 'windows',
              artifacts: osTemplateArtifacts(current),
              retention: build.retention || null,
            },
          }),
        };
      });
      sendJson(response, 200, osTemplateSummary(decided));
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          tenantId: null,
          eventType: `os-template.${decision}.rejected`,
          action: `${decision}-os-template`,
          resourceType: 'os-template',
          resourceId: buildId.slice(0, 80) || 'unknown',
          summary: `OS template ${decision} refused`,
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (request.method === 'POST' && parts.length === 3 && parts[2] === 'onboarding') {
    try {
      const scope = requestScope(context);
      const tenantId = requireSingleTenant(context.tenancy);
      if (onboarding.allowedRegistries.length === 0) {
        throw new ApiRequestError(
          503,
          'Onboarding is not configured: no approved source registry is set (ONBOARD_ALLOWED_REGISTRIES).',
        );
      }
      const body = await readJsonBody(request);
      const built = buildOnboardingRequest({
        id: await remediationStore.nextOnboardingId(),
        sourceReference: body.sourceReference,
        // The team's quarantine folder (today's onboarded/ while multi-tenancy is off).
        target: targetsForTenant(tenantId).onboarding,
        requestedBy: context.actorId,
        allowedRegistries: onboarding.allowedRegistries,
      });
      const onboardingRequest = { ...built, tenantId };
      const stored = await remediationStore.createOnboardingRequest(
        onboardingRequest,
        auditFor(context, {
          eventType: 'onboarding.request.created',
          action: 'create-onboarding-request',
          resourceType: 'onboarding-request',
          resourceId: onboardingRequest.id,
          summary: `Onboarding requested for ${onboardingRequest.source.reference}`,
          metadata: {
            sourceReference: onboardingRequest.source.reference,
            targetReference: onboardingRequest.target.tagReference,
          },
        }),
        scope,
      );
      sendJson(response, 201, stored, {
        'X-SSI-Data-Source': `onboarding-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'onboarding.request.rejected',
          action: 'create-onboarding-request',
          resourceType: 'onboarding-request',
          summary: 'Onboarding request rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // A person closes an onboarding request that no worker will finish (RBAC onboarding:create,
  // the team's own requests). The reason is required and audited; a worker that had already
  // started may still deliver its receipt, which is kept on record (src/lib/onboarding.js).
  if (request.method === 'POST' && parts.length === 5 && parts[2] === 'onboarding' && parts[4] === 'cancel') {
    const requestId = pathSegment(parts[3]);
    try {
      if (!requestId) throw new ApiRequestError(400, 'Invalid onboarding request ID');
      const body = await readJsonBody(request);
      const result = await remediationStore.updateOnboardingRequestWith(
        requestId,
        (current) => {
          const cancelled = cancelOnboardingRequest(current, {
            actorId: context.trustedActor ? context.actorId : '',
            reason: body?.reason,
          });
          return {
            request: cancelled,
            auditEvent: auditFor(context, {
              eventType: 'onboarding.request.cancelled',
              action: 'cancel-onboarding-request',
              resourceType: 'onboarding-request',
              resourceId: cancelled.id,
              severity: 'warning',
              summary: `Onboarding request ${cancelled.id} cancelled (was ${cancelled.cancellation.previousStatus})`,
              metadata: {
                sourceReference: cancelled.source.reference,
                targetReference: cancelled.target.tagReference,
                previousStatus: cancelled.cancellation.previousStatus,
                reason: cancelled.cancellation.reason,
              },
            }),
          };
        },
        requestScope(context),
      );
      if (!result) throw new ApiRequestError(404, 'Onboarding request not found');
      sendJson(response, 200, result.request, {
        'X-SSI-Data-Source': `onboarding-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'onboarding.cancel.rejected',
          action: 'cancel-onboarding-request',
          resourceType: 'onboarding-request',
          resourceId: requestId || 'invalid',
          summary: 'Onboarding request cancellation refused',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'onboarding' &&
    parts[4] === 'import-receipt'
  ) {
    try {
      const requestId = decodeURIComponent(parts[3]);
      // Signed with SSI_ONBOARD_RECEIPT_HMAC_SECRET (src/lib/workerReceiptAuth.js); the legacy
      // token is accepted only while it is still configured.
      const { data: receipt, rawBody } = await readJsonBody(request, { withRawBody: true });
      const authentication = authenticateWorkerReceipt({
        label: 'Onboarding receipt',
        subject: requestId,
        rawBody,
        headers: request.headers,
        purpose: EVIDENCE_PURPOSE.ONBOARD_RECEIPT,
        hmacSecret: process.env.SSI_ONBOARD_RECEIPT_HMAC_SECRET,
        legacyToken: process.env.ONBOARD_RECEIPT_TOKEN,
        legacyTokenHeader: 'x-ssi-onboard-receipt-token',
        maxAgeSeconds: workerEvidenceMaxAgeSeconds,
      });
      assertReceiptSigner(authentication, receipt);
      warnLegacyReceipt(authentication, `Onboarding receipt for ${requestId}`, 'ONBOARD_RECEIPT_TOKEN');
      // Decided under the request's row lock: a cancellation and a receipt never overwrite
      // each other, and a retried receipt changes nothing.
      const result = await remediationStore.updateOnboardingRequestWith(
        requestId,
        (current) => {
          if (isImportReceiptReplay(current, receipt)) return null;
          const updated = applyImportReceipt(current, receipt);
          const late = updated.importAfterCancellation && !current.importAfterCancellation ? updated.importAfterCancellation : null;
          const workerId = late ? late.workerId : updated.workerId;
          const workerContext = { ...context, actorId: workerActor('onboarding-worker', workerId) };
          if (late) {
            return {
              request: updated,
              auditEvent: auditFor(workerContext, {
                eventType: 'onboarding.receipt.after-cancellation',
                action: 'accept-onboarding-receipt',
                resourceType: 'onboarding-request',
                resourceId: updated.id,
                outcome: 'success',
                severity: 'warning',
                summary:
                  late.status === 'imported'
                    ? `Import of ${updated.id} finished after it was cancelled: ${late.targetReference} is in quarantine`
                    : `Import of ${updated.id} failed after it was cancelled`,
                metadata: {
                  importedDigest: late.importedDigest,
                  targetReference: late.targetReference,
                  workerId: late.workerId,
                  authentication: authentication.method,
                },
              }),
            };
          }
          return {
            request: updated,
            auditEvent: auditFor(workerContext, {
              eventType: 'onboarding.receipt.accepted',
              action: 'accept-onboarding-receipt',
              resourceType: 'onboarding-request',
              resourceId: updated.id,
              outcome: updated.status === ONBOARDING_STATES.FAILED ? 'denied' : 'success',
              severity: updated.status === ONBOARDING_STATES.FAILED ? 'warning' : 'info',
              summary: `Onboarding ${updated.status} for ${updated.source.reference}`,
              metadata: {
                importedDigest: updated.importedDigest,
                targetReference: updated.target.tagReference,
                workerId: updated.workerId,
                authentication: authentication.method,
              },
            }),
          };
        },
        WORKER_SCOPE,
      );
      if (!result) throw new ApiRequestError(404, 'Onboarding request not found');
      sendJson(response, 200, result.request, {
        'X-SSI-Data-Source': `onboarding-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
        'X-SSI-Receipt-Replay': result.changed ? 'false' : 'true',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'onboarding.receipt.rejected',
          action: 'accept-onboarding-receipt',
          resourceType: 'onboarding-request',
          resourceId: decodeURIComponent(parts[3]),
          summary: 'Onboarding receipt rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (request.method === 'POST' && parts.length === 3 && parts[2] === 'exceptions') {
    try {
      requireTrustedActor(context, 'Requesting a risk acceptance requires a signed-in user.');
      const scope = requestScope(context);
      const tenantId = requireSingleTenant(context.tenancy);
      const body = await readJsonBody(request);
      // Severity (and with it the maximum duration) comes from the scans, never the client.
      const scans = await getScanDataInScope(scope);
      const severity = severityForScope(scans.reports, {
        cve: body.cve,
        repository: repositoryFromReference(body.repository),
        package: body.package,
      });
      const validated = validateExceptionRequest(body, { config: publishPolicyConfig.riskAcceptance, severity });
      const exception = {
        ...createExceptionRecord({
          id: await remediationStore.nextExceptionId(),
          request: validated,
          actorId: context.actorId,
        }),
        tenantId,
      };
      const stored = await remediationStore.createException(
        exception,
        auditFor(context, {
          eventType: 'exception.requested',
          action: 'request-exception',
          resourceType: 'policy-exception',
          resourceId: exception.id,
          summary: `Risk acceptance ${exception.id} requested for ${exception.cve} in ${exception.repository}`,
          metadata: {
            cve: exception.cve,
            repository: exception.repository,
            package: exception.package,
            digest: exception.digest,
            reasonCode: exception.reasonCode,
            severity: exception.severity,
            severityVerified: exception.severityVerified,
            expiresAt: exception.expiresAt,
          },
        }),
        scope,
      );
      sendJson(response, 201, exceptionView(stored), {
        'X-SSI-Data-Source': `exceptions-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'exception.request.rejected',
          action: 'request-exception',
          resourceType: 'policy-exception',
          summary: 'Risk acceptance request rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (
    request.method === 'POST' &&
    parts.length === 5 &&
    parts[2] === 'exceptions' &&
    Object.hasOwn(EXCEPTION_DECISION_EVENTS, parts[4])
  ) {
    const decision = parts[4];
    const exceptionId = decodeURIComponent(parts[3]);
    try {
      requireTrustedActor(context, 'Deciding on a risk acceptance requires a signed-in approver.');
      const scope = requestScope(context);
      const existing = await remediationStore.getException(exceptionId, scope);
      if (!existing) throw new ApiRequestError(404, 'Exception not found');
      const body = await readJsonBody(request);
      const updated = decideException(existing, { decision, actorId: context.actorId, note: body.note });
      const event = EXCEPTION_DECISION_EVENTS[decision];
      const stored = await remediationStore.updateException(
        updated,
        auditFor(context, {
          eventType: event.eventType,
          action: `${decision}-exception`,
          resourceType: 'policy-exception',
          resourceId: updated.id,
          severity: event.severity,
          summary: `Risk acceptance ${updated.id} ${event.verb} for ${updated.cve} in ${updated.repository}`,
          metadata: {
            cve: updated.cve,
            repository: updated.repository,
            expiresAt: updated.expiresAt,
            requestedBy: updated.requestedBy,
            note: body.note,
          },
        }),
        scope,
      );
      sendJson(response, 200, exceptionView(stored), {
        'X-SSI-Data-Source': `exceptions-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      await recordRejectedMutation(
        context,
        {
          eventType: 'exception.decision.rejected',
          action: `${decision}-exception`,
          resourceType: 'policy-exception',
          resourceId: exceptionId,
          summary: `Risk acceptance ${EXCEPTION_DECISION_EVENTS[decision].noun} refused`,
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // Image inspection worker (azure-pipelines-image-inspection.yml): the OS package inventory,
  // layers, size and runtime configuration of one scanned image, HMAC-signed for that digest
  // (RBAC-exempt machine route). Only images of the SSI Harbor that Harbor has scanned are
  // accepted; Env values are refused (src/lib/imageInspection.js).
  if (request.method === 'POST' && parts.length === 5 && parts[2] === 'image-inspections' && parts[4] === 'worker') {
    let evidenceContext = context;
    const digest = pathSegment(parts[3]).toLowerCase();
    try {
      const { data: evidence, rawBody } = await readJsonBody(request, {
        maxBytes: maxImageInspectionEvidenceBytes,
        withRawBody: true,
      });
      const authentication = verifyWorkerEvidenceRequest({
        jobId: digest,
        rawBody,
        headers: request.headers,
        secret: process.env.SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET,
        maxAgeSeconds: workerEvidenceMaxAgeSeconds,
        purpose: EVIDENCE_PURPOSE.IMAGE_INSPECTION,
      });
      evidenceContext = {
        ...context,
        actorId: `image-inspection-worker:${authentication.workerId}`.slice(0, 200),
        trustedActor: true,
      };
      const record = validateImageInspectionEvidence(evidence, {
        digest,
        registryHosts: harborRegistryHosts,
        projects: harbor.projects,
        evidenceDigest: sha256ContentDigest(rawBody),
        intake: evidenceIntake(evidenceContext, { channel: 'worker', workerId: authentication.workerId }),
      });
      // Only an image Harbor has scanned can be compared, so only such an image is stored.
      const scans = await getScanData();
      const report = FIXTURE_SOURCES.has(scans.source) ? null : findScanReport(scans.reports, record.reference);
      if (!report) {
        throw new ImageInspectionError(
          `Harbor has no current scan of ${record.reference}; only scanned images of the SSI Harbor can be inspected.`,
          409,
        );
      }
      const saved = await remediationStore.saveImageInspection(
        record,
        applyImageInspection,
        auditFor(evidenceContext, {
          tenantId: report.tenantId || null,
          eventType: 'image.inspection.accepted',
          action: 'record-image-inspection',
          resourceType: 'image',
          resourceId: record.reference,
          outcome: 'success',
          severity: 'info',
          summary: `Image inspection recorded for ${record.reference}`,
          metadata: {
            digest: record.digest,
            evidenceDigest: record.evidenceDigest,
            os: record.os,
            platform: record.platform,
            packages: record.packages.length,
            layers: record.facts.diffIds.length,
          },
        }),
      );
      sendJson(
        response,
        200,
        {
          reference: saved.record.reference,
          digest: saved.record.digest,
          generatedAt: saved.record.generatedAt,
          os: saved.record.os,
          platform: saved.record.platform,
          packages: saved.record.packages.length,
          layers: saved.record.facts.diffIds.length,
        },
        { 'X-SSI-Evidence-Replay': saved.changed ? 'false' : 'true' },
      );
    } catch (error) {
      await recordRejectedMutation(
        evidenceContext,
        {
          eventType: 'image.inspection.rejected',
          action: 'record-image-inspection',
          resourceType: 'image',
          resourceId: digest.slice(0, 80),
          summary: 'Image inspection result rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  // OS template worker (azure-pipelines-os-template-windows.yml): the template manifest of one
  // build request, HMAC-signed for that request ID (RBAC-exempt machine route). The template
  // must come from the request's pinned ISO, edition and name and leave no CVE open
  // (src/lib/osTemplate.js).
  if (request.method === 'POST' && parts.length === 5 && parts[2] === 'os-templates' && parts[4] === 'worker') {
    let evidenceContext = context;
    const buildId = pathSegment(parts[3]);
    try {
      if (!OS_TEMPLATE_BUILD_ID.test(buildId)) throw new ApiRequestError(400, 'Invalid OS template build ID');
      const { data: evidence, rawBody } = await readJsonBody(request, {
        maxBytes: maxOsTemplateEvidenceBytes,
        withRawBody: true,
      });
      const authentication = verifyWorkerEvidenceRequest({
        jobId: buildId,
        rawBody,
        headers: request.headers,
        secret: process.env.SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET,
        maxAgeSeconds: workerEvidenceMaxAgeSeconds,
        purpose: EVIDENCE_PURPOSE.OS_TEMPLATE,
      });
      evidenceContext = {
        ...context,
        actorId: `os-template-worker:${authentication.workerId}`.slice(0, 200),
        trustedActor: true,
      };
      let changed = false;
      const saved = await remediationStore.updateOsTemplateBuildWith(buildId, async (current) => {
        if (!current) throw new ApiRequestError(404, 'OS template build request not found');
        const result = validateOsTemplateEvidence(evidence, {
          build: current,
          evidenceDigest: sha256ContentDigest(rawBody),
          intake: evidenceIntake(evidenceContext, { channel: 'worker', workerId: authentication.workerId }),
        });
        const applied = applyOsTemplateResult(current, result);
        changed = applied.changed;
        if (!changed) return null;
        const { summary, metadata } = osTemplateResultAudit(buildId, result);
        return {
          build: applied.build,
          auditEvent: auditFor(evidenceContext, {
            eventType: 'os-template.build.accepted',
            action: 'record-os-template-build',
            resourceType: 'os-template',
            resourceId: buildId,
            summary,
            metadata,
          }),
        };
      });
      sendJson(response, 200, osTemplateSummary(saved), { 'X-SSI-Evidence-Replay': changed ? 'false' : 'true' });
    } catch (error) {
      await recordRejectedMutation(
        evidenceContext,
        {
          tenantId: null,
          eventType: 'os-template.build.rejected',
          action: 'record-os-template-build',
          resourceType: 'os-template',
          resourceId: buildId.slice(0, 80) || 'unknown',
          summary: 'OS template build result rejected',
        },
        error,
      );
      sendError(response, context, error);
    }
    return true;
  }

  if (request.method !== 'GET') {
    sendJson(response, 405, { message: 'Method not allowed' });
    return true;
  }

  // Azure DevOps integration status (platform administrators): configuration without the
  // token, plus a read-only check that each configured pipeline is visible with it.
  if (parts.length === 4 && parts[2] === 'integrations' && parts[3] === 'azure-devops') {
    const view = describeAzureDevOpsConfig(azureDevOpsConfig);
    const pipelines = azureDevOps.enabled ? await azureDevOps.checkPipelines() : [];
    sendJson(response, 200, { ...view, checkedAt: new Date().toISOString(), checks: pipelines });
    return true;
  }

  if (parts.length === 3 && parts[2] === 'exceptions') {
    const scope = requestScope(context);
    try {
      const now = new Date();
      const exceptions = (await remediationStore.listExceptions(scope)).map((item) => exceptionView(item, now));
      sendJson(response, 200, exceptions, {
        'X-SSI-Data-Source': `exceptions-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      sendJson(response, 503, {
        message: `Risk acceptances could not be read. Run npm run db:migrate. ${error.message}`,
      });
    }
    return true;
  }

  // OS templates: the list (summaries), one request with its result, its worker runs.
  if (parts.length === 3 && parts[2] === 'os-templates') {
    const builds = await remediationStore.listOsTemplateBuilds();
    sendJson(response, 200, builds.map(osTemplateSummary), {
      'X-SSI-Data-Source': `os-template-${remediationStore.driver}`,
      'X-SSI-Data-Error': '',
    });
    return true;
  }
  if (parts.length === 4 && parts[2] === 'os-templates') {
    const build = await remediationStore.getOsTemplateBuild(pathSegment(parts[3]));
    if (!build) {
      sendJson(response, 404, { message: 'OS template build request not found' });
      return true;
    }
    sendJson(response, 200, { ...osTemplateSummary(build), result: build.result });
    return true;
  }
  if (request.method === 'GET' && parts.length === 5 && parts[2] === 'os-templates' && parts[4] === 'downloads') {
    await streamOsTemplateDownload(request, response, context, pathSegment(parts[3]), url.searchParams.get('ticket'));
    return true;
  }
  if (parts.length === 5 && parts[2] === 'os-templates' && parts[4] === 'pipeline-runs') {
    const build = await remediationStore.getOsTemplateBuild(pathSegment(parts[3]));
    if (!build) {
      sendJson(response, 404, { message: 'OS template build request not found' });
      return true;
    }
    sendJson(response, 200, await pipelineRuns.viewOsTemplate(build));
    return true;
  }

  if (parts.length === 3 && parts[2] === 'onboarding') {
    sendJson(response, 200, await remediationStore.listOnboardingRequests(requestScope(context)), {
      'X-SSI-Data-Source': `onboarding-${remediationStore.driver}`,
      'X-SSI-Data-Error': '',
    });
    return true;
  }

  if (parts.length === 5 && parts[2] === 'onboarding' && parts[4] === 'worker-handoff') {
    const handoffToken = process.env.ONBOARD_HANDOFF_TOKEN || '';
    if (!handoffToken) {
      sendJson(response, 503, { message: 'Onboarding worker handoff authentication is not configured' });
      return true;
    }
    if (!secureTokenMatches(handoffToken, request.headers['x-ssi-onboard-handoff-token'])) {
      sendJson(response, 403, { message: 'Onboarding worker handoff authentication failed' });
      return true;
    }

    const requestId = decodeURIComponent(parts[3]);
    try {
      // Requested → Importing: the worker took the request. Decided under the row lock, so a
      // cancellation at the same moment wins or loses cleanly (a cancelled request is refused).
      // No audit event: this is a handoff record, only a state step.
      const result = await remediationStore.updateOnboardingRequestWith(
        requestId,
        (current) => {
          buildOnboardingWorkerHandoff(current);
          if (current.status !== ONBOARDING_STATES.REQUESTED) return null;
          return {
            request: { ...current, status: ONBOARDING_STATES.IMPORTING, updatedAt: new Date().toISOString() },
            auditEvent: undefined,
          };
        },
        WORKER_SCOPE,
      );
      if (!result) {
        sendJson(response, 404, { message: 'Onboarding request not found' });
        return true;
      }
      const handoff = withHandoffTenant(buildOnboardingWorkerHandoff(result.request), result.request.tenantId);
      sendJson(response, 200, handoff, {
        'X-SSI-Data-Source': `onboarding-handoff-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      sendError(response, context, error);
    }
    return true;
  }

  if (parts.length === 3 && parts[2] === 'publish-policy') {
    // The selected team's policy (its approved folder as the boundary); every team without a
    // selection (platform administrator) sees the platform policy.
    sendJson(response, 200, publicPublishPolicyConfig(publishConfigFor(context.tenancy?.tenantId)), {
      'X-SSI-Data-Source': 'publish-policy-config',
      'X-SSI-Data-Error': '',
    });
    return true;
  }

  if (parts.length === 3 && parts[2] === 'publish-requests') {
    sendJson(response, 200, await remediationStore.listPublishRequests(requestScope(context)), {
      'X-SSI-Data-Source': `publish-requests-${remediationStore.driver}`,
      'X-SSI-Data-Error': '',
    });
    return true;
  }

  if (
    parts.length === 5 &&
    parts[2] === 'publish-requests' &&
    parts[4] === 'worker-handoff'
  ) {
    try {
      const scope = authorizePublishHandoff(request, context);
      const publishRequest = await remediationStore.getPublishRequest(decodeURIComponent(parts[3]), scope);
      if (!publishRequest) throw new ApiRequestError(404, 'Publish request not found');
      // The publish worker gets the handoff only while the image still passes its job-bound
      // checks: an issue reported after approval stops the publish.
      const handoff = buildPublishWorkerHandoff(publishRequest, undefined, {
        currentJob: await remediationStore.getJob(publishRequest.jobId, scope),
        config: publishConfigFor(publishRequest.tenantId),
      });
      sendJson(response, 200, withHandoffTenant(handoff, publishRequest.tenantId), {
        'X-SSI-Data-Source': `publish-handoff-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      sendError(response, context, error);
    }
    return true;
  }

  if (parts.length === 4 && parts[2] === 'publish-requests') {
    const publishRequest = await remediationStore.getPublishRequest(decodeURIComponent(parts[3]), requestScope(context));
    if (!publishRequest) {
      sendJson(response, 404, { message: 'Publish request not found' });
      return true;
    }
    sendJson(response, 200, publishRequest, {
      'X-SSI-Data-Source': `publish-request-${remediationStore.driver}`,
      'X-SSI-Data-Error': '',
    });
    return true;
  }

  if (parts.length === 3 && parts[2] === 'session') {
    sendJson(
      response,
      200,
      {
        subject: context.identity.subject,
        displayName: sessionDisplayName(context.identity.subject),
        roles: context.identity.roles,
        role: context.identity.roles[0] || '',
        permissions: context.identity.permissions,
        authenticated: context.identity.authenticated,
        enforced: context.identity.enforced,
        devLogin: devLoginEnabled,
        // UI: enforce açık ve giriş yoksa gerçek giriş formu (LDAP/lokal admin) göster.
        passwordLogin: ldapEnabled || Boolean(localAdmin),
        tenancy: sessionTenancy(context),
      },
      { 'X-SSI-Data-Source': 'session', 'X-SSI-Data-Error': '' },
    );
    return true;
  }

  // Free comparison of two scanned images (Scan Results). Read-only; each image is addressed
  // by <project>/<repository>@sha256:<digest>, and only scans visible to the caller's team
  // can be compared (same scope as GET /scans).
  if (parts.length === 4 && parts[2] === 'scans' && parts[3] === 'compare') {
    try {
      const scans = await getScanDataInScope(requestScope(context));
      const baseReference = url.searchParams.get('base') || '';
      const headReference = url.searchParams.get('head') || '';
      const baseReport = findScanReport(scans.reports, baseReference, 'base image');
      const headReport = findScanReport(scans.reports, headReference, 'compared image');
      if (!baseReport || !headReport) {
        const missing = !baseReport ? baseReference : headReference;
        sendJson(response, 404, { message: `No current Harbor scan of ${missing.slice(0, 300)} is available.` });
        return true;
      }
      // Inspections are read only for scans this request can see (checked above).
      const inspections = await remediationStore.getImageInspections([
        baseReference.toLowerCase(),
        headReference.toLowerCase(),
      ]);
      const comparison = buildImageDiff({
        baseReport,
        headReport,
        baseInspection: inspections.get(baseReference.toLowerCase()) || null,
        headInspection: inspections.get(headReference.toLowerCase()) || null,
        registryHost: harborRegistryHosts[0] || '',
      });
      sendJson(response, 200, comparison, { 'X-SSI-Data-Source': scans.source });
    } catch (error) {
      sendError(response, context, error);
    }
    return true;
  }

  if (parts.length === 3 && parts[2] === 'scans') {
    const scans = await getScanDataInScope(requestScope(context));
    sendJson(response, 200, scans.reports, {
      'X-SSI-Data-Source': scans.source,
      'X-SSI-Data-Error': scans.error,
    });
    return true;
  }

  if (parts.length === 3 && parts[2] === 'health') {
    // Public and unauthenticated: report liveness/readiness only. Failure details go to
    // the server log, never to the caller.
    try {
      await remediationStore.health();
      sendJson(response, 200, { status: 'ok', timestamp: new Date().toISOString() });
    } catch (error) {
      console.error(`[${context.correlationId}] Health check failed: ${error.message}`);
      sendJson(response, 503, { status: 'degraded', timestamp: new Date().toISOString() });
    }
    return true;
  }

  if (parts.length === 4 && parts[2] === 'reports' && parts[3] === 'remediation') {
    // Report-only jobs from the earlier Windows flow stay stored but are not reported.
    const scope = requestScope(context);
    const jobs = (await remediationStore.listJobs(scope)).filter((job) => !isReportOnlyJob(job));
    const publishRequests = await remediationStore.listPublishRequests(scope);
    sendJson(response, 200, buildRemediationReport(jobs, publishRequests), {
      'X-SSI-Data-Source': `remediation-report-${remediationStore.driver}`,
      'X-SSI-Data-Error': '',
    });
    return true;
  }

  if (
    request.method === 'GET' &&
    parts.length === 6 &&
    parts[2] === 'reports' &&
    parts[3] === 'remediation' &&
    parts[5] === 'document'
  ) {
    const scope = requestScope(context);
    const job = await remediationStore.getJob(decodeURIComponent(parts[4]), scope);
    if (!job) {
      sendJson(response, 404, { message: 'Remediation job not found' });
      return true;
    }

    const gateView = derivePublishGateView({ job, publishRequests: await remediationStore.listPublishRequests(scope) });
    // A verified job's report also says what the fix changed (src/lib/imageComparison.js).
    let comparison = null;
    if (job.mode === 'execution' && job.patchedImageDigest) {
      const scans = await getScanDataInScope(scope);
      const reports = FIXTURE_SOURCES.has(scans.source) ? [] : scans.reports;
      try {
        comparison = buildImageComparison({
          job,
          sourceReport: scanReportByDigest(reports, job.sourceDigest) || null,
          outputReport: scanReportByDigest(reports, job.patchedImageDigest) || null,
        });
      } catch (error) {
        if (!(error instanceof ImageComparisonError)) throw error;
      }
    }
    const model = buildRemediationReportDocumentModel(job, {
      publishGate: {
        status: gateView.status,
        allowed: gateView.tone === 'allowed' || gateView.tone === 'published',
        reason: gateView.reason,
      },
      comparison,
    });
    const html = renderRemediationReportDocumentHtml(model);
    sendDocument(response, 200, html, {
      disposition: url.searchParams.get('download') === 'true' ? 'attachment' : 'inline',
      filename: `${remediationReportDocumentFilename(job.id)}.html`,
      dataSource: `remediation-report-document-${remediationStore.driver}`,
    });
    return true;
  }

  // The audit log (src/lib/auditQuery.js): a page of events newest first, filtered on the
  // server; X-SSI-Next-Cursor is the `before` value of the next page ('' on the last one).
  if (parts.length === 3 && parts[2] === 'audit-events') {
    const { limit, before } = parseAuditPage(url.searchParams);
    const filters = parseAuditFilters(url.searchParams);
    const page = await remediationStore.queryAuditEvents({ limit, before, filters }, requestScope(context));
    sendJson(response, 200, page.events, {
      'X-SSI-Data-Source': `audit-${remediationStore.driver}`,
      'X-SSI-Data-Error': '',
      'X-SSI-Next-Cursor': page.nextCursor || '',
    });
    return true;
  }

  // How many events the filters match, in total and per category.
  if (parts.length === 4 && parts[2] === 'audit-events' && parts[3] === 'summary') {
    const filters = parseAuditFilters(url.searchParams);
    sendJson(response, 200, await remediationStore.summarizeAuditEvents({ filters }, requestScope(context)), {
      'X-SSI-Data-Source': `audit-${remediationStore.driver}`,
      'X-SSI-Data-Error': '',
    });
    return true;
  }

  if (parts.length === 4 && parts[2] === 'audit-events' && parts[3] === 'export') {
    await exportAuditEvents(response, context, url.searchParams);
    return true;
  }

  if (parts.length === 3 && parts[2] === 'remediation') {
    sendJson(response, 200, await remediationStore.listJobs(requestScope(context)), {
      'X-SSI-Data-Source': `remediation-${remediationStore.driver}`,
      'X-SSI-Data-Error': '',
    });
    return true;
  }

  // What changed between the source image and its patched output (src/lib/imageComparison.js).
  if (parts.length === 5 && parts[2] === 'remediation' && parts[4] === 'comparison') {
    const job = await remediationStore.getJob(pathSegment(parts[3]), requestScope(context));
    if (!job) {
      sendJson(response, 404, { message: 'Remediation job not found' });
      return true;
    }
    try {
      const scans = await getScanDataInScope(requestScope(context));
      // Sample scans are never evidence: in fixture mode the current comparison is unavailable.
      const reports = FIXTURE_SOURCES.has(scans.source) ? [] : scans.reports;
      const sourceReport = scanReportByDigest(reports, job.sourceDigest) || null;
      const outputReport = scanReportByDigest(reports, job.patchedImageDigest) || null;
      const comparison = buildImageComparison({ job, sourceReport, outputReport });
      sendJson(response, 200, comparison, {
        'X-SSI-Data-Source': `comparison-${remediationStore.driver}`,
        // A registry problem matters here only when it leaves one of the two digests unscanned.
        'X-SSI-Data-Error': sourceReport && outputReport ? '' : scans.error,
      });
    } catch (error) {
      sendError(response, context, error);
    }
    return true;
  }

  if (parts.length === 5 && parts[2] === 'remediation' && parts[4] === 'execution-readiness') {
    const job = await remediationStore.getJob(decodeURIComponent(parts[3]), requestScope(context));
    if (!job) {
      sendJson(response, 404, { message: 'Remediation job not found' });
      return true;
    }

    // The worker counts as available when SSI can start the Copa pipeline in Azure DevOps.
    const workerConfigured = Boolean(azureDevOpsConfig.configured && azureDevOpsConfig.pipelines.copaRemediation);
    sendJson(response, 200, buildExecutionReadiness(job, { workerConfigured }), {
      'X-SSI-Data-Source': `dry-run-${remediationStore.driver}`,
      'X-SSI-Data-Error': '',
    });
    return true;
  }

  // The worker pipeline actions and runs of an onboarding request, a publish request or a
  // scanned image, with live state from Azure DevOps.
  if (parts.length === 5 && parts[2] === 'onboarding' && parts[4] === 'pipeline-runs') {
    const onboardingRequest = await remediationStore.getOnboardingRequest(decodeURIComponent(parts[3]), requestScope(context));
    if (!onboardingRequest) {
      sendJson(response, 404, { message: 'Onboarding request not found' });
      return true;
    }
    sendJson(response, 200, await pipelineRuns.viewOnboarding(onboardingRequest));
    return true;
  }
  if (parts.length === 5 && parts[2] === 'publish-requests' && parts[4] === 'pipeline-runs') {
    const scope = requestScope(context);
    const publishRequest = await remediationStore.getPublishRequest(decodeURIComponent(parts[3]), scope);
    if (!publishRequest) {
      sendJson(response, 404, { message: 'Publish request not found' });
      return true;
    }
    const job = await remediationStore.getJob(publishRequest.jobId, scope);
    sendJson(response, 200, await pipelineRuns.viewPublish(publishRequest, job));
    return true;
  }
  if (parts.length === 4 && parts[2] === 'scans' && parts[3] === 'pipeline-runs') {
    try {
      const reference = url.searchParams.get('reference') || '';
      const scans = await getScanDataInScope(requestScope(context));
      if (!findScanReport(scans.reports, reference)) {
        sendJson(response, 404, { message: 'No current Harbor scan of this image is visible to your team.' });
        return true;
      }
      sendJson(response, 200, await pipelineRuns.viewImage(reference));
    } catch (error) {
      sendError(response, context, error);
    }
    return true;
  }

  // The worker pipeline actions of a job and its runs, with live state from Azure DevOps.
  if (parts.length === 5 && parts[2] === 'remediation' && parts[4] === 'pipeline-runs') {
    const job = await remediationStore.getJob(decodeURIComponent(parts[3]), requestScope(context));
    if (!job) {
      sendJson(response, 404, { message: 'Remediation job not found' });
      return true;
    }
    sendJson(response, 200, await pipelineRuns.view(job, requestScope(context)));
    return true;
  }

  if (parts.length === 5 && parts[2] === 'remediation' && parts[4] === 'worker-handoff') {
    const job = await remediationStore.getJob(decodeURIComponent(parts[3]), requestScope(context));
    if (!job) {
      sendJson(response, 404, { message: 'Remediation job not found' });
      return true;
    }

    try {
      sendJson(response, 200, withHandoffTenant(buildWorkerHandoffManifest(job), job.tenantId), {
        'X-SSI-Data-Source': `dry-run-${remediationStore.driver}`,
        'X-SSI-Data-Error': '',
      });
    } catch (error) {
      sendJson(response, 409, { message: error.message });
    }
    return true;
  }

  if (parts.length === 4 && parts[2] === 'remediation') {
    const job = await remediationStore.getJob(decodeURIComponent(parts[3]), requestScope(context));
    if (!job) {
      sendJson(response, 404, { message: 'Remediation job not found' });
      return true;
    }

    sendJson(response, 200, job, {
      'X-SSI-Data-Source': `dry-run-${remediationStore.driver}`,
      'X-SSI-Data-Error': '',
    });
    return true;
  }

  if (parts.length === 3 && parts[2] === 'images') {
    const inventory = await getInventoryWithEvidence(requestScope(context));
    sendJson(response, 200, filterImages(url, inventory.images), {
      'X-SSI-Data-Source': inventory.source,
      'X-SSI-Data-Error': inventory.error,
    });
    return true;
  }

  if (parts.length === 4 && parts[2] === 'images') {
    const inventory = await getInventoryWithEvidence(requestScope(context));
    const image = inventory.images.find((item) => item.id === decodeURIComponent(parts[3]));
    if (!image) {
      sendJson(response, 404, { message: 'Image not found' });
      return true;
    }

    sendJson(response, 200, image, {
      'X-SSI-Data-Source': inventory.source,
      'X-SSI-Data-Error': inventory.error,
    });
    return true;
  }

  if (parts.length === 5 && parts[2] === 'images' && parts[4] === 'sbom') {
    const imageId = decodeURIComponent(parts[3]);
    // Visible images only (the team's own and the shared catalog).
    const inventory = await getInventoryWithEvidence(requestScope(context));
    const image = inventory.images.find((item) => item.id === imageId);
    if (!image) {
      sendJson(response, 404, { message: 'Image not found' });
      return true;
    }

    sendJson(response, 200, FIXTURE_SOURCES.has(inventory.source) ? sbomReports[imageId] || [] : [], {
      'X-SSI-Data-Source': inventory.source,
      'X-SSI-Data-Error': inventory.error,
    });
    return true;
  }

  if (url.pathname.startsWith('/api/')) {
    sendJson(response, 404, { message: 'API route not found' });
    return true;
  }

  return false;
}

function isDecodablePath(url) {
  try {
    const { pathname } = new URL(url, `http://localhost:${port}`);
    decodeURIComponent(pathname);
    return true;
  } catch {
    return false;
  }
}

function resolveAsset(url) {
  const pathname = decodeURIComponent(new URL(url, `http://localhost:${port}`).pathname);
  const safePath = normalize(pathname)
    .replace(/^[/\\]+/, '')
    .replace(/^(\.\.[/\\])+/, '');
  const requested = join(root, safePath || 'index.html');

  if (isFile(requested)) {
    return { path: requested, status: 200 };
  }

  if (pathname.startsWith('/assets/')) {
    return { path: null, status: 404 };
  }

  return { path: join(root, 'index.html'), status: 200 };
}

await remediationStore.initialize();
await userStore.initialize();
await tenantStore.initialize();
await sessionRevocations.initialize();

const server = createServer(async (request, response) => {
  const context = requestContext(request);
  applySecurityHeaders(response, { https: secureCookies });
  response.setHeader('X-Correlation-ID', context.correlationId);

  try {
    // A path that is not valid percent-encoding is the client's error, not a server failure.
    if (!isDecodablePath(request.url || '/')) {
      sendJson(response, 400, { message: 'The request path is not valid percent-encoding.' });
      return;
    }
    if (await handleApi(request, response, context)) {
      return;
    }

    const asset = resolveAsset(request.url || '/');

    if (!asset.path) {
      response.writeHead(asset.status, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      response.end('Not found');
      return;
    }

    const extension = extname(asset.path);

    response.writeHead(asset.status, {
      'Content-Type': contentTypes[extension] || 'application/octet-stream',
      'Cache-Control': extension === '.html' ? 'no-store' : 'public, max-age=31536000, immutable',
      'X-Content-Type-Options': 'nosniff',
    });

    createReadStream(asset.path).pipe(response);
  } catch (error) {
    if (!response.headersSent) {
      sendError(response, context, error);
    } else {
      console.error(`[${context.correlationId}] Unhandled request error: ${error?.stack || error}`);
      response.destroy(error);
    }
  }
});

server.listen(port, '0.0.0.0', () => {
  console.log(`SSI listening on ${port} with ${remediationStore.driver} persistence`);
  if (devLoginEnabled) {
    console.warn('SSI_DEV_LOGIN=true: X-SSI-Actor-* headers are trusted as identity. Never enable this in production.');
  }
  if (fixturesEnabled) {
    console.warn('SSI_FIXTURES=true: sample inventory and scan data is served when Harbor is not configured.');
  }
  if (azureDevOpsConfig.configured) {
    console.log(
      `Azure DevOps: ${azureDevOpsConfig.orgUrl}/${azureDevOpsConfig.project}, ${Object.keys(azureDevOpsConfig.pipelines).length} pipeline(s) on ${azureDevOpsConfig.ref}.`,
    );
  } else if (azureDevOpsConfig.requested) {
    console.warn(`Azure DevOps integration is off: ${azureDevOpsConfig.problems.join(' ')}`);
  }
  if (onboarding.allowedRegistries.length === 0) {
    console.warn('ONBOARD_ALLOWED_REGISTRIES is empty: onboarding requests are refused until approved source registries are set.');
  } else {
    console.log(`Onboarding accepts images from: ${onboarding.allowedRegistries.join(', ')}`);
  }
  if (tenancyConfig.enabled) {
    console.log(`SSI_MULTI_TENANCY=true: ${tenantStore.listTenants().length} team(s); data, inventory and scans are team-scoped.`);
    // With multi-tenancy on, a non-admin user acts only through a team membership.
    const withoutTeam = userStore
      .list()
      .filter((user) => user.status === 'active' && user.role !== PLATFORM_ADMIN_ROLE)
      .filter((user) => tenantStore.membershipsForUser(user.username).length === 0)
      .map((user) => user.username);
    if (withoutTeam.length > 0) {
      console.warn(`${withoutTeam.length} active user(s) have no team membership and cannot act: ${withoutTeam.slice(0, 20).join(', ')}`);
    }
  }
  for (const channel of [
    {
      label: 'Publish receipt',
      hmacVariable: 'SSI_PUBLISH_RECEIPT_HMAC_SECRET',
      tokenVariable: 'SSI_PUBLISH_RECEIPT_TOKEN',
    },
    {
      label: 'Onboarding receipt',
      hmacVariable: 'SSI_ONBOARD_RECEIPT_HMAC_SECRET',
      tokenVariable: 'ONBOARD_RECEIPT_TOKEN',
    },
  ]) {
    const status = describeReceiptAuthentication({
      ...channel,
      hmacSecret: process.env[channel.hmacVariable],
      legacyToken: process.env[channel.tokenVariable],
    });
    if (status) console.warn(status.message);
  }
  // The label is stored on every decision; a pinned older label misdescribes the checks that ran.
  if (publishPolicyConfig.version !== PUBLISH_POLICY_VERSION) {
    console.warn(
      `SSI_PUBLISH_POLICY_VERSION=${publishPolicyConfig.version} differs from the running policy ${PUBLISH_POLICY_VERSION}; ` +
        'decisions are labelled with the configured value. Remove the variable or update it.',
    );
  }
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${signal} received; shutting down SSI`);

  server.close(async (error) => {
    try {
      await remediationStore.close();
    } finally {
      if (error) {
        console.error(`HTTP server shutdown failed: ${error.message}`);
        process.exitCode = 1;
      }
    }
  });
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
