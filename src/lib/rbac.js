// SSI — RBAC (Faz 5, Adım: Kimlik & Yetki)
//
// Saf, yan etkisiz yetkilendirme çekirdeği. "İki string simülasyonu"nu gerçek
// rol/izin modeliyle değiştirir. Merkezî `permissionForRoute` haritası her
// route için gereken izni verir; `authorizePermission` fail-closed uygular.
//
// Kimlik çözümleme (LDAP/AD-hazır) ayrı bir modüldedir (server/identity.js); bu
// modül yalnızca "hangi rol neye yetkili" ve "hangi route hangi izni ister"
// sorularını yanıtlar — böylece tek başına test edilebilir.

export const ROLES = {
  VIEWER: 'viewer',
  OPERATOR: 'operator',
  APPROVER: 'approver',
  ADMIN: 'admin',
};

// Okuma izinleri — her rol (viewer dahil) taşır.
const READS = [
  'inventory:read',
  'scan:read',
  'remediation:read',
  'report:read',
  'audit:read',
  'publish:read',
  'onboarding:read',
  'exception:read',
  'os-template:read',
];

// Rol → izin kümesi. admin joker ('*') taşır: her izni ve gelecekteki bilinmeyen
// mutasyonları da kapsar (fail-closed varsayılan).
export const ROLE_PERMISSIONS = {
  [ROLES.VIEWER]: [...READS],
  [ROLES.OPERATOR]: [
    ...READS,
    'remediation:plan',
    'remediation:manage',
    'onboarding:create',
    'publish:request',
    'exception:request',
    'remediation:accept',
    'os-template:build',
    'os-template:download',
  ],
  // remediation:accept — a consumer team member marks a candidate image as tested in their
  // own environment (or reports an issue). Approvers carry it too: the person who tried the
  // image is often not an operator. The publish policy forbids the requester to accept.
  // os-template:download — the template files (gigabytes, streamed from Azure DevOps): those
  // who build or approve templates, not every reader.
  [ROLES.APPROVER]: [
    ...READS,
    'publish:approve',
    'exception:approve',
    'remediation:accept',
    'os-template:approve',
    'os-template:download',
  ],
  [ROLES.ADMIN]: ['*'],
};

export class RbacError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = 'RbacError';
    this.statusCode = statusCode;
  }
}

// Serbest metinden (header/config) rol listesi üretir: trim, benzersiz, küçük harf.
export function parseRoles(value) {
  const parsed = String(value ?? '')
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  return [...new Set(parsed)];
}

// "alice:approver,bob:operator|admin" → { alice: ['approver'], bob: ['operator','admin'] }
export function parseRoleBindings(value) {
  const bindings = {};
  for (const entry of String(value ?? '').split(',')) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf(':');
    if (separator === -1) continue;
    const subject = trimmed.slice(0, separator).trim().toLowerCase();
    const roles = parseRoles(trimmed.slice(separator + 1).replace(/\|/g, ','));
    if (subject && roles.length > 0) bindings[subject] = roles;
  }
  return bindings;
}

// Rollerin birleşik izin kümesi. Bilinmeyen roller yok sayılır.
export function permissionsForRoles(roles) {
  const permissions = new Set();
  for (const role of roles || []) {
    for (const permission of ROLE_PERMISSIONS[role] || []) {
      permissions.add(permission);
    }
  }
  return [...permissions];
}

// Makine-arası route'lar: kendi HMAC/token doğrulaması olan worker callback'leri. Kullanıcı
// RBAC'ından muaftırlar ve (çok kiracılı yapıda) tüm takımlarda çalışırlar; kaydı kimliği
// doğrulanmış worker'ın verdiği ID belirler.
const MACHINE_ROUTES = [
  ['POST', 'remediation', 'worker-evidence'],
  ['POST', 'remediation', 'worker-supply-chain-evidence'],
  ['POST', 'remediation', 'worker-candidate-test'],
  ['POST', 'remediation', 'worker-canonical-report'],
  ['POST', 'image-inspections', 'worker'],
  ['POST', 'publish-requests', 'receipt'],
  ['POST', 'onboarding', 'import-receipt'],
  ['GET', 'onboarding', 'worker-handoff'],
  ['GET', 'publish-requests', 'worker-handoff'],
  ['POST', 'os-templates', 'worker'],
  // A plain browser link: authorised by the one-time ticket the signed-in user asked for
  // (POST …/download-tickets, os-template:download), not by a session or header.
  ['GET', 'os-templates', 'downloads'],
];

export function isMachineRoute(method, parts) {
  return (
    parts.length === 5 &&
    MACHINE_ROUTES.some(([routeMethod, resource, action]) => method === routeMethod && parts[2] === resource && parts[4] === action)
  );
}

// Bir route için gereken izin. `null` → RBAC muaf (public ya da makine-arası
// HMAC/token ile kendi doğrulaması olan endpoint). parts: ['api','v1', ...].
export function permissionForRoute(method, parts) {
  const p2 = parts[2];
  const p4 = parts[4];
  const len = parts.length;

  // Public
  if (len === 3 && (p2 === 'health' || p2 === 'session')) return null;
  // Giriş/çıkış: kendi kimlik doğrulaması var (LDAP/lokal admin), RBAC'tan muaf.
  if (p2 === 'auth') return null;

  // Kullanıcı yönetimi (rol atama): yalnızca admin. Tüm metotlar user:manage ister.
  if (p2 === 'users') return 'user:manage';
  // Takım (tenant) ve üyelik yönetimi: yalnızca platform yöneticisi (admin jokeri).
  if (p2 === 'tenants') return 'tenant:manage';

  // Makine-arası (kendi HMAC/token doğrulaması var) — kullanıcı RBAC'ından muaf.
  if (isMachineRoute(method, parts)) return null;

  if (method === 'POST') {
    if (len === 5 && p2 === 'remediation' && p4 === 'canonical-report') return 'remediation:manage';
    if (len === 5 && p2 === 'images' && p4 === 'remediation') return 'remediation:plan';
    if (len === 5 && p2 === 'remediation' && p4 === 'verification-evidence') return 'remediation:manage';
    // Manual upload of the signing worker's supply-chain receipt (audited as channel=manual).
    if (len === 5 && p2 === 'remediation' && p4 === 'supply-chain-evidence') return 'remediation:manage';
    // Manual upload of the candidate test worker's result (audited as channel=manual).
    if (len === 5 && p2 === 'remediation' && p4 === 'candidate-test') return 'remediation:manage';
    if (len === 5 && p2 === 'remediation' && p4 === 'consumer-acceptance') return 'remediation:accept';
    // Starting a worker pipeline in Azure DevOps (src/lib/pipelineRuns.js).
    if (len === 5 && p2 === 'remediation' && p4 === 'pipeline-runs') return 'remediation:manage';
    // Worker pipelines for other records (src/lib/workerPipelineActions.js). Publishing to
    // approved/ and signing are started by those who may approve a publish.
    if (len === 5 && p2 === 'onboarding' && p4 === 'pipeline-runs') return 'onboarding:create';
    if (len === 5 && p2 === 'publish-requests' && p4 === 'pipeline-runs') return 'publish:approve';
    if (len === 4 && p2 === 'scans' && parts[3] === 'pipeline-runs') return 'remediation:manage';
    if (len === 3 && p2 === 'publish-requests') return 'publish:request';
    // Publish decisions after the policy evaluation: approve, reject a pending request,
    // withdraw a published image (src/lib/publishLifecycle.js).
    if (len === 5 && p2 === 'publish-requests' && ['approve', 'reject', 'withdraw'].includes(p4)) return 'publish:approve';
    if (len === 3 && p2 === 'onboarding') return 'onboarding:create';
    // Closing an onboarding request no worker will finish (src/lib/onboarding.js).
    if (len === 5 && p2 === 'onboarding' && p4 === 'cancel') return 'onboarding:create';
    // Risk acceptance: operators request; approvers approve, reject or revoke.
    if (len === 3 && p2 === 'exceptions') return 'exception:request';
    if (len === 5 && p2 === 'exceptions' && ['approve', 'reject', 'revoke'].includes(p4)) return 'exception:approve';
    // OS templates (src/lib/osTemplate.js): operators request and build; approvers decide.
    if (len === 3 && p2 === 'os-templates') return 'os-template:build';
    if (len === 5 && p2 === 'os-templates' && p4 === 'pipeline-runs') return 'os-template:build';
    if (len === 5 && p2 === 'os-templates' && ['approve', 'reject'].includes(p4)) return 'os-template:approve';
    if (len === 5 && p2 === 'os-templates' && p4 === 'download-tickets') return 'os-template:download';
    // Bilinmeyen mutasyon → yalnızca admin (joker) geçer.
    return 'system:admin';
  }

  // GET okumaları
  // Integration status (Azure DevOps): platform administrators only.
  if (p2 === 'integrations') return 'system:admin';
  if (p2 === 'images') return 'inventory:read';
  if (p2 === 'scans') return 'scan:read';
  if (p2 === 'remediation') return 'remediation:read';
  if (p2 === 'reports') return 'report:read';
  if (p2 === 'audit-events') return 'audit:read';
  if (p2 === 'publish-requests' || p2 === 'publish-policy') return 'publish:read';
  if (p2 === 'onboarding') return 'onboarding:read';
  if (p2 === 'exceptions') return 'exception:read';
  if (p2 === 'os-templates') return 'os-template:read';

  // Bilinmeyen okuma: belirli izin yok (enforced modda kimlik doğrulaması yeterli).
  return null;
}

// Fail-closed yetki kontrolü. Muaf route'ta hiçbir şey yapmaz. Enforce edilen ve
// kimliksiz istek 401; izin yoksa 403. Joker ('*') admin'i her izne geçirir.
export function authorizePermission(identity, permission) {
  if (!permission) return;
  if (identity?.enforced && !identity?.authenticated) {
    throw new RbacError(401, 'Authentication required');
  }
  const permissions = identity?.permissions || [];
  if (permissions.includes('*') || permissions.includes(permission)) return;
  throw new RbacError(403, `Insufficient permissions: ${permission} required`);
}
