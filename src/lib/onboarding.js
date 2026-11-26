// SSI — Onboarding domain (Faz 5, Adım 2b)
//
// Dış (güvenilmeyen) bir imajı SSI'nin yönetimli akışına almak için ORKESTRASYON
// katmanı. SSI imajı KENDİSİ çekip Harbor'a YAZMAZ — bu, ayrı ve dar yetkili bir
// izole import worker'ının (Azure pipeline) işidir. Bu modül saf ve yan etkisizdir:
// isteği kurar, credential-free bir worker-handoff üretir ve worker'dan dönen
// import receipt'ini doğrulayıp uygular.
//
// Güvenlik duruşu: onboarding edilen imajlar Harbor'da ayrı bir KARANTİNA prefix'ine
// (varsayılan "onboarded/") iner; approved/ ile yan yana durmaz ve ancak normal
// scan + remediation + publish akışıyla terfi eder.

export const ONBOARDING_HANDOFF_CONTRACT = 'ssi.onboard-handoff/v1';
export const ONBOARDING_RECEIPT_CONTRACT = 'ssi.onboard-receipt/v1';

export const ONBOARDING_STATES = {
  REQUESTED: 'Requested',
  IMPORTING: 'Importing',
  IMPORTED: 'Imported',
  FAILED: 'Failed',
  CANCELLED: 'Cancelled',
};

// Requests a worker may still pick up or finish. Only one may be open per quarantine target.
export const OPEN_ONBOARDING_STATES = Object.freeze([ONBOARDING_STATES.REQUESTED, ONBOARDING_STATES.IMPORTING]);

const REASON_MIN_LENGTH = 10;
const REASON_MAX_LENGTH = 1000;
// The same limits for the Onboard screen, so it never offers what the server refuses.
export const CANCELLATION_REASON_LENGTH = Object.freeze({ min: REASON_MIN_LENGTH, max: REASON_MAX_LENGTH });
// Control and format characters and line separators: a reason is one line of visible text.
const hiddenOrLineBreakingCharacters = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

const sha256Pattern = /^sha256:[a-f0-9]{64}$/i;
const tagPattern = /^[\w][\w.-]{0,127}$/;
const severityKeys = ['critical', 'high', 'medium', 'low', 'unknown'];

export class OnboardingValidationError extends Error {
  constructor(message, statusCode = 422) {
    super(message);
    this.name = 'OnboardingValidationError';
    this.statusCode = statusCode;
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new OnboardingValidationError(message);
  }
}

function asText(value) {
  return value == null ? '' : String(value).trim();
}

function looksLikeRegistryHost(segment) {
  return segment.includes('.') || segment.includes(':') || segment === 'localhost';
}

// Docker Hub is addressed by several host names; they are one registry for policy.
const DOCKER_HUB_ALIASES = new Set(['docker.io', 'index.docker.io', 'registry-1.docker.io', 'registry.hub.docker.com']);

export function normalizeRegistryHost(host) {
  const value = asText(host).toLowerCase().replace(/\/+$/, '');
  return DOCKER_HUB_ALIASES.has(value) ? 'docker.io' : value;
}

// Parses ONBOARD_ALLOWED_REGISTRIES ("docker.io, ghcr.io, registry.corp:5000").
// An empty list means no registry restriction.
export function parseAllowedRegistries(value) {
  return [
    ...new Set(
      asText(value)
        .split(',')
        .map((entry) => normalizeRegistryHost(entry))
        .filter(Boolean),
    ),
  ];
}

// Bir imaj referansını (registry/repo:tag veya @sha256:...) güvenli biçimde ayrıştırır.
// Örn: "docker.io/library/nginx:1.27", "nginx:1.27", "ghcr.io/org/app@sha256:...".
export function parseImageReference(rawReference) {
  const reference = asText(rawReference);
  assert(reference.length > 0 && reference.length <= 512, 'A source image reference is required (up to 512 characters).');
  assert(!/\s/.test(reference), 'The source image reference cannot contain whitespace.');

  let remainder = reference;
  let digest = '';
  let tag = '';

  const atIndex = remainder.indexOf('@');
  if (atIndex !== -1) {
    digest = remainder.slice(atIndex + 1).toLowerCase();
    remainder = remainder.slice(0, atIndex);
    assert(sha256Pattern.test(digest), 'A digest-pinned reference must contain a valid sha256 digest.');
  }

  const lastColon = remainder.lastIndexOf(':');
  const lastSlash = remainder.lastIndexOf('/');
  if (lastColon > lastSlash) {
    tag = remainder.slice(lastColon + 1);
    remainder = remainder.slice(0, lastColon);
    assert(tagPattern.test(tag), `Invalid tag: ${tag}`);
  }

  const segments = remainder.split('/').filter(Boolean);
  assert(segments.length > 0, 'The source image reference must include a repository name.');

  let registry = 'docker.io';
  let pathSegments = segments;
  if (segments.length > 1 && looksLikeRegistryHost(segments[0])) {
    registry = segments[0];
    pathSegments = segments.slice(1);
  }
  assert(pathSegments.length > 0, 'The source image reference must include a repository name.');
  for (const segment of pathSegments) {
    assert(/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/i.test(segment), `Invalid repository segment: ${segment}`);
  }

  const repositoryPath = pathSegments.join('/');
  const name = pathSegments[pathSegments.length - 1];
  const effectiveTag = digest ? '' : tag || 'latest';

  return {
    reference,
    registry,
    repositoryPath,
    name,
    tag: effectiveTag,
    digest,
    pinnedByDigest: Boolean(digest),
  };
}

function sanitizeQuarantineTag(parsed, createdAt) {
  // Karantina hedef tag'i: kaynak tag geçerli ve latest değilse onu kullan;
  // aksi halde mutable 'latest' yerine zaman damgalı bir tag türet.
  if (parsed.tag && parsed.tag.toLowerCase() !== 'latest' && tagPattern.test(parsed.tag)) {
    return parsed.tag;
  }
  const stamp = new Date(createdAt || Date.now())
    .toISOString()
    .replace(/[-:T]/g, '')
    .slice(0, 14);
  return `onboard-${stamp}`;
}

// Bir onboarding isteği kurar. Hedef, KARANTİNA prefix'i altında türetilir
// (örn. onboarded/nginx). SSI bu aşamada hiçbir şey çekmez/yazmaz.
const QUARANTINE_PREFIX_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/i;

export function buildOnboardingRequest({
  id,
  sourceReference,
  target,
  requestedBy,
  createdAt,
  allowedRegistries = [],
}) {
  assert(asText(id), 'An onboarding request id is required.');
  const parsed = parseImageReference(sourceReference);
  if (allowedRegistries.length > 0) {
    const sourceRegistry = normalizeRegistryHost(parsed.registry);
    assert(
      allowedRegistries.includes(sourceRegistry),
      `Registry ${sourceRegistry} is not an approved intake source. Allowed: ${allowedRegistries.join(', ')}.`,
    );
  }

  const registry = asText(target?.registry);
  const project = asText(target?.project);
  const prefix = asText(target?.repositoryPrefix) || 'onboarded';
  assert(registry && project, 'The onboarding target registry and project must be configured.');
  // One folder or nested folders (a team's quarantine, e.g. onboarded/payments).
  assert(QUARANTINE_PREFIX_PATTERN.test(prefix), `Invalid quarantine prefix: ${prefix}`);

  const timestamp = asText(createdAt) || new Date().toISOString();
  const targetTag = sanitizeQuarantineTag(parsed, timestamp);
  const repository = `${prefix}/${parsed.name}`;
  const tagReference = `${registry}/${project}/${repository}:${targetTag}`;

  return {
    id,
    type: 'onboarding',
    status: ONBOARDING_STATES.REQUESTED,
    source: {
      reference: parsed.reference,
      registry: parsed.registry,
      repositoryPath: parsed.repositoryPath,
      tag: parsed.tag,
      digest: parsed.digest,
      pinnedByDigest: parsed.pinnedByDigest,
    },
    target: {
      registry,
      project,
      repositoryPrefix: prefix,
      repository,
      tag: targetTag,
      tagReference,
      quarantine: true,
    },
    requestedBy: asText(requestedBy) || 'unknown',
    createdAt: timestamp,
    updatedAt: timestamp,
    importedDigest: '',
    scanSummary: null,
    importedAt: '',
    workerId: '',
    error: '',
  };
}

// İzole worker'a verilecek credential-free handoff. Harbor robot secret, Docker
// config veya herhangi bir kimlik bilgisi İÇERMEZ; worker bunları kendi runtime
// secret'ından alır.
export function buildOnboardingWorkerHandoff(request) {
  if (!request || !OPEN_ONBOARDING_STATES.includes(request.status)) {
    throw new OnboardingValidationError(
      request?.status === ONBOARDING_STATES.CANCELLED
        ? `Onboarding request ${request.id} was cancelled; it must not be imported.`
        : 'Only a Requested or Importing request can be handed off.',
      409,
    );
  }

  return {
    contractVersion: ONBOARDING_HANDOFF_CONTRACT,
    requestId: request.id,
    source: {
      reference: request.source.reference,
      registry: request.source.registry,
      pinnedByDigest: request.source.pinnedByDigest,
    },
    target: {
      registry: request.target.registry,
      project: request.target.project,
      repository: request.target.repository,
      tag: request.target.tag,
      tagReference: request.target.tagReference,
    },
    scanner: { tool: 'trivy', scope: 'full-image' },
    constraints: {
      credentialMaterialIncluded: false,
      overwriteExistingTag: false,
      quarantine: true,
      rescanAfterImport: true,
    },
  };
}

function normalizeScanSummary(summary) {
  if (!summary || typeof summary !== 'object') return null;
  return severityKeys.reduce((acc, key) => {
    const value = Number(summary[key] ?? summary[key?.toUpperCase?.()] ?? 0);
    acc[key] = Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
    return acc;
  }, {});
}

// A person closes a request that will not be imported (for example one no worker picked up).
// Requested or Importing only; the reason is kept with who and when. A worker that already
// started may still deliver a receipt: applyImportReceipt records it without reopening.
export function cancelOnboardingRequest(request, { actorId, reason, cancelledAt } = {}) {
  if (!request || !OPEN_ONBOARDING_STATES.includes(request.status)) {
    throw new OnboardingValidationError('Only a Requested or Importing onboarding request can be cancelled.', 409);
  }
  const actor = asText(actorId);
  if (!actor) throw new OnboardingValidationError('A trusted signed-in identity is required to cancel an onboarding request.', 403);
  if (typeof reason !== 'string') throw new OnboardingValidationError('The cancellation reason must be text.');
  const text = reason.trim();
  if (text.length < REASON_MIN_LENGTH || text.length > REASON_MAX_LENGTH) {
    throw new OnboardingValidationError(`The cancellation reason must be ${REASON_MIN_LENGTH}-${REASON_MAX_LENGTH} characters.`);
  }
  if (hiddenOrLineBreakingCharacters.test(text)) {
    throw new OnboardingValidationError('The cancellation reason must be a single line of printable text.');
  }
  const timestamp = asText(cancelledAt) || new Date().toISOString();
  return {
    ...request,
    status: ONBOARDING_STATES.CANCELLED,
    updatedAt: timestamp,
    cancellation: { cancelledBy: actor, reason: text, cancelledAt: timestamp, previousStatus: request.status },
  };
}

// True when the receipt repeats the one already recorded (a worker retry): nothing changes.
export function isImportReceiptReplay(request, receipt) {
  const recorded = request?.status === ONBOARDING_STATES.CANCELLED ? request.importAfterCancellation : request;
  if (!recorded || !receipt || typeof receipt !== 'object') return false;
  const status = asText(receipt.status).toLowerCase();
  if (status === 'imported') {
    return (
      (recorded.status === ONBOARDING_STATES.IMPORTED || recorded.status === 'imported') &&
      asText(recorded.importedDigest) === asText(receipt.importedDigest).toLowerCase() &&
      asText(receipt.targetReference) === request.target?.tagReference
    );
  }
  return status === 'failed' && (recorded.status === ONBOARDING_STATES.FAILED || recorded.status === 'failed');
}

// Worker'dan dönen import receipt'ini doğrular ve isteği günceller. Başarılı
// import isteği Imported yapar (karantinaya inen digest + Trivy özeti); başarısız
// receipt Failed yapar. Fonksiyon saftır: güncellenmiş yeni istek nesnesi döner.
export function applyImportReceipt(request, receipt, { acceptedAt } = {}) {
  assert(request, 'Unknown onboarding request.');
  assert(receipt && typeof receipt === 'object' && !Array.isArray(receipt), 'The import receipt must be a JSON object.');
  assert(receipt.contractVersion === ONBOARDING_RECEIPT_CONTRACT, `Unsupported receipt contract: ${asText(receipt.contractVersion) || 'missing'}.`);
  assert(asText(receipt.requestId) === request.id, 'The receipt request id does not match.');

  const timestamp = asText(acceptedAt) || new Date().toISOString();
  const status = asText(receipt.status).toLowerCase();
  assert(['imported', 'failed'].includes(status), `Invalid receipt status: ${asText(receipt.status)}.`);

  if (request.status === ONBOARDING_STATES.CANCELLED) {
    // The worker had started before the cancellation. What it did is kept on record (an
    // imported image really is in quarantine now); the request stays cancelled.
    if (request.importAfterCancellation) {
      throw new OnboardingValidationError('A receipt is already recorded for this cancelled request.', 409);
    }
    const importedDigest = asText(receipt.importedDigest).toLowerCase();
    if (status === 'imported') {
      assert(sha256Pattern.test(importedDigest), 'The receipt importedDigest must be a valid sha256 digest.');
      assert(asText(receipt.targetReference) === request.target.tagReference, 'The receipt target reference does not match the request.');
    }
    return {
      ...request,
      updatedAt: timestamp,
      importAfterCancellation: {
        status,
        importedDigest: status === 'imported' ? importedDigest : '',
        targetReference: request.target.tagReference,
        scanSummary: status === 'imported' ? normalizeScanSummary(receipt.scanSummary) : null,
        workerId: asText(receipt.workerId),
        error: status === 'failed' ? asText(receipt.error) || 'Import worker reported a failure.' : '',
        recordedAt: timestamp,
      },
    };
  }

  if (status === 'failed') {
    return {
      ...request,
      status: ONBOARDING_STATES.FAILED,
      updatedAt: timestamp,
      importedAt: timestamp,
      workerId: asText(receipt.workerId),
      error: asText(receipt.error) || 'Import worker reported a failure.',
    };
  }

  const importedDigest = asText(receipt.importedDigest).toLowerCase();
  assert(sha256Pattern.test(importedDigest), 'The receipt importedDigest must be a valid sha256 digest.');
  assert(
    asText(receipt.targetReference) === request.target.tagReference,
    'The receipt target reference does not match the request.',
  );

  return {
    ...request,
    status: ONBOARDING_STATES.IMPORTED,
    updatedAt: timestamp,
    importedAt: timestamp,
    importedDigest,
    scanSummary: normalizeScanSummary(receipt.scanSummary),
    workerId: asText(receipt.workerId),
    error: '',
  };
}
