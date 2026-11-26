// SSI — Risk acceptance (policy exceptions)
//
// Pure, side-effect free core of the risk acceptance feature: request validation,
// lifecycle transitions and the matching that lets the publish gate stop counting an
// accepted finding. Persistence, identity and audit live in the server and the store.
//
// An exception is bound to a CVE in a repository (project/repo). Package and digest are
// optional narrowing: remediation produces a new digest on every rebuild, so a digest-bound
// exception would stop matching after the next rebuild.
//
// "Expired" is never stored. An Approved exception whose expiresAt has passed is read as
// Expired, which also removes it from policy evaluation without a scheduler.

export const EXCEPTION_REASONS = {
  not_affected: 'Not affected',
  no_fix_available: 'No fix available',
  compensating_control: 'Compensating control',
  accepted_risk: 'Accepted risk',
};

export const EXCEPTION_STATUSES = ['Requested', 'Approved', 'Rejected', 'Revoked'];
export const EXCEPTION_DECISIONS = ['approve', 'reject', 'revoke'];

export const DEFAULT_EXCEPTION_MAX_DAYS = 90;
export const DEFAULT_EXCEPTION_MAX_DAYS_CRITICAL = 30;
export const MIN_JUSTIFICATION_LENGTH = 20;
export const MIN_DECISION_NOTE_LENGTH = 10;

const DAY_MS = 24 * 60 * 60 * 1000;
const cvePattern = /^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$/i;
const repositoryPattern = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$/;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const packagePattern = /^[A-Za-z0-9][A-Za-z0-9+._:@/-]{0,213}$/;
const severityRank = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const GATED_SEVERITIES = ['critical', 'high'];

export class ExceptionValidationError extends Error {
  constructor(message, statusCode = 422) {
    super(message);
    this.name = 'ExceptionValidationError';
    this.statusCode = statusCode;
  }
}

function text(value) {
  return value == null ? '' : String(value).trim();
}

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function toTime(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  const time = value instanceof Date ? value.getTime() : Date.parse(value);
  return Number.isNaN(time) ? null : time;
}

function nowTime(now) {
  return toTime(now ?? new Date()) ?? Date.now();
}

export function buildExceptionPolicyConfig(environment = {}) {
  const maxDays = positiveInteger(environment.SSI_EXCEPTION_MAX_DAYS, DEFAULT_EXCEPTION_MAX_DAYS);
  const maxDaysCritical = Math.min(
    positiveInteger(
      environment.SSI_EXCEPTION_MAX_DAYS_CRITICAL,
      DEFAULT_EXCEPTION_MAX_DAYS_CRITICAL,
    ),
    maxDays,
  );
  return {
    maxDays,
    maxDaysCritical,
    twoPersonRule: true,
    appliesTo: ['critical-threshold', 'high-threshold'],
  };
}

export function normalizeSeverity(value) {
  const key = text(value).toLowerCase();
  return Object.hasOwn(severityRank, key) ? key : 'unknown';
}

// "harbor.example.com/project/repo:tag@sha256:…" → "project/repo". A first segment that
// looks like a host (contains "." or ":" or is localhost) is treated as the registry.
export function repositoryFromReference(reference) {
  let value = text(reference).toLowerCase();
  if (!value) return '';
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  value = value.split('@')[0];
  const lastSlash = value.lastIndexOf('/');
  const lastColon = value.lastIndexOf(':');
  if (lastColon > lastSlash) value = value.slice(0, lastColon);
  const segments = value.split('/').filter(Boolean);
  if (segments.length > 1 && (/[.:]/.test(segments[0]) || segments[0] === 'localhost'))
    segments.shift();
  return segments.join('/');
}

export function exceptionMaxDays(severity, config) {
  return normalizeSeverity(severity) === 'critical' ? config.maxDaysCritical : config.maxDays;
}

// Highest severity reported for this CVE in the repository's scan reports, or '' when the
// scans do not show it. The server uses this instead of a client-supplied severity.
export function severityForScope(reports, { cve, repository, package: packageName }) {
  const wantedPackage = text(packageName);
  let best = '';
  for (const report of reports || []) {
    if (repositoryFromReference(report.image || report.id) !== repository) continue;
    for (const finding of report.findings || []) {
      if (!sameVulnerability(finding.cve, cve)) continue;
      if (wantedPackage && text(finding.package) !== wantedPackage) continue;
      const severity = normalizeSeverity(finding.severity);
      if (!best || severityRank[severity] > severityRank[best]) best = severity;
    }
  }
  return best;
}

// CVE ids are upper case; GHSA ids keep their canonical lower-case body (GHSA-xxxx-xxxx-xxxx).
export function normalizeVulnerabilityId(value) {
  const id = text(value);
  return /^ghsa-/i.test(id) ? `GHSA-${id.slice(5).toLowerCase()}` : id.toUpperCase();
}

function sameVulnerability(left, right) {
  return text(left).toUpperCase() === text(right).toUpperCase();
}

export function validateExceptionRequest(body, { config, severity, now } = {}) {
  const cve = normalizeVulnerabilityId(body?.cve);
  if (!cvePattern.test(cve)) {
    throw new ExceptionValidationError(
      'A valid CVE (CVE-YYYY-NNNN) or GHSA identifier is required.',
    );
  }

  const repository = repositoryFromReference(body?.repository);
  if (!repositoryPattern.test(repository)) {
    throw new ExceptionValidationError('Repository must be a Harbor project/repository path.');
  }

  const packageName = text(body?.package);
  if (packageName && !packagePattern.test(packageName)) {
    throw new ExceptionValidationError('Package name is invalid.');
  }

  const digest = text(body?.digest).toLowerCase();
  if (digest && !digestPattern.test(digest)) {
    throw new ExceptionValidationError('Digest must be a full sha256 digest.');
  }

  const reasonCode = text(body?.reasonCode);
  if (!Object.hasOwn(EXCEPTION_REASONS, reasonCode)) {
    throw new ExceptionValidationError(
      `Reason must be one of: ${Object.keys(EXCEPTION_REASONS).join(', ')}.`,
    );
  }

  const justification = text(body?.justification);
  if (justification.length < MIN_JUSTIFICATION_LENGTH) {
    throw new ExceptionValidationError(
      `Justification must contain at least ${MIN_JUSTIFICATION_LENGTH} characters.`,
    );
  }
  if (justification.length > 4000) {
    throw new ExceptionValidationError('Justification must not exceed 4000 characters.');
  }

  // Unknown severity is treated as Critical: the strictest limit applies when the scans
  // cannot confirm the finding (fail-closed).
  const verifiedSeverity = severity ? normalizeSeverity(severity) : '';
  const limitSeverity = verifiedSeverity || 'critical';
  const maxDays = exceptionMaxDays(limitSeverity, config);
  const current = nowTime(now);
  // durationDays lets the server compute the expiry from its own clock (no client skew);
  // an explicit expiresAt is accepted for API clients.
  const durationDays = body?.durationDays;
  if (durationDays !== undefined && (!Number.isInteger(durationDays) || durationDays < 1)) {
    throw new ExceptionValidationError('Duration must be a whole number of days.');
  }
  const expiresAt =
    durationDays !== undefined ? current + durationDays * DAY_MS : toTime(body?.expiresAt);
  if (expiresAt === null || expiresAt <= current) {
    throw new ExceptionValidationError('Expiry must be a future date.');
  }
  if (expiresAt > current + maxDays * DAY_MS) {
    throw new ExceptionValidationError(
      verifiedSeverity
        ? `A ${verifiedSeverity} finding can be accepted for at most ${maxDays} days.`
        : `The scans do not confirm this finding's severity, so the Critical limit applies: at most ${maxDays} days.`,
    );
  }

  return {
    cve,
    repository,
    package: packageName || null,
    digest: digest || null,
    reasonCode,
    justification,
    severity: verifiedSeverity || 'unknown',
    severityVerified: Boolean(verifiedSeverity),
    expiresAt: new Date(expiresAt).toISOString(),
  };
}

export function createExceptionRecord({ id, request, actorId, now }) {
  const requestedBy = text(actorId);
  if (!requestedBy)
    throw new ExceptionValidationError('An authenticated requester identity is required.', 403);
  const timestamp = new Date(nowTime(now)).toISOString();
  return {
    id,
    ...request,
    status: 'Requested',
    requestedBy,
    requestedAt: timestamp,
    decidedBy: null,
    decidedAt: null,
    decisionNote: null,
    revokedBy: null,
    revokedAt: null,
    revokeReason: null,
    history: [
      { action: 'requested', actor: requestedBy, at: timestamp, note: request.justification },
    ],
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

export function effectiveExceptionStatus(exception, now) {
  if (exception?.status === 'Approved') {
    const expiresAt = toTime(exception.expiresAt);
    if (expiresAt === null || expiresAt <= nowTime(now)) return 'Expired';
  }
  return exception?.status || 'Requested';
}

export function isExceptionActive(exception, now) {
  return effectiveExceptionStatus(exception, now) === 'Approved';
}

// Two exceptions overlap when they could both match the same finding.
export function exceptionScopesOverlap(left, right) {
  if (text(left.cve).toUpperCase() !== text(right.cve).toUpperCase()) return false;
  if (left.repository !== right.repository) return false;
  if (left.package && right.package && left.package !== right.package) return false;
  if (left.digest && right.digest && left.digest !== right.digest) return false;
  return true;
}

// Open = blocks a second exception for the same scope. A request whose expiry has already
// passed can no longer be approved, so it does not block a new request.
export function isExceptionOpen(exception, now) {
  const status = effectiveExceptionStatus(exception, now);
  if (status === 'Requested') {
    const expiresAt = toTime(exception.expiresAt);
    return expiresAt !== null && expiresAt > nowTime(now);
  }
  return status === 'Approved';
}

export function decideException(exception, { decision, actorId, note, now }) {
  if (!EXCEPTION_DECISIONS.includes(decision)) {
    throw new ExceptionValidationError('Decision must be approve, reject or revoke.');
  }
  const actor = text(actorId);
  if (!actor)
    throw new ExceptionValidationError('An authenticated approver identity is required.', 403);
  const reason = text(note);
  if (reason.length < MIN_DECISION_NOTE_LENGTH) {
    throw new ExceptionValidationError(
      `A note of at least ${MIN_DECISION_NOTE_LENGTH} characters is required.`,
    );
  }

  const current = nowTime(now);
  const timestamp = new Date(current).toISOString();
  const status = effectiveExceptionStatus(exception, current);

  if (decision === 'approve' || decision === 'reject') {
    if (status !== 'Requested') {
      throw new ExceptionValidationError(
        `Only a requested exception can be ${decision}d; ${exception.id} is ${status}.`,
        409,
      );
    }
    // Two-person rule: always on for risk acceptance, independent of the publish flag.
    if (actor.toLowerCase() === text(exception.requestedBy).toLowerCase()) {
      throw new ExceptionValidationError(
        'Two-person rule: the requester cannot decide on their own exception.',
        403,
      );
    }
    if (decision === 'approve' && toTime(exception.expiresAt) <= current) {
      throw new ExceptionValidationError(
        'The requested expiry has already passed; ask for a new exception.',
        409,
      );
    }
    const approved = decision === 'approve';
    return {
      ...exception,
      status: approved ? 'Approved' : 'Rejected',
      decidedBy: actor,
      decidedAt: timestamp,
      decisionNote: reason,
      updatedAt: timestamp,
      history: [
        ...(exception.history || []),
        { action: approved ? 'approved' : 'rejected', actor, at: timestamp, note: reason },
      ],
    };
  }

  if (status !== 'Approved') {
    throw new ExceptionValidationError(
      `Only an active exception can be revoked; ${exception.id} is ${status}.`,
      409,
    );
  }
  return {
    ...exception,
    status: 'Revoked',
    revokedBy: actor,
    revokedAt: timestamp,
    revokeReason: reason,
    updatedAt: timestamp,
    history: [
      ...(exception.history || []),
      { action: 'revoked', actor, at: timestamp, note: reason },
    ],
  };
}

// The most severe finding an exception may cover: the severity it was approved for (and
// whose duration limit it passed). An unconfirmed severity was held to the Critical limit.
function coverageRank(exception) {
  return exception.severityVerified === false
    ? severityRank.critical
    : severityRank[normalizeSeverity(exception.severity)];
}

function exceptionMatchesFinding(exception, finding, repositories, digests) {
  if (!sameVulnerability(exception.cve, finding.cve)) return false;
  if (!repositories.has(exception.repository)) return false;
  if (exception.package && exception.package !== text(finding.package)) return false;
  if (exception.digest && !digests.has(exception.digest)) return false;
  // A finding rescored above the approved severity is not covered (fail-closed).
  if (severityRank[normalizeSeverity(finding.severity)] > coverageRank(exception)) return false;
  return true;
}

// Matches active exceptions against the output image findings. Only Critical and High
// findings are gated, so only those can be accepted; everything else stays in "remaining".
// Returns the accepted findings, the remaining counts and the exceptions that were applied.
// Only Approved, unexpired exceptions are considered. `digests` holds the output digest and
// the source digest it was remediated from.
export function applyExceptions({ findings, exceptions, repositories, digests, now }) {
  const scope = new Set((repositories || []).map(repositoryFromReference).filter(Boolean));
  const digestScope = new Set(
    (digests || []).map((value) => text(value).toLowerCase()).filter(Boolean),
  );
  const active = (exceptions || []).filter((exception) => isExceptionActive(exception, now));
  const remaining = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const accepted = [];
  const applied = new Map();

  for (const finding of findings || []) {
    const severity = normalizeSeverity(finding.severity);
    const match =
      GATED_SEVERITIES.includes(severity) &&
      active.find((exception) => exceptionMatchesFinding(exception, finding, scope, digestScope));
    if (!match) {
      remaining[severity] += 1;
      continue;
    }
    accepted.push({
      cve: normalizeVulnerabilityId(finding.cve),
      package: text(finding.package),
      severity,
      exceptionId: match.id,
    });
    const entry = applied.get(match.id) || {
      id: match.id,
      cve: match.cve,
      expiresAt: match.expiresAt,
      findings: 0,
    };
    entry.findings += 1;
    applied.set(match.id, entry);
  }

  return { accepted, remaining, appliedExceptions: [...applied.values()] };
}

function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const finding of findings || []) counts[normalizeSeverity(finding.severity)] += 1;
  return counts;
}

function reportForDigest(reports, digest) {
  const expected = text(digest).toLowerCase();
  if (!expected) return null;
  return (reports || []).find((report) => text(report.digest).toLowerCase() === expected) || null;
}

// Publish gate input for one verified remediation job. Exceptions are applied only when
// they can be proven to match: the output digest's scan report must exist and still show
// the Critical/High counts the remediation was verified with. Otherwise the result is
// "unavailable" and the thresholds stay unchanged (fail-closed).
// The repository scope covers the image lineage: the remediated output repository and the
// source repository where the findings were first reported.
export function buildExceptionAdjustment({ job, reports, exceptions, now }) {
  const active = (exceptions || []).filter((exception) => isExceptionActive(exception, now));
  if (active.length === 0) return { status: 'none' };

  const outputReport = reportForDigest(reports, job?.patchedImageDigest);
  if (!outputReport || !Array.isArray(outputReport.findings)) {
    return { status: 'unavailable', reason: 'the output image scan report was not found.' };
  }
  const verified = job.fullImageComparison?.output?.severity || null;
  const current = severityCounts(outputReport.findings);
  if (
    !verified ||
    ['critical', 'high'].some((key) => Number(verified[key] || 0) !== current[key])
  ) {
    return {
      status: 'unavailable',
      reason: 'the output image scan changed since the remediation was verified.',
    };
  }
  const sourceReport = reportForDigest(reports, job.sourceDigest);
  return {
    status: 'applied',
    ...applyExceptions({
      findings: outputReport.findings,
      exceptions: active,
      repositories: [outputReport.image, sourceReport?.image, job.image, job.patchedImageTag],
      digests: [job.patchedImageDigest, job.sourceDigest],
      now,
    }),
  };
}
