import {
  buildExecutionReadiness,
  createLifecycleEvent,
  REMEDIATION_LIFECYCLE_STATES,
} from './remediationLifecycle.js';
import { classifyImageOs, OS_KIND } from './imageOs.js';

export const REMEDIATION_SCOPE = 'os-packages-only';

export const COPA_ENGINE = {
  name: 'Copacetic',
  version: 'v0.14.2',
  execution: 'not-run',
};

const severityKeys = ['critical', 'high', 'medium', 'low'];
const unavailableFixedVersions = new Set(['', '-', 'n/a', 'na', 'unknown', 'none']);

function asText(value, fallback = '') {
  return value == null ? fallback : String(value);
}

function normalizedText(value) {
  return asText(value).trim().toLowerCase();
}

function severityKey(severity) {
  const normalized = normalizedText(severity);
  return severityKeys.includes(normalized) ? normalized : null;
}

function countSeverities(findings) {
  return findings.reduce(
    (counts, finding) => {
      const key = severityKey(finding.severity);
      if (key) {
        counts[key] += 1;
      }
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
}

function hasFixedVersion(value) {
  return !unavailableFixedVersions.has(normalizedText(value));
}

function isWolfiTarget(report, finding) {
  return [report.os, report.image, finding.type, finding.target]
    .map((value) => normalizedText(value))
    .some((value) => value.includes('wolfi') || value.includes('chainguard'));
}

function exclusionReason(report, finding) {
  if (finding.class !== 'os-pkgs') {
    if (finding.class === 'lang-pkgs') {
      return 'Application dependency remediation is outside the phase-one OS package scope.';
    }

    return 'Package class is not proven to be os-pkgs; it cannot be sent to Copa safely.';
  }

  if (isWolfiTarget(report, finding)) {
    return 'Wolfi/Chainguard images are not eligible for Copa patching in this phase.';
  }

  if (!finding.package || finding.package === '-') {
    return 'Package metadata is incomplete.';
  }

  if (!hasFixedVersion(finding.fixed)) {
    return 'No fixed package version is available.';
  }

  return '';
}

function plannedFinding(finding) {
  return {
    cve: finding.cve || 'UNKNOWN',
    package: finding.package || '-',
    from: finding.installed || '-',
    to: finding.fixed || '-',
    severity: finding.severity || 'Unknown',
    cvss: Number(finding.cvss) || 0,
  };
}

function deduplicatePackageUpdates(findings) {
  const seen = new Set();

  return findings.filter((finding) => {
    const key = `${finding.package}|${finding.from}|${finding.to}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export function proposePatchedReference(imageReference) {
  const reference = asText(imageReference).trim();
  if (!reference) {
    return '';
  }

  const withoutDigest = reference.split('@')[0];
  const lastSlash = withoutDigest.lastIndexOf('/');
  const lastColon = withoutDigest.lastIndexOf(':');
  const repository = lastColon > lastSlash ? withoutDigest.slice(0, lastColon) : withoutDigest;
  const tag = lastColon > lastSlash ? withoutDigest.slice(lastColon + 1) : 'latest';

  return `${repository}:${tag}-copa-r1`;
}

export function planOsPackageRemediation(report = {}) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const eligible = [];
  const remaining = [];
  const excluded = [];

  for (const finding of findings) {
    const reason = exclusionReason(report, finding);
    const normalized = plannedFinding(finding);

    if (!reason) {
      eligible.push(normalized);
      continue;
    }

    if (finding.class === 'os-pkgs') {
      remaining.push({ ...normalized, reason });
    } else {
      excluded.push({ ...normalized, reason });
    }
  }

  const osFindings = findings.filter((finding) => finding.class === 'os-pkgs');

  return {
    scope: REMEDIATION_SCOPE,
    before: countSeverities(osFindings),
    plannedFixes: eligible,
    packageUpdates: deduplicatePackageUpdates(eligible),
    remaining,
    excluded,
  };
}

// Windows images are out of scope until Windows support is built: Copa patches Linux OS
// packages only. The request is refused instead of producing a misleading plan.
export const WINDOWS_NOT_SUPPORTED_MESSAGE =
  'Windows images are not supported yet. Copa patches Linux OS packages only, and Windows scanning is planned ' +
  'for a later release. Rebuild the image on the current Microsoft base image instead.';

export class RemediationScopeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RemediationScopeError';
    this.statusCode = 422;
  }
}

export function assertRemediationInScope(report) {
  if (classifyImageOs(report?.os).kind === OS_KIND.WINDOWS) {
    throw new RemediationScopeError(WINDOWS_NOT_SUPPORTED_MESSAGE);
  }
}

// Report-only jobs were created for Windows images by an earlier version. They are kept in
// storage (the audit log refers to them) but are no longer shown or counted.
export function isReportOnlyJob(job) {
  return job?.remediation === 'report-only' || job?.status === 'ReportOnly';
}

export function createDryRunRemediationJob({ id, report, createdAt }) {
  assertRemediationInScope(report);

  const plan = planOsPackageRemediation(report);
  const image = report.image || report.id || 'unknown:image';
  const status = plan.plannedFixes.length > 0 ? 'Planned' : 'Blocked';
  const timestamp = createdAt || new Date().toISOString();
  const outputReference = proposePatchedReference(image);

  const job = {
    id,
    type: 'remediation',
    mode: 'dry-run',
    status,
    lifecycleState:
      status === 'Blocked' ? REMEDIATION_LIFECYCLE_STATES.BLOCKED : REMEDIATION_LIFECYCLE_STATES.PLANNED,
    image,
    sourceDigest: report.digest || '',
    scanReportId: report.id || image,
    scanner: report.scanner || 'Trivy',
    os: report.os || 'unknown',
    scope: REMEDIATION_SCOPE,
    engine: COPA_ENGINE.name,
    engineVersion: COPA_ENGINE.version,
    execution: COPA_ENGINE.execution,
    createdAt: timestamp,
    startedAt: '',
    verifiedAt: '',
    verificationStatus: 'Pending',
    proposedPatchedTag: outputReference,
    patchedImageTag: '',
    patchedImageDigest: '',
    before: plan.before,
    after: null,
    plannedFixes: plan.plannedFixes,
    packageUpdates: plan.packageUpdates,
    fixed: [],
    remaining: plan.remaining,
    excluded: plan.excluded,
    canonicalReport: null,
    logs: [
      `Dry run created from ${report.scanner || 'Trivy'} scan ${report.id || image}.`,
      `${plan.plannedFixes.length} eligible OS package vulnerability finding(s) planned.`,
      'No image pull, Copa patch, registry push, or re-scan was executed.',
    ],
    error:
      status === 'Blocked'
        ? 'No eligible OS package vulnerability finding was found for the phase-one remediation scope.'
        : '',
  };

  return {
    ...job,
    lifecycleEvents: [
      createLifecycleEvent({
        state: job.lifecycleState,
        at: timestamp,
        actor: 'api',
        message:
          status === 'Blocked'
            ? 'Dry Run blocked because no eligible OS package remediation was found.'
            : 'Dry Run plan created; no image pull, Copa patch, registry push, or re-scan was requested.',
      }),
    ],
    executionReadiness: buildExecutionReadiness(job),
  };
}

export function replanDryRunFromCanonicalReport({ job, canonicalReport, acceptedAt }) {
  if (!job || job.mode !== 'dry-run') {
    throw new Error('Canonical Trivy input can only be attached to a Dry Run remediation job.');
  }

  if (!canonicalReport?.normalizedReport || !canonicalReport?.receipt) {
    throw new Error('A validated canonical Trivy report is required to replan remediation.');
  }

  const timestamp = acceptedAt || new Date().toISOString();
  const report = {
    ...canonicalReport.normalizedReport,
    id: job.scanReportId || canonicalReport.normalizedReport.id,
    image: job.image || canonicalReport.normalizedReport.image,
    digest: job.sourceDigest || canonicalReport.receipt.sourceDigest,
  };
  const replanned = createDryRunRemediationJob({
    id: job.id,
    report,
    createdAt: job.createdAt || timestamp,
  });
  const planMessage =
    replanned.status === 'Blocked'
      ? 'Canonical report accepted, but no eligible OS package remediation was found.'
      : `Canonical report accepted and ${replanned.plannedFixes.length} eligible OS package finding(s) were planned.`;
  const updatedJob = {
    ...replanned,
    createdAt: job.createdAt || timestamp,
    updatedAt: timestamp,
    scanReportId: job.scanReportId || canonicalReport.normalizedReport.id,
    image: job.image || canonicalReport.normalizedReport.image,
    sourceDigest: job.sourceDigest || canonicalReport.receipt.sourceDigest,
    proposedPatchedTag: proposePatchedReference(job.image || canonicalReport.normalizedReport.image),
    canonicalReport: {
      ...canonicalReport.receipt,
      acceptedAt: timestamp,
    },
    // Worker pipeline runs started from SSI stay with the job (src/lib/pipelineRuns.js): the
    // Copa input check needs the canonical scan run that produced this report.
    ...(Array.isArray(job.pipelineRuns) ? { pipelineRuns: job.pipelineRuns } : {}),
    logs: [
      ...(job.logs || []),
      `Canonical Trivy JSON accepted for immutable source digest ${canonicalReport.receipt.sourceDigest}.`,
      planMessage,
      'No image pull, Copa patch, registry push, or re-scan was executed.',
    ],
    lifecycleEvents: [
      ...(job.lifecycleEvents || []),
      createLifecycleEvent({
        state: replanned.lifecycleState,
        at: timestamp,
        actor: 'canonical-intake',
        message: planMessage,
      }),
    ],
  };

  return {
    ...updatedJob,
    executionReadiness: buildExecutionReadiness(updatedJob),
  };
}
