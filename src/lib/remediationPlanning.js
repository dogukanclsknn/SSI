// SSI — remediation planning helpers (pure, no React).
//
// The Remediation screen must always say which scanned image a dry-run plan is for.
// These helpers link a scan report to the remediation jobs already created for it and
// summarise the report for the planning card.

const FULL_DIGEST = /^sha256:[a-f0-9]{64}$/;

function text(value) {
  return String(value ?? '').trim();
}

function fullDigest(value) {
  const digest = text(value).toLowerCase();
  return FULL_DIGEST.test(digest) ? digest : '';
}

function jobTime(job) {
  return text(job?.verifiedAt || job?.createdAt || job?.startedAt);
}

// Remediation jobs created from this scan report: same report id, or the same immutable
// source digest (a re-scan of the same image gets a new report but keeps the digest).
// Newest first.
export function remediationJobsForReport(jobs, report) {
  if (!report) return [];
  const reportId = text(report.id);
  const digest = fullDigest(report.digest);
  return (Array.isArray(jobs) ? jobs : [])
    .filter(
      (job) =>
        (reportId && text(job?.scanReportId) === reportId) ||
        (digest && fullDigest(job?.sourceDigest) === digest),
    )
    .sort((left, right) => jobTime(right).localeCompare(jobTime(left)));
}

// The newest job that covers a scan report, if any.
export function latestRemediationJobForReport(jobs, report) {
  return remediationJobsForReport(jobs, report)[0] || null;
}

// Harbor scan times arrive as UTC "YYYY-MM-DD HH:mm" (see harbor.js formatScannedAt);
// ISO strings are accepted too. Returns epoch milliseconds or NaN.
export function scanTime(value) {
  const raw = text(value);
  const minute = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})$/.exec(raw);
  return Date.parse(minute ? `${minute[1]}T${minute[2]}:00Z` : raw);
}

// Whether a job was planned from the image's latest scan. "stale" means the image was
// re-scanned after the job was created, so its findings may no longer match the plan.
// Compared at minute precision, the resolution of Harbor scan times.
export function planFreshness(job, report) {
  const scannedAt = scanTime(report?.scannedAt);
  const createdAt = Date.parse(text(job?.createdAt));
  if (Number.isNaN(scannedAt) || Number.isNaN(createdAt)) return 'unknown';
  const minute = 60 * 1000;
  return Math.floor(createdAt / minute) >= Math.floor(scannedAt / minute) ? 'current' : 'stale';
}

const SEVERITIES = ['critical', 'high', 'medium', 'low'];

// Counts for the planning card. "withFix" is what the scanner reports as fixable; the dry
// run itself decides what is in scope (OS packages only), so it is shown as an upper bound.
export function summarizeScanReport(report) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const severity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  let withFix = 0;
  for (const finding of findings) {
    const key = text(finding?.severity).toLowerCase();
    severity[SEVERITIES.includes(key) ? key : 'unknown'] += 1;
    if (finding?.status === 'Fix available') withFix += 1;
  }
  return { total: findings.length, withFix, severity };
}
