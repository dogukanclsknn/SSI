// SSI — remediation status of a CVE in a scanned image, derived from verified evidence.
//
// The CVE Queue aggregates live scan reports, so a CVE fixed by Copacetic is still listed
// against its *source* image (that image is unchanged in the registry). This module joins
// those findings with verified remediation jobs so the queue can say, per image, whether a
// finding was removed by a verified remediation ("remediated") or survived the
// verification re-scan ("remaining").
//
// Only jobs that passed verification count (the same rule as the publish gate): a dry run or
// an unverified execution never marks anything as remediated. Matching uses the full source
// digest (scan report id as a fallback) and the CVE + package pair, the same key the
// verification-evidence intake uses to reconcile fixed and remaining findings.

export const CVE_REMEDIATION_STATUS = Object.freeze({
  REMEDIATED: 'remediated',
  REMAINING: 'remaining',
  OPEN: 'open',
});

function text(value) {
  return String(value ?? '').trim();
}

function findingKey(cve, packageName) {
  return `${text(cve).toLowerCase()}|${text(packageName).toLowerCase()}`;
}

export function isVerifiedRemediationJob(job) {
  return (
    job?.mode === 'execution' && job?.status === 'Verified' && job?.verificationStatus === 'Passed'
  );
}

function keySet(findings) {
  return new Set(
    (Array.isArray(findings) ? findings : []).map((finding) =>
      findingKey(finding?.cve, finding?.package),
    ),
  );
}

function isNewer(candidate, current) {
  return text(candidate.verifiedAt) > text(current.verifiedAt);
}

// Indexes the newest verified job per source image. A later verification of the same
// source supersedes an earlier one, so the queue always reflects the latest evidence.
export function indexVerifiedRemediations(jobs) {
  const byDigest = new Map();
  const byReportId = new Map();

  for (const job of Array.isArray(jobs) ? jobs : []) {
    if (!isVerifiedRemediationJob(job)) continue;
    const entry = {
      jobId: text(job.id),
      verifiedAt: text(job.verifiedAt),
      patchedImageTag: text(job.patchedImageTag),
      patchedImageDigest: text(job.patchedImageDigest).toLowerCase(),
      fixed: keySet(job.fixed),
      remaining: keySet(job.remaining),
    };
    const digest = text(job.sourceDigest).toLowerCase();
    const reportId = text(job.scanReportId);
    if (digest && (!byDigest.has(digest) || isNewer(entry, byDigest.get(digest))))
      byDigest.set(digest, entry);
    if (reportId && (!byReportId.has(reportId) || isNewer(entry, byReportId.get(reportId)))) {
      byReportId.set(reportId, entry);
    }
  }

  return { byDigest, byReportId };
}

function verifiedEntryFor(index, image) {
  const digest = text(image?.digest).toLowerCase();
  if (digest.startsWith('sha256:') && index?.byDigest?.has(digest))
    return index.byDigest.get(digest);
  const reportId = text(image?.reportId);
  return (reportId && index?.byReportId?.get(reportId)) || null;
}

// Status of one CVE in one scanned image. `packages` are the packages the CVE affects in
// that image; one still present after verification makes the whole finding "remaining".
export function cveRemediationStatus(index, image, cve, packages) {
  const entry = verifiedEntryFor(index, image);
  if (!entry) return { status: CVE_REMEDIATION_STATUS.OPEN };

  const keys = (packages?.length ? packages : ['']).map((packageName) =>
    findingKey(cve, packageName),
  );
  const evidence = {
    jobId: entry.jobId,
    verifiedAt: entry.verifiedAt,
    patchedImageTag: entry.patchedImageTag,
  };
  if (keys.some((key) => entry.remaining.has(key)))
    return { status: CVE_REMEDIATION_STATUS.REMAINING, ...evidence };
  if (keys.some((key) => entry.fixed.has(key)))
    return { status: CVE_REMEDIATION_STATUS.REMEDIATED, ...evidence };
  return { status: CVE_REMEDIATION_STATUS.OPEN };
}

// Rolls the per-image statuses of one CVE up to the queue row.
export function summarizeCveRemediation(images) {
  const counts = { remediated: 0, remaining: 0, open: 0 };
  for (const image of Array.isArray(images) ? images : []) {
    const status = image?.remediation?.status;
    if (status === CVE_REMEDIATION_STATUS.REMEDIATED) counts.remediated += 1;
    else if (status === CVE_REMEDIATION_STATUS.REMAINING) counts.remaining += 1;
    else counts.open += 1;
  }

  const total = counts.remediated + counts.remaining + counts.open;
  let status = CVE_REMEDIATION_STATUS.OPEN;
  if (counts.remaining > 0) status = CVE_REMEDIATION_STATUS.REMAINING;
  else if (total > 0 && counts.remediated === total) status = CVE_REMEDIATION_STATUS.REMEDIATED;

  return { status, ...counts, total };
}
