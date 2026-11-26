// SSI — Image comparison: what changed between the source image and its patched output.
//
// Answers the reviewer's question before an approval: "did the fix change anything important?"
// Built only from SSI's own evidence (bound to immutable digests) and the registry's scans:
//   - OS package CVEs at verification (remediation evidence, frozen)
//   - full-image CVEs today (Harbor scans of both digests)
//   - OS package changes and runtime behaviour (candidate test evidence)
//   - image configuration (configuration integrity evidence)
//   - layers and size (worker-reported image facts, when available)
//   - supply chain (signature, SBOM, provenance of the patched image)
//
// The comparison is a list of dimensions. Every dimension states its status (available,
// unavailable, not-applicable), where its data comes from, its columns and rows, and the
// points a reviewer must look at ("attention"). A new dimension is one more builder in
// DIMENSION_BUILDERS; consumers (API, console, CSV, report document) render any dimension
// from its columns. Contract: ssi.image-comparison/v1.
//
// Pure: no I/O.

import { CandidateTestError, diffPackages } from './candidateTest.js';
import { inventoryOf } from './imageInspection.js';

export const IMAGE_COMPARISON_CONTRACT = 'ssi.image-comparison/v1';

export const DIMENSION_STATUS = Object.freeze({
  AVAILABLE: 'available',
  UNAVAILABLE: 'unavailable',
  NOT_APPLICABLE: 'not-applicable',
});

// Attention levels, most important first.
export const ATTENTION_LEVELS = Object.freeze(['high', 'warning', 'info']);

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
const SEVERE = new Set(['Critical', 'High']);
const sha256Pattern = /^sha256:[a-f0-9]{64}$/;

export class ImageComparisonError extends Error {
  constructor(message, statusCode = 422) {
    super(message);
    this.name = 'ImageComparisonError';
    this.statusCode = statusCode;
  }
}

function text(value) {
  return value == null ? '' : String(value).trim();
}

function digestOf(value) {
  const digest = text(value).toLowerCase();
  return sha256Pattern.test(digest) ? digest : '';
}

export function normalizeSeverity(value) {
  const name = text(value).toLowerCase();
  return SEVERITIES.find((severity) => severity.toLowerCase() === name) || 'Unknown';
}

function severityRank(value) {
  return SEVERITIES.indexOf(normalizeSeverity(value));
}

function countBySeverity(rows) {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity.toLowerCase(), 0]));
  for (const row of rows) counts[normalizeSeverity(row.severity).toLowerCase()] += 1;
  return counts;
}

function findingKey(finding) {
  return `${text(finding?.cve).toUpperCase()}|${text(finding?.package).toLowerCase()}`;
}

function attention(level, code, message) {
  return { level, code, message };
}

function dimension({
  id,
  title,
  source,
  status = DIMENSION_STATUS.AVAILABLE,
  note = '',
  summary = {},
  columns = [],
  rows = [],
  attention: points = [],
}) {
  return { id, title, source, status, note, summary, columns, rows, attention: points };
}

function unavailable(id, title, source, note) {
  return dimension({ id, title, source, status: DIMENSION_STATUS.UNAVAILABLE, note });
}

const CHANGE_ORDER = {
  new: 0,
  removed: 1,
  added: 2,
  changed: 3,
  restored: 4,
  fixed: 5,
  remaining: 6,
  unchanged: 7,
};

function byChangeThenSeverity(left, right) {
  return (
    (CHANGE_ORDER[left.change] ?? 9) - (CHANGE_ORDER[right.change] ?? 9) ||
    severityRank(left.severity) - severityRank(right.severity) ||
    text(left.cve || left.name || left.id).localeCompare(text(right.cve || right.name || right.id))
  );
}

const VULNERABILITY_COLUMNS = [
  { key: 'change', label: 'Change' },
  { key: 'cve', label: 'Vulnerability' },
  { key: 'severity', label: 'Severity' },
  { key: 'package', label: 'Package' },
  { key: 'source', label: 'Source version' },
  { key: 'patched', label: 'Patched version' },
];

// ── OS package CVEs at verification (frozen evidence) ──────────────────────────
function verifiedVulnerabilities({ job }) {
  const id = 'vulnerabilities-verified';
  const title = 'OS package vulnerabilities at verification';
  const source = 'Remediation evidence (Trivy re-scan of the patched digest)';
  if (!Array.isArray(job.fixed) || !Array.isArray(job.remaining)) {
    return unavailable(id, title, source, 'The job has no verification evidence.');
  }
  const rows = [
    ...job.fixed.map((finding) => ({
      change: 'fixed',
      cve: text(finding.cve),
      severity: normalizeSeverity(finding.severity),
      package: text(finding.package),
      source: text(finding.from),
      patched: text(finding.to),
      changed: true,
    })),
    ...job.remaining.map((finding) => ({
      change: 'remaining',
      cve: text(finding.cve),
      severity: normalizeSeverity(finding.severity),
      package: text(finding.package),
      source: text(finding.from),
      patched: text(finding.from),
      changed: false,
    })),
  ].sort(byChangeThenSeverity);
  const remaining = rows.filter((row) => row.change === 'remaining');
  const severeRemaining = remaining.filter((row) => SEVERE.has(row.severity)).length;
  return dimension({
    id,
    title,
    source,
    note: 'Frozen when the evidence was accepted; this is what the approval is based on.',
    summary: {
      fixed: job.fixed.length,
      remaining: job.remaining.length,
      before: job.before || null,
      after: job.after || null,
    },
    columns: VULNERABILITY_COLUMNS,
    rows,
    attention:
      severeRemaining > 0
        ? [
            attention(
              'warning',
              'severe-remaining',
              `${severeRemaining} critical or high OS package finding(s) remain after the patch.`,
            ),
          ]
        : [],
  });
}

// ── Full-image CVEs today (Harbor scans of both digests) ───────────────────────
function findingsOf(report) {
  return (Array.isArray(report?.findings) ? report.findings : []).filter((finding) =>
    text(finding?.cve),
  );
}

// Harbor prints scan times as "YYYY-MM-DD HH:MM" (UTC); null when not parseable.
function scanTime(value) {
  const match = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})/.exec(text(value));
  const time = match ? Date.parse(`${match[1]}T${match[2]}:00Z`) : NaN;
  return Number.isFinite(time) ? time : null;
}

const SCANS_APART_DAYS = 7;
const NO_COMMON_FINDINGS_MINIMUM = 5;
export const PACKAGE_UPDATED = 'Updated by the patch';
export const PACKAGE_UNCHANGED = 'Not changed by the patch';

// Copa changes OS packages only and keeps the source layers, so a package missing from the
// candidate test's change list is one the patch did not touch.
function remediationPackageEvidence(updatedPackages) {
  if (!updatedPackages) return null;
  return {
    classify: (name) =>
      updatedPackages.has(name)
        ? { label: PACKAGE_UPDATED, unchanged: false }
        : { label: PACKAGE_UNCHANGED, unchanged: true },
    attributableSuffix: ', in packages the patch updated',
    unchangedNote: (count, shown) =>
      `${count} finding(s) appear only in today's scan of the patched image, in packages the patch did not change (${shown}). ` +
      'They come from newer vulnerability data, not from the patch; rescan the source image in Harbor to confirm.',
  };
}

// Two inspected images: a package is "the same" only when both OS inventories list it with
// the same version for every architecture. A package missing from the compared image's OS
// inventory (an application dependency, a copied binary) may differ, so it never counts.
export const PACKAGE_SAME_VERSION = 'Same version in both images';
export const PACKAGE_DIFFERENT_VERSION = 'Different in the compared image';
export const PACKAGE_NOT_INVENTORIED = 'Not in the OS package inventory';

function inspectionPackageEvidence(baseInspection, headInspection) {
  if (!baseInspection || !headInspection) return null;
  const versionsByName = (inspection) => {
    const byName = new Map();
    for (const item of Array.isArray(inspection.packages) ? inspection.packages : []) {
      const name = text(item.name).toLowerCase();
      if (!byName.has(name)) byName.set(name, new Map());
      byName.get(name).set(text(item.arch), text(item.version));
    }
    return byName;
  };
  const base = versionsByName(baseInspection);
  const head = versionsByName(headInspection);
  const sameVersion = (name) => {
    const left = base.get(name);
    const right = head.get(name);
    return (
      Boolean(left && right) &&
      left.size === right.size &&
      [...right].every(([arch, version]) => left.get(arch) === version)
    );
  };
  return {
    classify: (name) =>
      !head.has(name)
        ? { label: PACKAGE_NOT_INVENTORIED, unchanged: false }
        : sameVersion(name)
          ? { label: PACKAGE_SAME_VERSION, unchanged: true }
          : { label: PACKAGE_DIFFERENT_VERSION, unchanged: false },
    attributableSuffix: '',
    unchangedNote: (count, shown) =>
      `${count} finding(s) appear only in today's scan of the compared image, in packages with the same version in both images (${shown}). ` +
      'They come from newer vulnerability data, not from a difference between the images; rescan the base image in Harbor to confirm.',
  };
}

// Package names the patch changed, from the candidate test of the same patched digest; null
// when that evidence is missing (no test, another digest, or a summary-only legacy record).
function updatedPackagesOf(job) {
  const test = job.candidateTest;
  const changes = test?.packageChanges?.changes;
  if (
    !Array.isArray(changes) ||
    digestOf(test.candidateDigest) !== digestOf(job.patchedImageDigest)
  ) {
    return null;
  }
  return new Set(changes.map((item) => text(item?.name).toLowerCase()).filter(Boolean));
}

// Full-image findings of two scans compared by vulnerability and package. Shared by the
// remediation comparison (source -> patched) and the free comparison of two images
// (base -> compared). `sides` names the two images in attention messages.
function diffFindings(baseReport, headReport, sides) {
  const before = new Map();
  for (const finding of findingsOf(baseReport)) before.set(findingKey(finding), finding);
  const after = new Map();
  for (const finding of findingsOf(headReport)) after.set(findingKey(finding), finding);

  const rows = [];
  for (const [key, finding] of before) {
    const head = after.get(key);
    rows.push({
      change: head ? 'remaining' : 'fixed',
      cve: text(finding.cve),
      severity: normalizeSeverity((head || finding).severity),
      package: text(finding.package),
      source: text(finding.installed),
      // A remediation installs the scanner's fix version; two arbitrary images only show
      // what the compared scan reports, so its version stays empty for a fixed finding.
      patched: head
        ? text(head.installed)
        : sides.fixVersionWhenFixed
          ? text(finding.fixed) || ''
          : '',
      changed: !head,
    });
  }
  for (const [key, finding] of after) {
    if (before.has(key)) continue;
    rows.push({
      change: 'new',
      cve: text(finding.cve),
      severity: normalizeSeverity(finding.severity),
      package: text(finding.package),
      source: '',
      patched: text(finding.installed),
      changed: true,
    });
  }
  rows.sort(byChangeThenSeverity);

  const fresh = rows.filter((row) => row.change === 'new');
  // With evidence of which packages are the same in both images (sides.packageEvidence), a new
  // finding in such a package cannot come from the difference between the images: the two
  // scans used different vulnerability data.
  const evidence = sides.packageEvidence || null;
  const fromScanData = [];
  if (evidence) {
    for (const row of fresh) {
      const verdict = evidence.classify(row.package.toLowerCase());
      row.packageChange = verdict.label;
      if (verdict.unchanged) fromScanData.push(row);
    }
  }
  const attributable = fresh.filter((row) => !fromScanData.includes(row));
  const severeAttributable = attributable.filter((row) => SEVERE.has(row.severity)).length;
  const points = [];
  if (attributable.length > 0) {
    points.push(
      attention(
        severeAttributable > 0 ? 'high' : 'warning',
        sides.newCode,
        `${attributable.length} vulnerability finding(s) appear only in ${sides.head}${evidence?.attributableSuffix || ''}${severeAttributable > 0 ? ` (${severeAttributable} critical or high)` : ''}.`,
      ),
    );
  }
  if (fromScanData.length > 0) {
    const names = [...new Set(fromScanData.map((row) => row.package))];
    const shown =
      names.slice(0, 5).join(', ') + (names.length > 5 ? ` and ${names.length - 5} more` : '');
    points.push(
      attention(
        'info',
        'new-in-unchanged-packages',
        evidence.unchangedNote(fromScanData.length, shown),
      ),
    );
  }
  // Two images that share no finding at all are rarely versions of the same image.
  const remainingCount = rows.filter((row) => row.change === 'remaining').length;
  if (
    sides.warnNoCommonFindings &&
    remainingCount === 0 &&
    before.size >= NO_COMMON_FINDINGS_MINIMUM &&
    after.size >= NO_COMMON_FINDINGS_MINIMUM
  ) {
    points.push(
      attention(
        'warning',
        'no-common-findings',
        `The two images share none of their ${before.size} and ${after.size} findings. They may be built on different base images or operating systems; compare versions of the same image for a meaningful result.`,
      ),
    );
  }
  // Scans made far apart use different vulnerability data: CVEs published in between show
  // up as differences that the images themselves do not have.
  const [baseTime, headTime] = [scanTime(baseReport.scannedAt), scanTime(headReport.scannedAt)];
  const daysApart =
    baseTime === null || headTime === null
      ? null
      : Math.floor(Math.abs(headTime - baseTime) / 86_400_000);
  if (daysApart !== null && daysApart >= SCANS_APART_DAYS) {
    points.push(
      attention(
        'info',
        'scans-apart',
        `The two Harbor scans are ${daysApart} days apart. Vulnerabilities published in between appear as differences; rescan the older image in Harbor for a like-for-like comparison.`,
      ),
    );
  }
  return {
    rows,
    points,
    summary: {
      fixed: rows.filter((row) => row.change === 'fixed').length,
      remaining: remainingCount,
      new: fresh.length,
      newInUnchangedPackages: evidence ? fromScanData.length : null,
      newBySeverity: countBySeverity(fresh),
      today: { source: before.size, patched: after.size },
      scannedAt: { source: text(baseReport.scannedAt), patched: text(headReport.scannedAt) },
      scanDaysApart: daysApart,
      scanner: text(headReport.scanner || baseReport.scanner),
    },
  };
}

const CURRENT_VULNERABILITY_NOTE =
  'Compared by vulnerability and package. "New" means the finding is reported for the patched image but not for the source: ' +
  'either the updated package version carries it, or the two scans used different vulnerability data.';

function currentVulnerabilities({ job, sourceReport, outputReport }) {
  const id = 'vulnerabilities-current';
  const title = 'Full-image vulnerabilities today';
  const source = 'Harbor scans of the source and patched digests';
  const sourceDigest = digestOf(job.sourceDigest);
  const outputDigest = digestOf(job.patchedImageDigest);
  const matches = (report, digest) => Boolean(report) && digestOf(report.digest) === digest;
  if (!matches(sourceReport, sourceDigest) || !matches(outputReport, outputDigest)) {
    const missing = [
      !matches(sourceReport, sourceDigest) && 'source',
      !matches(outputReport, outputDigest) && 'patched',
    ]
      .filter(Boolean)
      .join(' and ');
    return unavailable(
      id,
      title,
      source,
      `No current Harbor scan of the ${missing} digest is available.`,
    );
  }

  const diff = diffFindings(sourceReport, outputReport, {
    head: 'the patched image',
    newCode: 'new-in-patched',
    fixVersionWhenFixed: true,
    packageEvidence: remediationPackageEvidence(updatedPackagesOf(job)),
  });
  const snapshot = job.fullImageComparison?.status === 'available' ? job.fullImageComparison : null;
  const atVerification = snapshot
    ? {
        source: Number(snapshot.source?.findings) || 0,
        patched: Number(snapshot.output?.findings) || 0,
      }
    : null;
  const points = [...diff.points];
  if (atVerification && diff.summary.today.patched > atVerification.patched) {
    points.push(
      attention(
        'info',
        'found-since-verification',
        `The patched image has ${diff.summary.today.patched - atVerification.patched} more finding(s) today than at verification: vulnerabilities published since then.`,
      ),
    );
  }
  return dimension({
    id,
    title,
    source,
    note:
      diff.summary.newInUnchangedPackages === null
        ? CURRENT_VULNERABILITY_NOTE
        : `${CURRENT_VULNERABILITY_NOTE} "Package change" says, from the candidate test, whether the patch updated the package of a new finding.`,
    summary: { ...diff.summary, atVerification },
    columns:
      diff.summary.newInUnchangedPackages === null
        ? VULNERABILITY_COLUMNS
        : [...VULNERABILITY_COLUMNS, { key: 'packageChange', label: 'Package change' }],
    rows: diff.rows,
    attention: points,
  });
}

// ── OS package changes (candidate test evidence) ───────────────────────────────
function packages({ job }) {
  const id = 'packages';
  const title = 'OS packages';
  const source = 'Candidate test (package inventory of both images)';
  const changes = job.candidateTest?.packageChanges;
  if (!changes)
    return unavailable(
      id,
      title,
      source,
      'No candidate test result yet: run SSI - Candidate Test for this job.',
    );
  const listed = Array.isArray(changes.changes) ? changes.changes : [];
  const rows = listed
    .map((item) => ({
      change: item.change,
      name: item.name,
      arch: item.arch || '',
      source: item.from || '',
      patched: item.to || '',
      planned: item.planned ? 'Planned fix' : 'Not in the plan',
      majorVersionChange: item.majorVersionChange ? 'Yes' : '',
      changed: true,
    }))
    .sort(byChangeThenSeverity);
  const summary = packageSummary(changes.summary, listed);
  const points = [];
  if (summary.unplanned > 0) {
    points.push(
      attention(
        'high',
        'unplanned-package-change',
        `${summary.unplanned} package change(s) were not in the remediation plan.`,
      ),
    );
  }
  if (summary.removed > 0)
    points.push(
      attention(
        'high',
        'package-removed',
        `${summary.removed} package(s) were removed by the patch.`,
      ),
    );
  if (summary.majorVersionChanges > 0) {
    points.push(
      attention(
        'warning',
        'major-version-change',
        `${summary.majorVersionChanges} package(s) moved to a new major version.`,
      ),
    );
  }
  if (summary.added > 0)
    points.push(
      attention('warning', 'package-added', `${summary.added} package(s) were added by the patch.`),
    );
  return dimension({
    id,
    title,
    source,
    note: Array.isArray(changes.changes)
      ? ''
      : 'This candidate test record carries package counts only; re-run the candidate test for the package list.',
    summary,
    columns: [
      { key: 'change', label: 'Change' },
      { key: 'name', label: 'Package' },
      { key: 'arch', label: 'Arch' },
      { key: 'source', label: 'Source version' },
      { key: 'patched', label: 'Patched version' },
      { key: 'planned', label: 'Plan' },
      { key: 'majorVersionChange', label: 'Major version' },
    ],
    rows,
    attention: points,
  });
}

// Counts from the worker summary; any count it leaves out is derived from the listed changes.
function packageSummary(reported = {}, listed = []) {
  const count = (key, derived) =>
    Number.isFinite(Number(reported?.[key])) && reported?.[key] !== null
      ? Number(reported[key])
      : derived;
  return {
    changed: count('changed', listed.length),
    unplanned: count('unplanned', listed.filter((item) => !item.planned).length),
    added: count('added', listed.filter((item) => item.change === 'added').length),
    removed: count('removed', listed.filter((item) => item.change === 'removed').length),
    majorVersionChanges: count(
      'majorVersionChanges',
      listed.filter((item) => item.majorVersionChange).length,
    ),
    unchanged: count('unchanged', null),
  };
}

// ── Image configuration (configuration integrity evidence) ─────────────────────
function configuration({ job }) {
  const id = 'configuration';
  const title = 'Image configuration';
  const source = 'Configuration integrity evidence (remediation worker)';
  const integrity = job.verificationEvidence?.configIntegrity;
  if (!integrity)
    return unavailable(
      id,
      title,
      source,
      'The verification evidence of this job predates the configuration check.',
    );
  const restoredFields = Array.isArray(integrity.restoredFields) ? integrity.restoredFields : [];
  const facts = job.candidateTest?.imageFacts;
  const fields =
    facts?.source?.config && facts?.candidate?.config
      ? configFieldRows(facts.source.config, facts.candidate.config)
      : [];
  const restored = new Set(restoredFields);
  const rows = fields.length
    ? // A restored field is a change Copa made and SSI undid: it stays visible under "Only
      // changes" whether or not the worker reported the values. Still different = drift.
      fields.map((row) =>
        restored.has(row.field)
          ? { ...row, change: row.changed ? 'changed' : 'restored', changed: true }
          : row,
      )
    : restoredFields.map((field) => ({
        change: 'restored',
        field,
        source: '',
        patched: '',
        changed: true,
      }));
  const points = [];
  if (integrity.status === 'restored') {
    points.push(
      attention(
        'info',
        'config-restored',
        `Copa dropped ${restoredFields.join(', ') || 'configuration fields'}; the values were restored from the source and verified.`,
      ),
    );
  }
  const drifted = rows.filter((row) => row.change === 'changed');
  if (drifted.length > 0) {
    points.push(
      attention(
        'high',
        'config-changed',
        `The runtime configuration differs in ${drifted.map((row) => row.field).join(', ')}.`,
      ),
    );
  }
  return dimension({
    id,
    title,
    source,
    note: fields.length
      ? 'Environment variables are compared by name only; their values are never collected.'
      : 'Field values become visible once the candidate test worker reports image facts.',
    summary: { status: integrity.status, platform: text(integrity.platform), restoredFields },
    columns: [
      { key: 'change', label: 'Change' },
      { key: 'field', label: 'Field' },
      { key: 'source', label: 'Source' },
      { key: 'patched', label: 'Patched' },
    ],
    rows,
    attention: points,
  });
}

// Field-by-field comparison of two runtime configurations (worker-reported; Env as names only).
export function configFieldRows(sourceConfig = {}, patchedConfig = {}) {
  const show = (value) =>
    value === undefined || value === null || value === ''
      ? ''
      : typeof value === 'string'
        ? value
        : JSON.stringify(value);
  const keys = [...new Set([...Object.keys(sourceConfig), ...Object.keys(patchedConfig)])].sort();
  return keys.map((field) => {
    const left = show(sourceConfig[field]);
    const right = show(patchedConfig[field]);
    return {
      change: left === right ? 'unchanged' : 'changed',
      field,
      source: left,
      patched: right,
      changed: left !== right,
    };
  });
}

// ── Runtime behaviour (candidate test evidence) ────────────────────────────────
const CHECK_LABELS = {
  'image-config': 'Runtime configuration',
  startup: 'Startup with the default command',
  healthcheck: 'Health check',
  'package-inventory': 'OS packages',
};

function runtime({ job }) {
  const id = 'runtime';
  const title = 'Runtime behaviour';
  const source = 'Candidate test (both images started side by side, isolated)';
  const test = job.candidateTest;
  if (!test)
    return unavailable(
      id,
      title,
      source,
      'No candidate test result yet: run SSI - Candidate Test for this job.',
    );
  const startup = test.startup || {};
  const checks = Array.isArray(test.checks) ? test.checks : [];
  const rows = [
    {
      change: startup.source?.state === startup.candidate?.state ? 'unchanged' : 'changed',
      id: 'startup-state',
      check: 'Container state after start',
      source: text(startup.source?.state),
      patched: text(startup.candidate?.state),
      result: '',
      changed: startup.source?.state !== startup.candidate?.state,
    },
    ...checks.map((check) => ({
      change: check.status === 'fail' ? 'changed' : 'unchanged',
      id: check.id,
      check: CHECK_LABELS[check.id] || check.id,
      source: '',
      patched: '',
      result:
        check.status === 'not-applicable'
          ? 'Not applicable'
          : check.status === 'pass'
            ? 'Pass'
            : 'Fail',
      detail: text(check.detail),
      changed: check.status === 'fail',
    })),
  ];
  const failed = checks.filter((check) => check.status === 'fail');
  return dimension({
    id,
    title,
    source,
    summary: {
      passed: test.passed === true,
      platform: text(test.platform),
      testedAt: text(test.generatedAt),
    },
    columns: [
      { key: 'check', label: 'Check' },
      { key: 'source', label: 'Source' },
      { key: 'patched', label: 'Patched' },
      { key: 'result', label: 'Result' },
      { key: 'detail', label: 'Detail' },
    ],
    rows,
    attention: failed.length
      ? [
          attention(
            'high',
            'candidate-test-failed',
            `The candidate test failed: ${failed.map((check) => CHECK_LABELS[check.id] || check.id).join(', ')}.`,
          ),
        ]
      : [],
  });
}

// ── Layers and size (worker-reported image facts) ──────────────────────────────
// Layers of the second image against the first: kept ("unchanged"), "added", or "removed"
// (only in the first). sharedBaseLayers: how many bottom layers both have, in order.
function diffLayers(firstIds, secondIds) {
  const known = new Set(firstIds);
  const kept = new Set(secondIds);
  const rows = secondIds.map((digest, index) => ({
    change: known.has(digest) ? 'unchanged' : 'added',
    position: index + 1,
    digest,
    changed: !known.has(digest),
  }));
  for (const digest of firstIds) {
    if (!kept.has(digest)) rows.push({ change: 'removed', position: '', digest, changed: true });
  }
  let sharedBaseLayers = 0;
  while (
    sharedBaseLayers < Math.min(firstIds.length, secondIds.length) &&
    firstIds[sharedBaseLayers] === secondIds[sharedBaseLayers]
  ) {
    sharedBaseLayers += 1;
  }
  return {
    rows,
    added: rows.filter((row) => row.change === 'added').length,
    removed: rows.filter((row) => row.change === 'removed').length,
    sharedBaseLayers,
  };
}

function byteSize(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

// Layers are RootFS diff IDs from `docker image inspect` of both pulled digests.
function layers({ job }) {
  const id = 'layers';
  const title = 'Layers and size';
  const source = 'Candidate test (docker image inspect of both digests)';
  const facts = job.candidateTest?.imageFacts;
  const sourceIds = Array.isArray(facts?.source?.diffIds) ? facts.source.diffIds : [];
  const patchedIds = Array.isArray(facts?.candidate?.diffIds) ? facts.candidate.diffIds : [];
  if (sourceIds.length === 0 || patchedIds.length === 0) {
    return unavailable(
      id,
      title,
      source,
      facts
        ? 'The candidate test did not report the layer list of both images.'
        : 'No image facts in the candidate test result yet: run SSI - Candidate Test again for this job.',
    );
  }
  const { rows, added, removed, sharedBaseLayers } = diffLayers(sourceIds, patchedIds);
  // Copa appends its patch on top: the source layers must stay the first layers, in order.
  const sourcePreserved = sharedBaseLayers === sourceIds.length;
  const sourceBytes = byteSize(facts.source.sizeBytes);
  const patchedBytes = byteSize(facts.candidate.sizeBytes);
  const points = [];
  if (removed > 0) {
    points.push(
      attention(
        'high',
        'layer-removed',
        `${removed} source layer(s) are missing from the patched image.`,
      ),
    );
  } else if (!sourcePreserved) {
    points.push(
      attention(
        'warning',
        'layers-reordered',
        'The source layers are not the first layers of the patched image, in order.',
      ),
    );
  }
  return dimension({
    id,
    title,
    source,
    note: 'Copa adds its patch as new layer(s) on top; the source layers are expected to stay unchanged.',
    summary: {
      sourceLayers: sourceIds.length,
      patchedLayers: patchedIds.length,
      added,
      removed,
      sourcePreserved,
      sourceBytes,
      patchedBytes,
      sizeDeltaBytes:
        sourceBytes === null || patchedBytes === null ? null : patchedBytes - sourceBytes,
    },
    columns: [
      { key: 'change', label: 'Change' },
      { key: 'position', label: '#' },
      { key: 'digest', label: 'Layer (diff ID)' },
    ],
    rows,
    attention: points,
  });
}

// ── Supply chain (patched image) ───────────────────────────────────────────────
function supplyChain({ job }) {
  const evidence = job.supplyChain || {};
  const rows = [
    ['signature', 'Signature (Cosign)'],
    ['sbom', 'SBOM'],
    ['provenance', 'Provenance'],
  ].map(([key, label]) => ({
    change: evidence[key] === true ? 'added' : 'unchanged',
    item: label,
    source: 'Not applicable',
    patched: evidence[key] === true ? 'Verified' : 'Not attached',
    changed: evidence[key] === true,
  }));
  return dimension({
    id: 'supply-chain',
    title: 'Supply chain',
    source: 'Signing worker evidence (approved digest)',
    note: 'Signature, SBOM and provenance are produced for the published image; the external source has none from SSI.',
    summary: {
      signature: evidence.signature === true,
      sbom: evidence.sbom === true,
      provenance: evidence.provenance === true,
    },
    columns: [
      { key: 'item', label: 'Evidence' },
      { key: 'source', label: 'Source' },
      { key: 'patched', label: 'Patched' },
    ],
    rows,
  });
}

// Order is the reading order of the comparison.
export const DIMENSION_BUILDERS = Object.freeze([
  verifiedVulnerabilities,
  currentVulnerabilities,
  packages,
  configuration,
  runtime,
  layers,
  supplyChain,
]);

function headline(dimensions) {
  const find = (id) =>
    dimensions.find((item) => item.id === id && item.status === DIMENSION_STATUS.AVAILABLE);
  const verified = find('vulnerabilities-verified');
  const current = find('vulnerabilities-current');
  const packageDimension = find('packages');
  const config = find('configuration');
  const run = find('runtime');
  const layerDimension = find('layers');
  return {
    vulnerabilitiesFixed: verified ? verified.summary.fixed : null,
    vulnerabilitiesRemaining: verified ? verified.summary.remaining : null,
    // New findings the patch can be responsible for; those in packages it did not change are
    // counted separately (newer vulnerability data), when the candidate test says so.
    vulnerabilitiesNew: current
      ? current.summary.new - (current.summary.newInUnchangedPackages || 0)
      : null,
    vulnerabilitiesNewUnchangedPackages: current
      ? (current.summary.newInUnchangedPackages ?? null)
      : null,
    findingsBase: current ? current.summary.today.source : null,
    findingsHead: current ? current.summary.today.patched : null,
    packagesChanged: packageDimension ? packageDimension.summary.changed : null,
    packagesUnplanned: packageDimension ? packageDimension.summary.unplanned : null,
    configuration: config ? config.summary.status : null,
    runtimePassed: run ? run.summary.passed : null,
    layersAdded: layerDimension ? layerDimension.summary.added : null,
    sizeDeltaBytes: layerDimension ? layerDimension.summary.sizeDeltaBytes : null,
  };
}

// job: an RM-EXEC job (verified). sourceReport / outputReport: the current registry scans of
// the source and patched digests (null when not available).
export function buildImageComparison({
  job,
  sourceReport = null,
  outputReport = null,
  generatedAt,
} = {}) {
  if (
    !job ||
    job.mode !== 'execution' ||
    !digestOf(job.patchedImageDigest) ||
    !digestOf(job.sourceDigest)
  ) {
    throw new ImageComparisonError(
      'A comparison needs a verified remediation job with a source and a patched digest.',
      409,
    );
  }
  const context = { job, sourceReport, outputReport };
  const dimensions = DIMENSION_BUILDERS.map((build) => build(context));
  const points = dimensions
    .flatMap((item) => item.attention.map((point) => ({ ...point, dimension: item.id })))
    .sort(
      (left, right) => ATTENTION_LEVELS.indexOf(left.level) - ATTENTION_LEVELS.indexOf(right.level),
    );
  if (job.publishWithdrawal) {
    points.unshift({
      level: 'high',
      code: 'withdrawn',
      dimension: 'release',
      message: `This image was withdrawn after publish: ${text(job.publishWithdrawal.reason)}`,
    });
  }
  return {
    contractVersion: IMAGE_COMPARISON_CONTRACT,
    kind: 'remediation',
    jobId: job.id,
    tenantId: job.tenantId || null,
    generatedAt: generatedAt || new Date().toISOString(),
    base: { role: 'source', reference: text(job.image), digest: digestOf(job.sourceDigest) },
    head: {
      role: 'patched',
      reference: text(job.patchedImageTag),
      digest: digestOf(job.patchedImageDigest),
    },
    headline: headline(dimensions),
    attention: points,
    dimensions,
  };
}

// ── Free comparison of two scanned images (no remediation job) ─────────────────
// A scanned image is addressed by its immutable reference "<project>/<repository>@sha256:…",
// so a tag that moves between listing and comparing can never swap the compared image.
const SCAN_REFERENCE_PATTERN = /^([a-z0-9][a-z0-9._/-]*)@(sha256:[a-f0-9]{64})$/;

export function scanReportReference(report) {
  const image = text(report?.image || report?.id);
  const digest = digestOf(report?.digest);
  if (!image || !digest) return '';
  const at = image.indexOf('@');
  // Harbor scan images carry no registry host, so the only ":" is the tag separator.
  const repository =
    at >= 0
      ? image.slice(0, at)
      : image.includes(':')
        ? image.slice(0, image.lastIndexOf(':'))
        : image;
  return `${repository}@${digest}`;
}

// The visible scan report of `reference`, or null. Malformed references are a client error.
export function findScanReport(reports, reference, label = 'image') {
  const value = text(reference).toLowerCase();
  if (!SCAN_REFERENCE_PATTERN.test(value)) {
    throw new ImageComparisonError(`The ${label} must be <project>/<repository>@sha256:<64 hex>.`);
  }
  return (
    (Array.isArray(reports) ? reports : []).find(
      (report) => scanReportReference(report) === value,
    ) || null
  );
}

// ── Free comparison: dimensions from image inspections (SSI - Image Inspection) ─────
export const IMAGE_INSPECTION_PIPELINE = 'SSI - Image Inspection';
const INSPECTION_SOURCE = 'Image inspection of both digests (SSI - Image Inspection)';

function inspectionsMissing(id, title, baseInspection, headInspection) {
  if (baseInspection && headInspection) return null;
  const missing = [
    !baseInspection && 'the base image',
    !headInspection && 'the compared image',
  ].filter(Boolean);
  return unavailable(
    id,
    title,
    INSPECTION_SOURCE,
    `Not inspected yet: ${missing.join(' and ')}. Run ${IMAGE_INSPECTION_PIPELINE} once per image; the image references are listed above.`,
  );
}

function osFamily(inspection) {
  return text(inspection?.os).split(/\s+/)[0].toLowerCase();
}

function inspectedPackages({ baseInspection, headInspection }) {
  const id = 'packages';
  const title = 'OS packages';
  const missing = inspectionsMissing(id, title, baseInspection, headInspection);
  if (missing) return missing;
  let diff;
  try {
    diff = diffPackages(inventoryOf(baseInspection), inventoryOf(headInspection));
  } catch (error) {
    if (!(error instanceof CandidateTestError)) throw error;
    return unavailable(
      id,
      title,
      INSPECTION_SOURCE,
      `${error.message} The images are too different to list package by package.`,
    );
  }
  const rows = diff.changes
    .map((item) => ({
      change: item.change,
      name: item.name,
      arch: item.arch || '',
      source: item.from || '',
      patched: item.to || '',
      majorVersionChange: item.majorVersionChange ? 'Yes' : '',
      changed: true,
    }))
    .sort(byChangeThenSeverity);
  const points = [];
  const [baseOs, headOs] = [osFamily(baseInspection), osFamily(headInspection)];
  if (baseOs && headOs && baseOs !== headOs) {
    points.push(
      attention(
        'warning',
        'different-os',
        `The two images use different operating systems (${text(baseInspection.os)} and ${text(headInspection.os)}). Their packages and vulnerabilities cannot be compared one to one.`,
      ),
    );
  }
  return dimension({
    id,
    title,
    source: INSPECTION_SOURCE,
    summary: {
      ...diff.summary,
      differences: diff.changes.length,
      os: { base: text(baseInspection.os), compared: text(headInspection.os) },
      sameOs: Boolean(baseOs) && baseOs === headOs,
    },
    columns: [
      { key: 'change', label: 'Change' },
      { key: 'name', label: 'Package' },
      { key: 'arch', label: 'Arch' },
      { key: 'source', label: 'Base version' },
      { key: 'patched', label: 'Compared version' },
      { key: 'majorVersionChange', label: 'Major version' },
    ],
    rows,
    attention: points,
  });
}

function inspectedLayers({ baseInspection, headInspection }) {
  const id = 'layers';
  const title = 'Layers and size';
  const missing = inspectionsMissing(id, title, baseInspection, headInspection);
  if (missing) return missing;
  const baseIds = Array.isArray(baseInspection.facts?.diffIds) ? baseInspection.facts.diffIds : [];
  const headIds = Array.isArray(headInspection.facts?.diffIds) ? headInspection.facts.diffIds : [];
  const { rows, added, removed, sharedBaseLayers } = diffLayers(baseIds, headIds);
  const baseBytes = byteSize(baseInspection.facts?.sizeBytes);
  const headBytes = byteSize(headInspection.facts?.sizeBytes);
  return dimension({
    id,
    title,
    source: INSPECTION_SOURCE,
    note: 'Shared bottom layers mean a shared base image; an image built on the other one adds layers on top.',
    summary: {
      baseLayers: baseIds.length,
      comparedLayers: headIds.length,
      sharedBaseLayers,
      added,
      removed,
      baseBytes,
      comparedBytes: headBytes,
      sizeDeltaBytes: baseBytes === null || headBytes === null ? null : headBytes - baseBytes,
    },
    columns: [
      { key: 'change', label: 'Change' },
      { key: 'position', label: '#' },
      { key: 'digest', label: 'Layer (diff ID)' },
    ],
    rows,
    attention:
      baseIds.length > 0 && headIds.length > 0 && sharedBaseLayers === 0
        ? [
            attention(
              'info',
              'no-shared-layers',
              'The two images share no base layer: they are built from different base images.',
            ),
          ]
        : [],
  });
}

function inspectedConfiguration({ baseInspection, headInspection }) {
  const id = 'configuration';
  const title = 'Image configuration';
  const missing = inspectionsMissing(id, title, baseInspection, headInspection);
  if (missing) return missing;
  const rows = configFieldRows(
    baseInspection.facts?.config || {},
    headInspection.facts?.config || {},
  );
  return dimension({
    id,
    title,
    source: INSPECTION_SOURCE,
    note: 'Environment variables are compared by name only; their values are never collected.',
    summary: { changed: rows.filter((row) => row.changed).length, fields: rows.length },
    columns: [
      { key: 'change', label: 'Change' },
      { key: 'field', label: 'Field' },
      { key: 'source', label: 'Base' },
      { key: 'patched', label: 'Compared' },
    ],
    rows,
  });
}

const IMAGE_DIFF_COLUMNS = [
  { key: 'change', label: 'Change' },
  { key: 'cve', label: 'Vulnerability' },
  { key: 'severity', label: 'Severity' },
  { key: 'package', label: 'Package' },
  { key: 'source', label: 'Base version' },
  { key: 'patched', label: 'Compared version' },
];

// Two current Harbor scans compared by vulnerability. Rows use the same keys as the
// remediation comparison (source = base side, patched = compared side), so every consumer
// renders both kinds alike.
// baseInspection / headInspection: stored ssi.image-inspection/v1 records (null when an image
// was not inspected yet); registryHost: the Harbor registry name the pipeline pulls from.
export function buildImageDiff({
  baseReport,
  headReport,
  baseInspection = null,
  headInspection = null,
  registryHost = '',
  generatedAt,
} = {}) {
  const baseReference = scanReportReference(baseReport);
  const headReference = scanReportReference(headReport);
  if (!baseReference || !headReference) {
    throw new ImageComparisonError(
      'Both images need a current scan with an immutable digest.',
      409,
    );
  }
  if (digestOf(baseReport.digest) === digestOf(headReport.digest)) {
    throw new ImageComparisonError(
      'Both references are the same image content (same digest); there is nothing to compare.',
    );
  }
  const diff = diffFindings(baseReport, headReport, {
    head: 'the compared image',
    newCode: 'new-in-compared',
    fixVersionWhenFixed: false,
    warnNoCommonFindings: true,
    packageEvidence: inspectionPackageEvidence(baseInspection, headInspection),
  });
  const vulnerabilities = dimension({
    id: 'vulnerabilities-current',
    title: 'Full-image vulnerabilities today',
    source: 'Harbor scans of both digests',
    note:
      'Compared by vulnerability and package. "New" is only in the compared image, "Fixed" only in the base image, ' +
      '"Remaining" in both. A difference can also come from scans that used different vulnerability data.' +
      (diff.summary.newInUnchangedPackages === null
        ? ''
        : ' "Package version" says, from the image inspections, whether the package of a new finding differs between the images.'),
    summary: diff.summary,
    columns:
      diff.summary.newInUnchangedPackages === null
        ? IMAGE_DIFF_COLUMNS
        : [...IMAGE_DIFF_COLUMNS, { key: 'packageChange', label: 'Package version' }],
    rows: diff.rows,
    attention: diff.points,
  });
  const context = { baseInspection, headInspection };
  const dimensions = [
    vulnerabilities,
    inspectedPackages(context),
    inspectedLayers(context),
    inspectedConfiguration(context),
  ];
  const points = dimensions
    .flatMap((item) => item.attention.map((point) => ({ ...point, dimension: item.id })))
    .sort(
      (left, right) => ATTENTION_LEVELS.indexOf(left.level) - ATTENTION_LEVELS.indexOf(right.level),
    );
  // Measured different operating systems make the "no common findings" guess redundant.
  const attentionPoints = points.some((point) => point.code === 'different-os')
    ? points.filter((point) => point.code !== 'no-common-findings')
    : points;
  const packageDimension =
    dimensions[1].status === DIMENSION_STATUS.AVAILABLE ? dimensions[1] : null;
  const layerDimension = dimensions[2].status === DIMENSION_STATUS.AVAILABLE ? dimensions[2] : null;
  const side = (role, report, reference, inspection) => ({
    role,
    reference: text(report.image),
    digest: digestOf(report.digest),
    immutableReference: reference,
    registryReference: registryHost ? `${text(registryHost).toLowerCase()}/${reference}` : '',
    inspectedAt: inspection ? text(inspection.generatedAt) : null,
  });
  return {
    contractVersion: IMAGE_COMPARISON_CONTRACT,
    kind: 'images',
    jobId: null,
    tenantId: baseReport.tenantId || null,
    generatedAt: generatedAt || new Date().toISOString(),
    base: side('base', baseReport, baseReference, baseInspection),
    head: side('compared', headReport, headReference, headInspection),
    // No frozen evidence here: fixed and remaining come from today's scans of both images.
    headline: {
      ...headline(dimensions),
      vulnerabilitiesFixed: diff.summary.fixed,
      vulnerabilitiesRemaining: diff.summary.remaining,
      packageDifferences: packageDimension ? packageDimension.summary.differences : null,
      sameOs: packageDimension ? packageDimension.summary.sameOs : null,
      layersShared: layerDimension ? layerDimension.summary.sharedBaseLayers : null,
    },
    attention: attentionPoints,
    dimensions,
  };
}

// Decimal units, as registries and Docker print them.
export function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  const units = ['B', 'kB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (Math.abs(value) >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
}

// One line per dimension, for documents and notifications.
export function describeDimension(item) {
  if (item.status !== DIMENSION_STATUS.AVAILABLE) return `Not available: ${item.note}`;
  const s = item.summary;
  switch (item.id) {
    case 'vulnerabilities-verified':
      return `${s.fixed} fixed, ${s.remaining} remaining (OS packages, at verification).`;
    case 'vulnerabilities-current':
      return s.newInUnchangedPackages > 0
        ? `${s.fixed} fixed, ${s.remaining} remaining, ${s.new - s.newInUnchangedPackages} new from the patch and ${s.newInUnchangedPackages} in packages the patch did not change (full image, today).`
        : `${s.fixed} fixed, ${s.remaining} remaining, ${s.new} new in the patched image (full image, today).`;
    case 'packages':
      return `${s.changed} changed, ${s.added} added, ${s.removed} removed${s.unchanged === null ? '' : `, ${s.unchanged} unchanged`}; ${s.unplanned} not in the plan.`;
    case 'configuration':
      return s.status === 'preserved'
        ? `Preserved from the source (${s.platform}).`
        : `Restored from the source and verified (${s.restoredFields.join(', ')}; ${s.platform}).`;
    case 'runtime':
      return s.passed
        ? `Candidate test passed on ${s.platform}.`
        : `Candidate test failed on ${s.platform}.`;
    case 'layers':
      return (
        `${s.sourceLayers} → ${s.patchedLayers} layers (${s.added} added, ${s.removed} removed)` +
        (s.sizeDeltaBytes === null
          ? '.'
          : `; size ${formatBytes(s.sourceBytes)} → ${formatBytes(s.patchedBytes)}.`)
      );
    case 'supply-chain': {
      const present = [
        s.signature && 'signature',
        s.sbom && 'SBOM',
        s.provenance && 'provenance',
      ].filter(Boolean);
      return present.length
        ? `Patched image carries ${present.join(', ')}.`
        : 'No signature, SBOM or provenance attached yet.';
    }
    default:
      return `${item.rows.filter((row) => row.changed).length} change(s).`;
  }
}

// One dimension as CSV (header + rows), cells quoted: for exports and spreadsheets. A cell
// that a spreadsheet would run as a formula (=, +, -, @, tab, CR) is prefixed with ' : the
// data comes from scanners and registries, not from SSI.
export function dimensionCsv(item) {
  const quote = (value) => {
    const cell = String(value ?? '');
    const safe = /^[=+\-@\t\r]/.test(cell) ? `'${cell}` : cell;
    return `"${safe.replace(/"/g, '""')}"`;
  };
  const header = item.columns.map((column) => quote(column.label)).join(',');
  const lines = item.rows.map((row) =>
    item.columns.map((column) => quote(row[column.key])).join(','),
  );
  return [header, ...lines].join('\n');
}
