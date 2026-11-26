import { createHash } from 'node:crypto';
import { normalizeTrivyScan } from './trivy.js';

const sha256Pattern = /sha256:[a-f0-9]{64}/gi;

export class CanonicalTrivyValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CanonicalTrivyValidationError';
  }
}

function asText(value) {
  return value == null ? '' : String(value).trim();
}

function reportDigests(report = {}) {
  const candidates = [
    report.ArtifactName,
    report.ArtifactID,
    report.Metadata?.ImageID,
    ...(Array.isArray(report.Metadata?.RepoDigests) ? report.Metadata.RepoDigests : []),
  ]
    .map(asText)
    .filter(Boolean);

  return [...new Set(candidates.flatMap((candidate) => candidate.match(sha256Pattern) || []))];
}

function contentDigest(report, rawContent) {
  const content = typeof rawContent === 'string' ? rawContent : JSON.stringify(report);
  return `sha256:${createHash('sha256').update(content, 'utf8').digest('hex')}`;
}

function assert(condition, message) {
  if (!condition) {
    throw new CanonicalTrivyValidationError(message);
  }
}

export function validateCanonicalTrivyReport(report, { expectedSourceDigest, rawContent } = {}) {
  assert(report && typeof report === 'object' && !Array.isArray(report), 'Canonical Trivy report must be a JSON object.');
  assert(report.SchemaVersion === 2, 'Canonical Trivy report must use SchemaVersion 2.');
  assert(report.ArtifactType === 'container_image', 'Canonical Trivy report must describe a container_image artifact.');
  assert(Array.isArray(report.Results) && report.Results.length > 0, 'Canonical Trivy report must contain at least one result.');

  const expectedDigest = asText(expectedSourceDigest).toLowerCase();
  assert(/^sha256:[a-f0-9]{64}$/.test(expectedDigest), 'Remediation job is missing a valid immutable source digest.');

  const sourceDigests = reportDigests(report).map((digest) => digest.toLowerCase());
  assert(
    sourceDigests.includes(expectedDigest),
    'Canonical Trivy report source digest does not match the remediation job source digest.',
  );

  const resultClasses = [...new Set(report.Results.map((result) => asText(result?.Class)))];
  assert(
    resultClasses.length > 0 && resultClasses.every((resultClass) => resultClass === 'os-pkgs'),
    'Canonical Trivy report must contain only os-pkgs results for phase-one remediation.',
  );

  const normalizedReport = normalizeTrivyScan(report);
  assert(
    normalizedReport.findings.every((finding) => finding.class === 'os-pkgs'),
    'Canonical Trivy report produced a finding outside the os-pkgs scope.',
  );

  const digest = contentDigest(report, rawContent);

  return {
    normalizedReport,
    receipt: {
      reportId: asText(report.ReportID) || `CTR-${digest.slice('sha256:'.length, 'sha256:'.length + 12)}`,
      contentDigest: digest,
      sourceDigest: expectedDigest,
      artifactName: asText(report.ArtifactName),
      generatedAt: asText(report.CreatedAt),
      trivyVersion: asText(report.Trivy?.Version),
      schemaVersion: report.SchemaVersion,
      scope: 'os-packages-only',
      resultClasses,
      findingCount: normalizedReport.findings.length,
      os: normalizedReport.os,
    },
  };
}
