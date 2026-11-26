import { CONFIG_INTEGRITY_CONTRACT_VERSION, CONFIG_INTEGRITY_STATUSES } from './imageConfigIntegrity.js';
import { createLifecycleEvent, REMEDIATION_LIFECYCLE_STATES } from './remediationLifecycle.js';

export const REMEDIATION_EVIDENCE_CONTRACT_VERSION = 'ssi.copa-remediation-poc/v1alpha1';

const severityKeys = ['critical', 'high', 'medium', 'low', 'unknown'];
const sha256Pattern = /^sha256:[a-f0-9]{64}$/i;
const platformPattern = /^[a-z0-9]+\/[a-z0-9_]+(?:\/[a-z0-9]+)?$/;
const configFieldPattern = /^[A-Za-z][A-Za-z0-9]{0,63}$/;

export class RemediationEvidenceValidationError extends Error {
  constructor(message, statusCode = 422) {
    super(message);
    this.name = 'RemediationEvidenceValidationError';
    this.statusCode = statusCode;
  }
}

function assertEvidence(condition, message) {
  if (!condition) {
    throw new RemediationEvidenceValidationError(message);
  }
}

function asText(value) {
  return value == null ? '' : String(value).trim();
}

function normalizedDigest(value) {
  return asText(value).toLowerCase();
}

function isSha256(value) {
  return sha256Pattern.test(asText(value));
}

function asNonNegativeInteger(value, label) {
  const parsed = Number(value);
  assertEvidence(Number.isInteger(parsed) && parsed >= 0, `${label} must be a non-negative integer.`);
  return parsed;
}

function normalizeSeveritySummary(value, label) {
  assertEvidence(value && typeof value === 'object' && !Array.isArray(value), `${label} is required.`);

  return severityKeys.reduce((summary, key) => {
    summary[key] = asNonNegativeInteger(value[key] ?? 0, `${label}.${key}`);
    return summary;
  }, {});
}

function severityTotal(summary) {
  return severityKeys.reduce((total, key) => total + summary[key], 0);
}

function normalizedVersion(value) {
  return asText(value).replace(/^v/i, '');
}

function findingKey(finding) {
  return `${asText(finding?.cve).toLowerCase()}|${asText(finding?.package).toLowerCase()}`;
}

function buildFindingQueues(findings) {
  const queues = new Map();

  for (const finding of findings) {
    const key = findingKey(finding);
    const queue = queues.get(key) || [];
    queue.push(finding);
    queues.set(key, queue);
  }

  return queues;
}

function consumePlannedFinding(queues, evidenceFinding) {
  const key = findingKey(evidenceFinding);
  const queue = queues.get(key) || [];
  assertEvidence(
    queue.length > 0,
    `Verification finding ${asText(evidenceFinding?.cve) || 'UNKNOWN'} / ${asText(evidenceFinding?.package) || '-'} is not present in the canonical remediation plan.`,
  );
  return queue.shift();
}

function validateFindingList(findings, label) {
  assertEvidence(Array.isArray(findings), `${label} must be an array.`);
  for (const finding of findings) {
    assertEvidence(asText(finding?.cve), `${label} entries require a CVE or advisory identifier.`);
    assertEvidence(asText(finding?.package), `${label} entries require a package name.`);
  }
}

function validateOutputTag(tagReference) {
  const reference = asText(tagReference);
  const lastSlash = reference.lastIndexOf('/');
  const lastColon = reference.lastIndexOf(':');
  const tag = lastColon > lastSlash ? reference.slice(lastColon + 1) : '';

  assertEvidence(reference && tag, 'A tagged remediation output reference is required.');
  assertEvidence(tag.toLowerCase() !== 'latest', 'The remediation output must not use the mutable latest tag.');
  return reference;
}

// Proof from the worker's image configuration integrity gate that the patched output starts
// and runs like the source (scripts/image-config-integrity.mjs). Required: evidence from a
// worker without the gate is rejected, so an image that lost its Entrypoint/Cmd cannot be
// verified.
function validateConfigIntegrity(value, outputDigest) {
  assertEvidence(
    value && typeof value === 'object' && !Array.isArray(value),
    'Evidence is missing the image configuration integrity proof (configIntegrity). Re-run the Copa remediation pipeline with the current worker.',
  );
  assertEvidence(
    value.contractVersion === CONFIG_INTEGRITY_CONTRACT_VERSION,
    `Unsupported image configuration integrity contract: ${asText(value.contractVersion) || 'missing'}.`,
  );
  assertEvidence(
    CONFIG_INTEGRITY_STATUSES.includes(value.status),
    'Image configuration integrity status must be preserved or restored.',
  );
  assertEvidence(value.verified === true, 'Image configuration integrity must be verified on the final output image.');
  assertEvidence(value.layersPreserved === true, 'Image configuration integrity must confirm that no layer changed.');

  const platform = asText(value.platform);
  assertEvidence(platformPattern.test(platform), 'Image configuration integrity platform is invalid.');

  const digests = {};
  for (const key of [
    'sourceConfigDigest',
    'copaOutputDigest',
    'copaConfigDigest',
    'outputDigest',
    'outputConfigDigest',
    'runtimeConfigDigest',
  ]) {
    digests[key] = normalizedDigest(value[key]);
    assertEvidence(isSha256(digests[key]), `Image configuration integrity ${key} must be a sha256 digest.`);
  }
  assertEvidence(
    digests.outputDigest === outputDigest,
    'Image configuration integrity is not bound to the remediation output digest.',
  );

  assertEvidence(Array.isArray(value.restoredFields), 'Image configuration integrity restoredFields must be an array.');
  const restoredFields = value.restoredFields.map(asText);
  assertEvidence(
    restoredFields.every((field) => configFieldPattern.test(field)),
    'Image configuration integrity restoredFields contains an invalid field name.',
  );
  if (value.status === 'restored') {
    assertEvidence(restoredFields.length > 0, 'A restored image configuration must list the restored fields.');
    assertEvidence(
      digests.copaOutputDigest !== outputDigest,
      'A restored image configuration must produce a new output digest.',
    );
  } else {
    assertEvidence(restoredFields.length === 0, 'A preserved image configuration cannot list restored fields.');
    assertEvidence(
      digests.copaOutputDigest === outputDigest && digests.copaConfigDigest === digests.outputConfigDigest,
      'A preserved image configuration must keep the Copa output unchanged.',
    );
  }

  return {
    contractVersion: CONFIG_INTEGRITY_CONTRACT_VERSION,
    status: value.status,
    verified: true,
    platform,
    restoredFields,
    layersPreserved: true,
    ...digests,
  };
}

export function createVerifiedRemediationJob({
  id,
  dryRunJob,
  evidence,
  acceptedAt,
  evidenceDigest,
  fullImageComparison = null,
}) {
  assertEvidence(dryRunJob?.mode === 'dry-run', 'Verification evidence can only be attached to a Dry Run job.');
  assertEvidence(dryRunJob?.canonicalReport, 'A canonical OS-only Trivy report is required before verification evidence.');
  assertEvidence(
    Array.isArray(dryRunJob.plannedFixes) && dryRunJob.plannedFixes.length > 0,
    'The Dry Run job does not contain an eligible canonical remediation plan.',
  );
  assertEvidence(evidence && typeof evidence === 'object' && !Array.isArray(evidence), 'Remediation evidence must be a JSON object.');
  assertEvidence(
    evidence.contractVersion === REMEDIATION_EVIDENCE_CONTRACT_VERSION,
    `Unsupported remediation evidence contract: ${asText(evidence.contractVersion) || 'missing'}.`,
  );
  assertEvidence(evidence.mode === 'approved-poc-execution', 'Only approved PoC execution evidence is accepted.');

  const sourceDigest = normalizedDigest(evidence.source?.digest);
  assertEvidence(isSha256(sourceDigest), 'Evidence source digest must be a sha256 digest.');
  assertEvidence(
    sourceDigest === normalizedDigest(dryRunJob.sourceDigest),
    'Evidence source digest does not match the Dry Run immutable source digest.',
  );
  assertEvidence(
    asText(evidence.source?.immutableReference).toLowerCase().endsWith(`@${sourceDigest}`),
    'Evidence immutable source reference is not bound to the source digest.',
  );

  const canonicalDigest = normalizedDigest(evidence.canonicalInput?.contentDigest);
  assertEvidence(isSha256(canonicalDigest), 'Canonical evidence content digest must be a sha256 digest.');
  assertEvidence(
    canonicalDigest === normalizedDigest(dryRunJob.canonicalReport.contentDigest),
    'Evidence canonical content digest does not match the accepted Trivy report.',
  );
  assertEvidence(evidence.canonicalInput?.scope === 'os-packages-only', 'Evidence must use the os-packages-only scope.');

  const canonicalFindings = asNonNegativeInteger(evidence.canonicalInput?.findings, 'canonicalInput.findings');
  assertEvidence(
    canonicalFindings === Number(dryRunJob.canonicalReport.findingCount),
    'Evidence finding count does not match the accepted canonical Trivy report.',
  );
  assertEvidence(
    canonicalFindings === dryRunJob.plannedFixes.length,
    'Evidence finding count does not match the Dry Run remediation plan.',
  );

  const outputDigest = normalizedDigest(evidence.output?.digest);
  assertEvidence(isSha256(outputDigest), 'Evidence output digest must be a sha256 digest.');
  const outputTag = validateOutputTag(evidence.output?.tagReference);
  assertEvidence(
    asText(evidence.output?.immutableReference).toLowerCase().endsWith(`@${outputDigest}`),
    'Evidence immutable output reference is not bound to the output digest.',
  );
  assertEvidence(evidence.output?.approvedPublishAttempted === false, 'Approved publish must remain disabled for PoC evidence.');
  const configIntegrity = validateConfigIntegrity(evidence.configIntegrity, outputDigest);

  assertEvidence(asText(evidence.engine?.name).toLowerCase().includes('copacetic'), 'Evidence engine must be Copacetic.');
  assertEvidence(evidence.engine?.packageScope === 'os', 'Evidence engine package scope must be OS packages.');
  assertEvidence(
    normalizedVersion(evidence.engine?.version) === normalizedVersion(dryRunJob.engineVersion),
    'Evidence Copacetic version does not match the planned engine version.',
  );

  assertEvidence(evidence.verification?.scanner === 'Trivy', 'Verification evidence must be produced by Trivy.');
  assertEvidence(evidence.verification?.reScanPatchedDigest === true, 'The patched output digest must be re-scanned.');
  assertEvidence(evidence.verification?.passed === true, 'Verification must pass before evidence can be accepted.');

  const beforeFindings = asNonNegativeInteger(evidence.verification?.before?.findings, 'verification.before.findings');
  const afterFindings = asNonNegativeInteger(evidence.verification?.after?.findings, 'verification.after.findings');
  const before = normalizeSeveritySummary(evidence.verification?.before?.severity, 'verification.before.severity');
  const after = normalizeSeveritySummary(evidence.verification?.after?.severity, 'verification.after.severity');

  assertEvidence(beforeFindings === canonicalFindings, 'Verification before count must match the canonical input.');
  assertEvidence(afterFindings <= beforeFindings, 'Verification after count cannot exceed the before count.');
  assertEvidence(severityTotal(before) === beforeFindings, 'Verification before severity totals are inconsistent.');
  assertEvidence(severityTotal(after) === afterFindings, 'Verification after severity totals are inconsistent.');

  validateFindingList(evidence.verification?.fixed, 'verification.fixed');
  validateFindingList(evidence.verification?.remaining, 'verification.remaining');
  assertEvidence(
    evidence.verification.fixed.length === beforeFindings - afterFindings,
    'Verification fixed findings do not match the before/after delta.',
  );
  assertEvidence(
    evidence.verification.remaining.length === afterFindings,
    'Verification remaining findings do not match the after count.',
  );

  assertEvidence(evidence.result?.status === 'verified-poc-output', 'Evidence result status must be verified-poc-output.');
  assertEvidence(evidence.result?.patchAttempted === true, 'Evidence must confirm that Copa patching was attempted.');
  assertEvidence(evidence.result?.registryWriteAttempted === true, 'Evidence must confirm the test-tag registry write.');
  assertEvidence(evidence.result?.verificationScanAttempted === true, 'Evidence must confirm the verification re-scan.');
  assertEvidence(evidence.result?.approvedPublishAttempted === false, 'Evidence must confirm that approved publish was not attempted.');

  const findingQueues = buildFindingQueues(dryRunJob.plannedFixes);
  const fixed = evidence.verification.fixed.map((finding) => {
    const planned = consumePlannedFinding(findingQueues, finding);
    return {
      ...planned,
      to: asText(finding.fixedVersion) || planned.to,
    };
  });
  const remaining = evidence.verification.remaining.map((finding) => {
    const planned = consumePlannedFinding(findingQueues, finding);
    return {
      ...planned,
      reason: 'Still present after verification re-scan.',
    };
  });
  const unmatchedPlanCount = [...findingQueues.values()].reduce((total, queue) => total + queue.length, 0);
  assertEvidence(unmatchedPlanCount === 0, 'Verification evidence does not account for every canonical planned finding.');

  const timestamp = acceptedAt || new Date().toISOString();
  const completedAt = asText(evidence.generatedAt) || timestamp;

  return {
    id,
    parentJobId: dryRunJob.id,
    type: 'remediation',
    mode: 'execution',
    status: 'Verified',
    lifecycleState: REMEDIATION_LIFECYCLE_STATES.VERIFIED,
    image: dryRunJob.image,
    sourceDigest,
    scanReportId: dryRunJob.scanReportId,
    scanner: evidence.verification.scanner,
    os: dryRunJob.os,
    scope: dryRunJob.scope,
    engine: 'Copacetic',
    engineVersion: `v${normalizedVersion(evidence.engine.version)}`,
    execution: 'completed',
    createdAt: completedAt,
    startedAt: completedAt,
    verifiedAt: completedAt,
    verificationStatus: 'Passed',
    proposedPatchedTag: outputTag,
    patchedImageTag: outputTag,
    patchedImageDigest: outputDigest,
    before,
    after,
    plannedFixes: dryRunJob.plannedFixes,
    packageUpdates: dryRunJob.packageUpdates || [],
    fixed,
    remaining,
    excluded: [],
    canonicalReport: dryRunJob.canonicalReport,
    verificationEvidence: {
      contractVersion: evidence.contractVersion,
      evidenceDigest,
      acceptedAt: timestamp,
      sourceDigest,
      // Exact source the worker patched (bound to sourceDigest above); the candidate test
      // pipeline runs it next to the output.
      sourceReference: asText(evidence.source.immutableReference),
      canonicalContentDigest: canonicalDigest,
      outputDigest,
      engine: evidence.engine.name,
      engineVersion: evidence.engine.version,
      scanner: evidence.verification.scanner,
      resultStatus: evidence.result.status,
      approvedPublishAttempted: false,
      configIntegrity,
    },
    fullImageComparison,
    publishGate: {
      allowed: false,
      status: 'Blocked',
      reason: 'Verified PoC output is not approved for central publish.',
      approvedPublishAttempted: false,
    },
    logs: [
      `Verification evidence accepted for Dry Run ${dryRunJob.id}.`,
      `Copacetic produced immutable output ${outputDigest}.`,
      `Canonical OS package findings reduced from ${beforeFindings} to ${afterFindings}.`,
      configIntegrity.status === 'restored'
        ? `Image configuration restored from the source (${configIntegrity.restoredFields.join(', ')}) and verified on ${configIntegrity.platform}.`
        : `Image configuration preserved from the source and verified on ${configIntegrity.platform}.`,
      'Approved central publish was not attempted; publish gate remains blocked.',
    ],
    error: '',
    lifecycleEvents: [
      createLifecycleEvent({
        state: REMEDIATION_LIFECYCLE_STATES.VERIFIED,
        at: completedAt,
        actor: 'verification-evidence-intake',
        message: `Copacetic output verified by Trivy: ${beforeFindings} to ${afterFindings} OS package findings.`,
      }),
    ],
  };
}
