export const WORKER_CONTRACT_VERSION = 'ssi.remediation-worker/v1alpha1';

export const REMEDIATION_LIFECYCLE_STATES = Object.freeze({
  PLANNED: 'planned',
  QUEUED: 'queued',
  RUNNING: 'running',
  PATCHED: 'patched',
  RESCANNING: 'rescanning',
  VERIFIED: 'verified',
  FAILED: 'failed',
  BLOCKED: 'blocked',
  // Legacy: report-only jobs stored by the earlier Windows flow. Windows is not supported
  // now, but the state stays so those stored records still read correctly.
  REPORT_ONLY: 'report-only',
});

const lifecycleValues = new Set(Object.values(REMEDIATION_LIFECYCLE_STATES));

const allowedTransitions = {
  planned: new Set(['queued', 'blocked']),
  queued: new Set(['running', 'failed', 'blocked']),
  running: new Set(['patched', 'failed']),
  patched: new Set(['rescanning', 'failed']),
  rescanning: new Set(['verified', 'failed']),
  verified: new Set(),
  failed: new Set(),
  blocked: new Set(),
  'report-only': new Set(),
};

const stateLabels = {
  planned: 'Planned',
  queued: 'Queued',
  running: 'Running',
  patched: 'Patched',
  rescanning: 'Re-scanning',
  verified: 'Verified',
  failed: 'Failed',
  blocked: 'Blocked',
  'report-only': 'Report-only',
};

const executionPhases = {
  planned: 'not-run',
  queued: 'queued',
  running: 'running',
  patched: 'running',
  rescanning: 'running',
  verified: 'completed',
  failed: 'failed',
  blocked: 'not-run',
  'report-only': 'not-run',
};

function asText(value, fallback = '') {
  return value == null ? fallback : String(value);
}

function currentLifecycleState(job = {}) {
  if (lifecycleValues.has(job.lifecycleState)) {
    return job.lifecycleState;
  }

  return job.status === 'Blocked' ? REMEDIATION_LIFECYCLE_STATES.BLOCKED : REMEDIATION_LIFECYCLE_STATES.PLANNED;
}

function hasImmutableDigest(value) {
  return /^sha256:[a-f0-9]{6,}$/i.test(asText(value).trim());
}

function hasCanonicalTrivyReport(job = {}) {
  const report = job.canonicalReport;
  const sourceDigest = asText(job.sourceDigest).toLowerCase();

  return Boolean(
    report &&
      asText(report.reportId).trim() &&
      report.schemaVersion === 2 &&
      report.scope === 'os-packages-only' &&
      hasImmutableDigest(report.contentDigest) &&
      hasImmutableDigest(report.sourceDigest) &&
      asText(report.artifactName).trim() &&
      asText(report.sourceDigest).toLowerCase() === sourceDigest,
  );
}

function sourceRepository(reference) {
  const withoutDigest = asText(reference).trim().split('@')[0];
  const lastSlash = withoutDigest.lastIndexOf('/');
  const lastColon = withoutDigest.lastIndexOf(':');

  return lastColon > lastSlash ? withoutDigest.slice(0, lastColon) : withoutDigest;
}

function immutableReference(job) {
  const source = sourceRepository(job.canonicalReport?.artifactName || job.image);
  const digest = asText(job.sourceDigest).trim();

  return source && digest ? `${source}@${digest}` : '';
}

function hasCanonicalRemediationPlan(job = {}) {
  return (
    hasImmutableDigest(job.sourceDigest) &&
    hasCanonicalTrivyReport(job) &&
    Array.isArray(job.plannedFixes) &&
    job.plannedFixes.length > 0
  );
}

function hasWorkerHandoffPrerequisites(job = {}) {
  return (
    job.mode === 'dry-run' &&
    currentLifecycleState(job) === REMEDIATION_LIFECYCLE_STATES.PLANNED &&
    hasCanonicalRemediationPlan(job)
  );
}

function lifecycleMessage(nextState) {
  return {
    planned: 'Remediation plan created; no worker action was requested.',
    queued: 'Execution job queued for an isolated remediation worker.',
    running: 'Isolated remediation worker started the controlled execution.',
    patched: 'Patch output created; verification re-scan is required before publish.',
    rescanning: 'Verification scan started against the patched image.',
    verified: 'Verification scan completed and the remediation result was verified.',
    failed: 'Remediation execution failed; registry publish remains blocked.',
    blocked: 'Remediation cannot continue until blocking requirements are resolved.',
    'report-only': 'Image is out of the in-place remediation scope; scan and report only.',
  }[nextState];
}

export function lifecycleStatusLabel(state) {
  return stateLabels[state] || 'Unknown';
}

export function isAllowedLifecycleTransition(fromState, toState) {
  return Boolean(allowedTransitions[fromState]?.has(toState));
}

export function createLifecycleEvent({ state, at, actor = 'system', message }) {
  if (!lifecycleValues.has(state)) {
    throw new Error(`Unknown remediation lifecycle state: ${state}`);
  }

  return {
    state,
    at: at || new Date().toISOString(),
    actor,
    message: message || lifecycleMessage(state),
  };
}

// What a Dry Run still needs before the isolated Copa worker can patch it. The checklist holds
// only conditions that can actually be met: the job's own prerequisites, and whether SSI can
// start the worker itself (`workerConfigured`: the Azure DevOps Copa pipeline is configured,
// src/lib/azureDevOps.js). The verification re-scan and the registry boundaries are not listed:
// the worker always enforces them, and only its verified evidence moves the job forward.
export function buildExecutionReadiness(job = {}, { workerConfigured = false } = {}) {
  const lifecycleState = currentLifecycleState(job);
  const plannedFixes = Array.isArray(job.plannedFixes) ? job.plannedFixes : [];
  const workerHandoffReady = hasWorkerHandoffPrerequisites(job);
  const requirements = [
    {
      id: 'eligible-os-package-plan',
      label: 'Eligible OS package plan',
      met: plannedFixes.length > 0,
      detail:
        plannedFixes.length > 0
          ? `${plannedFixes.length} OS package finding(s) are eligible for remediation.`
          : 'At least one os-pkgs finding with a fixed version is required.',
    },
    {
      id: 'immutable-source-digest',
      label: 'Immutable source digest',
      met: hasImmutableDigest(job.sourceDigest),
      detail: hasImmutableDigest(job.sourceDigest)
        ? 'The worker can pin the input image by digest.'
        : 'A sha256 source digest must be captured before execution is queued.',
    },
    {
      id: 'canonical-trivy-report',
      label: 'Canonical raw Trivy JSON',
      met: hasCanonicalTrivyReport(job),
      detail: hasCanonicalTrivyReport(job)
        ? `${job.canonicalReport.findingCount ?? 0} OS package finding(s) were accepted for the immutable source digest.`
          : 'The isolated worker must generate an OS-only Trivy JSON report for Copa input.',
    },
    {
      id: 'credential-free-worker-handoff',
      label: 'Credential-free worker handoff manifest',
      met: workerHandoffReady,
      detail: workerHandoffReady
        ? 'A read-only, digest-pinned manifest can be exported for the isolated worker; it does not dispatch work.'
        : 'A planned Dry Run with a matching canonical OS-only report and eligible package fixes is required.',
    },
    {
      id: 'isolated-worker',
      label: 'Isolated remediation worker',
      met: Boolean(workerConfigured),
      detail: workerConfigured
        ? 'SSI starts the isolated Copa worker in Azure DevOps from this job; it never patches in the web application.'
        : 'Azure DevOps automation is off: run the Copa worker pipeline in Azure DevOps with this job’s handoff manifest.',
    },
  ];

  const blockers = requirements.filter((requirement) => !requirement.met).map((requirement) => requirement.label);

  return {
    contractVersion: WORKER_CONTRACT_VERSION,
    jobId: job.id || '',
    lifecycleState,
    lifecycleLabel: lifecycleStatusLabel(lifecycleState),
    ready: blockers.length === 0,
    // Every requirement includes a configured worker, so a ready job is one SSI can dispatch.
    dispatchAllowed: blockers.length === 0,
    workerConfigured: Boolean(workerConfigured),
    message:
      'The web application does not patch images. The isolated worker pipeline does, and only its verified evidence moves the job forward.',
    requirements,
    blockers,
  };
}

export function createExecutionJobFromDryRun({ id, dryRunJob, createdAt }) {
  if (!dryRunJob || dryRunJob.mode !== 'dry-run') {
    throw new Error('An execution job can only be created from a Dry Run remediation plan.');
  }

  if (currentLifecycleState(dryRunJob) !== REMEDIATION_LIFECYCLE_STATES.PLANNED) {
    throw new Error('Only a planned Dry Run remediation job can create an execution job.');
  }
  if (!hasCanonicalRemediationPlan(dryRunJob)) {
    throw new Error(
      'An execution job requires a validated canonical OS-only Trivy report and at least one eligible package fix.',
    );
  }

  const timestamp = createdAt || new Date().toISOString();
  const executionJob = {
    ...dryRunJob,
    id,
    mode: 'execution',
    parentJobId: dryRunJob.id,
    status: lifecycleStatusLabel(REMEDIATION_LIFECYCLE_STATES.QUEUED),
    lifecycleState: REMEDIATION_LIFECYCLE_STATES.QUEUED,
    execution: executionPhases.queued,
    createdAt: timestamp,
    startedAt: '',
    verifiedAt: '',
    verificationStatus: 'Pending',
    fixed: [],
    patchedImageTag: '',
    patchedImageDigest: '',
    after: null,
    logs: [
      `Execution job created from Dry Run ${dryRunJob.id}.`,
      'No worker dispatch, image pull, Copa patch, registry push, or re-scan has occurred.',
    ],
    lifecycleEvents: [
      createLifecycleEvent({
        state: REMEDIATION_LIFECYCLE_STATES.QUEUED,
        at: timestamp,
        actor: 'scheduler',
      }),
    ],
  };

  return {
    ...executionJob,
    executionReadiness: buildExecutionReadiness(executionJob),
  };
}

export function transitionRemediationJob(job, nextState, options = {}) {
  const currentState = currentLifecycleState(job);
  if (!lifecycleValues.has(nextState)) {
    throw new Error(`Unknown remediation lifecycle state: ${nextState}`);
  }
  if (!isAllowedLifecycleTransition(currentState, nextState)) {
    throw new Error(`Invalid remediation lifecycle transition: ${currentState} -> ${nextState}`);
  }

  const timestamp = options.at || new Date().toISOString();
  const event = createLifecycleEvent({
    state: nextState,
    at: timestamp,
    actor: options.actor || 'worker',
    message: options.message,
  });
  const updatedJob = {
    ...job,
    status: lifecycleStatusLabel(nextState),
    lifecycleState: nextState,
    execution: executionPhases[nextState],
    startedAt:
      nextState === REMEDIATION_LIFECYCLE_STATES.RUNNING ? job.startedAt || timestamp : job.startedAt || '',
    verifiedAt:
      nextState === REMEDIATION_LIFECYCLE_STATES.VERIFIED ? timestamp : job.verifiedAt || '',
    verificationStatus:
      nextState === REMEDIATION_LIFECYCLE_STATES.VERIFIED
        ? 'Passed'
        : nextState === REMEDIATION_LIFECYCLE_STATES.FAILED
          ? 'Failed'
          : job.verificationStatus || 'Pending',
    lifecycleEvents: [...(job.lifecycleEvents || []), event],
    logs: [...(job.logs || []), event.message],
  };

  return {
    ...updatedJob,
    executionReadiness: buildExecutionReadiness(updatedJob),
  };
}

export function buildWorkerDispatchPayload(executionJob = {}) {
  if (executionJob.mode !== 'execution') {
    throw new Error('Worker dispatch requires an execution job, not a Dry Run plan.');
  }
  if (currentLifecycleState(executionJob) !== REMEDIATION_LIFECYCLE_STATES.QUEUED) {
    throw new Error('Worker dispatch requires a queued execution job.');
  }
  if (!hasImmutableDigest(executionJob.sourceDigest)) {
    throw new Error('Worker dispatch requires an immutable sha256 source digest.');
  }
  if (!hasCanonicalRemediationPlan(executionJob)) {
    throw new Error(
      'Worker dispatch requires a validated canonical OS-only Trivy report and at least one eligible package fix.',
    );
  }

  return {
    contractVersion: WORKER_CONTRACT_VERSION,
    job: {
      id: executionJob.id,
      parentJobId: executionJob.parentJobId || '',
      createdAt: executionJob.createdAt || '',
    },
    source: {
      image: executionJob.image,
      digest: executionJob.sourceDigest,
      immutableReference: immutableReference(executionJob),
    },
    scanner: {
      tool: 'trivy',
      report: 'canonical-trivy.json',
      scope: 'os-packages-only',
      command: 'trivy image --pkg-types os --ignore-unfixed --format json',
    },
    canonicalInput: {
      reportId: executionJob.canonicalReport.reportId,
      contentDigest: executionJob.canonicalReport.contentDigest,
      sourceDigest: executionJob.canonicalReport.sourceDigest,
      schemaVersion: executionJob.canonicalReport.schemaVersion,
      scope: executionJob.canonicalReport.scope,
      rawReportEmbedded: false,
    },
    remediation: {
      engine: 'copacetic',
      command: 'copa patch --report canonical-trivy.json',
      outputReference: executionJob.proposedPatchedTag || '',
    },
    verification: {
      reScanPatchedDigest: true,
      blockPublishUntilVerified: true,
    },
    credentialDelivery: {
      mode: 'worker-runtime-secret',
      includedInPayload: false,
    },
  };
}

export function buildWorkerHandoffManifest(job = {}) {
  if (!hasWorkerHandoffPrerequisites(job)) {
    throw new Error(
      'A planned Dry Run with a validated canonical OS-only Trivy report and eligible package fixes is required.',
    );
  }

  const source = immutableReference(job);
  const canonical = job.canonicalReport;
  const plannedFixes = job.plannedFixes || [];
  const packageUpdates = job.packageUpdates || [];
  const preparedAt = canonical.acceptedAt || job.updatedAt || job.createdAt || '';

  return {
    contractVersion: WORKER_CONTRACT_VERSION,
    kind: 'RemediationHandoffManifest',
    metadata: {
      jobId: job.id,
      preparedAt,
      idempotencyKey: `remediation-handoff:${job.id}:${job.sourceDigest}:${canonical.contentDigest}`,
    },
    spec: {
      executionMode: 'prepare-only',
      source: {
        repository: sourceRepository(canonical.artifactName || job.image),
        digest: job.sourceDigest,
        immutableReference: source,
      },
      canonicalInput: {
        reportId: canonical.reportId,
        contentDigest: canonical.contentDigest,
        sourceDigest: canonical.sourceDigest,
        artifactName: canonical.artifactName,
        schemaVersion: canonical.schemaVersion,
        scope: canonical.scope,
        findingCount: canonical.findingCount,
        trivyVersion: canonical.trivyVersion || '',
        rawReportEmbedded: false,
        delivery: {
          mode: 'trusted-job-artifact',
          rawReportEmbedded: false,
          workerFetchRequired: true,
          contentDigestRequired: true,
        },
      },
      remediation: {
        engine: {
          name: job.engine || 'Copacetic',
          version: job.engineVersion || '',
        },
        scope: job.scope || 'os-packages-only',
        plannedFindingCount: plannedFixes.length,
        packageUpdateCount: packageUpdates.length,
        findings: plannedFixes,
        packageUpdates,
      },
      output: {
        proposedReference: job.proposedPatchedTag || '',
        sourceMutation: 'forbidden',
        registryWrite: 'worker-runtime-only',
        publishAllowed: false,
      },
      verification: {
        reScanPatchedDigest: true,
        blockPublishUntilVerified: true,
      },
    },
    safeguards: {
      webContainerDispatch: false,
      dockerSocketInWebContainer: false,
      registryCredentialsEmbedded: false,
    },
  };
}
