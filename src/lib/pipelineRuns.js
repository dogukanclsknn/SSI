// Starting worker pipelines from SSI (Azure DevOps automation, Phase 2). Pure: no I/O.
//
// SSI decides every template parameter from its own record of the remediation job; a person
// only chooses the action (and, for Copa, may give the canonical scan's Build ID). The
// pipelines keep validating their inputs and fail closed, so a wrong value never leads to a
// patched or published image.
//
// Actions and the job each one belongs to:
//   canonical-scan  planned Dry Run   SSI - Canonical Trivy Scan      (sourceRepository, sourceDigest)
//   copa-prepare    planned Dry Run   SSI - Copa Patch + Re-scan PoC  executeRemediation=false
//   copa-execute    planned Dry Run   SSI - Copa Patch + Re-scan PoC  executeRemediation=true; needs a
//                                     succeeded copa-prepare for the same canonical input
//   candidate-test  verified RM-EXEC  SSI - Candidate Test            (the pipeline's three parameters)
//
// Runs are kept on the job (`pipelineRuns`, newest first) together with the parameters sent.

import { buildExecutionReadiness, REMEDIATION_LIFECYCLE_STATES } from './remediationLifecycle.js';
import { candidateTestParameters } from './candidateTestView.js';

export const PIPELINE_ACTIONS = Object.freeze({
  'canonical-scan': { role: 'canonicalScan', label: 'Canonical Trivy scan' },
  'copa-prepare': { role: 'copaRemediation', label: 'Copa input check' },
  'copa-execute': { role: 'copaRemediation', label: 'Copa patch + re-scan' },
  'candidate-test': { role: 'candidateTest', label: 'Candidate test' },
});

export const MAX_STORED_RUNS = 50;

const fullDigestPattern = /^sha256:[a-f0-9]{64}$/;
const repositoryPathPattern = /^[a-z0-9][a-z0-9._/-]*$/;
const copaOutputTagPattern = /^copa-poc-[a-z0-9][a-z0-9.-]{0,110}$/;
const buildIdPattern = /^[1-9][0-9]{0,9}$/;

export class PipelineRunError extends Error {
  constructor(message, statusCode = 409) {
    super(message);
    this.name = 'PipelineRunError';
    this.statusCode = statusCode;
  }
}

const text = (value) => (value == null ? '' : String(value).trim());

export function isRunActive(run) {
  return text(run?.state) !== 'completed';
}

export function isRunSucceeded(run) {
  return text(run?.state) === 'completed' && text(run?.result) === 'succeeded';
}

export function runsOf(job) {
  return Array.isArray(job?.pipelineRuns) ? job.pipelineRuns : [];
}

// Where the newest Copa patch SSI started for this Dry Run writes its candidate
// ("<repository>:copa-poc-<date>-<source tag>-<job>-r<N>"), or '' when no patch was started.
export function copaOutputReferenceOf(job) {
  const run = runsOf(job).find((item) => item.action === 'copa-execute' && text(item.parameters?.outputTag));
  if (!run) return '';
  const repository = text(run.parameters.outputRepository);
  return repository ? `${repository}:${text(run.parameters.outputTag)}` : text(run.parameters.outputTag);
}

const trimSlashes = (value) => text(value).replace(/^\/+|\/+$/g, '');

// Where the Copa worker writes the patched candidate. A patched image is untested and not yet
// approved, so it always lands in quarantine: an image patched from the approved catalog
// (<publishPrefix>/<path>) gets its candidate at the same path under the quarantine prefix
// (<quarantinePrefix>/<path>). It reaches the approved catalog again only through the candidate
// test, consumer acceptance and an approved publish, like any other candidate.
export function copaOutputRepository(sourceRepository, { publishPrefix = 'approved', quarantinePrefix = 'onboarded' } = {}) {
  const repository = trimSlashes(sourceRepository);
  const approved = trimSlashes(publishPrefix);
  if (!approved || !repository.startsWith(`${approved}/`)) return repository;
  const quarantine = trimSlashes(quarantinePrefix);
  if (!quarantine || quarantine === approved) {
    throw new PipelineRunError(
      'No quarantine folder is configured for patched images (ONBOARD_TARGET_REPOSITORY_PREFIX).',
    );
  }
  return `${quarantine}/${repository.slice(approved.length + 1)}`;
}

// "<host>/<project>/<repository path>:<tag>" (host optional) → the repository path inside the
// Harbor project the worker pipelines use. Images from another project are refused.
export function harborRepositoryPath(image, harborProject) {
  const project = text(harborProject);
  let reference = text(image).split('@')[0];
  const lastSlash = reference.lastIndexOf('/');
  const lastColon = reference.lastIndexOf(':');
  if (lastColon > lastSlash) reference = reference.slice(0, lastColon);
  const segments = reference.split('/').filter(Boolean);
  if (segments.length > 1 && (segments[0].includes('.') || segments[0].includes(':')))
    segments.shift();
  if (!project || segments[0] !== project || segments.length < 2) {
    throw new PipelineRunError(
      `The image is not in the Harbor project the worker pipelines use${project ? ` (${project})` : ''}.`,
    );
  }
  const path = segments.slice(1).join('/');
  if (!repositoryPathPattern.test(path)) {
    throw new PipelineRunError('The image repository is not a lower-case Harbor repository path.');
  }
  return path;
}

function imageTag(image) {
  const reference = text(image).split('@')[0];
  const lastSlash = reference.lastIndexOf('/');
  const lastColon = reference.lastIndexOf(':');
  return lastColon > lastSlash ? reference.slice(lastColon + 1) : '';
}

function slug(value, maxLength) {
  return text(value)
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, '-')
    .replace(/^[.-]+|[.-]+$/g, '')
    .slice(0, maxLength)
    .replace(/[.-]+$/g, '');
}

function requireSourceDigest(job) {
  const digest = text(job?.sourceDigest).toLowerCase();
  if (!fullDigestPattern.test(digest)) {
    throw new PipelineRunError('The job has no complete sha256 source digest.');
  }
  return digest;
}

function dryRunState(job) {
  if (job?.mode !== 'dry-run') return '';
  return job.lifecycleState || (job.status === 'Blocked' ? 'blocked' : 'planned');
}

// The canonical scan is what unblocks a Dry Run planned from a Harbor scan (Harbor does not
// prove the os-pkgs class), so it runs on a planned or a blocked Dry Run.
function requireDryRunForScan(job) {
  const state = dryRunState(job);
  if (
    state !== REMEDIATION_LIFECYCLE_STATES.PLANNED &&
    state !== REMEDIATION_LIFECYCLE_STATES.BLOCKED
  ) {
    throw new PipelineRunError('This action needs a Dry Run job.');
  }
}

function requirePlannedDryRun(job) {
  if (dryRunState(job) !== REMEDIATION_LIFECYCLE_STATES.PLANNED) {
    throw new PipelineRunError('This action needs a planned Dry Run job.');
  }
}

function requireCanonicalPlan(job) {
  const met = new Map(buildExecutionReadiness(job).requirements.map((item) => [item.id, item.met]));
  if (!met.get('canonical-trivy-report')) {
    throw new PipelineRunError('Upload the canonical Trivy JSON for this source digest first.');
  }
  if (!met.get('eligible-os-package-plan')) {
    throw new PipelineRunError(
      'The canonical report has no OS package finding with a fixed version.',
    );
  }
  const contentDigest = text(job.canonicalReport?.contentDigest).toLowerCase();
  if (!fullDigestPattern.test(contentDigest)) {
    throw new PipelineRunError('The canonical report has no complete sha256 content digest.');
  }
  return contentDigest;
}

// The canonical scan run the Copa worker downloads its input from: a Build ID the person gave,
// or the newest succeeded canonical scan SSI started for this source digest.
function canonicalBuildIdFor(job, sourceDigest, requested) {
  const given = text(requested);
  if (given) {
    if (!buildIdPattern.test(given)) {
      throw new PipelineRunError('The canonical scan Build ID must be a positive number.', 422);
    }
    return given;
  }
  const scan = runsOf(job).find(
    (run) =>
      run.action === 'canonical-scan' &&
      isRunSucceeded(run) &&
      run.parameters?.sourceDigest === sourceDigest,
  );
  if (!scan) {
    throw new PipelineRunError(
      'No succeeded canonical scan for this source digest. Run it from SSI or enter its Build ID.',
    );
  }
  return String(scan.runId);
}

function copaOutputTag(job, now) {
  const day = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
  const attempt = runsOf(job).filter((run) => run.action === 'copa-execute').length + 1;
  const parts = [
    `copa-poc-${day}`,
    slug(imageTag(job.image), 40),
    slug(job.id, 40),
    `r${attempt}`,
  ].filter(Boolean);
  const tag = parts.join('-');
  if (!copaOutputTagPattern.test(tag)) {
    throw new PipelineRunError('A valid copa-poc output tag could not be derived for this job.');
  }
  return tag;
}

// Decides the pipeline and its template parameters for `action` on `job`, or throws a
// PipelineRunError that says what is missing. `pipelines` are the configured definition IDs;
// `verifiedExecutionId` names a verified RM-EXEC job already made from this Dry Run.
export function planPipelineRun(
  job,
  action,
  {
    harborProject,
    pipelines = {},
    canonicalBuildId,
    verifiedExecutionId = '',
    publishPrefix,
    quarantinePrefix,
    now = Date.now(),
  } = {},
) {
  const definition = PIPELINE_ACTIONS[action];
  if (!definition) throw new PipelineRunError('Unknown pipeline action.', 422);
  if (!job?.id) throw new PipelineRunError('Remediation job not found.', 404);

  if (action === 'candidate-test') {
    if (job.mode !== 'execution' || job.lifecycleState !== REMEDIATION_LIFECYCLE_STATES.VERIFIED) {
      throw new PipelineRunError('The candidate test needs a verified RM-EXEC job.');
    }
    if (job.publishWithdrawal)
      throw new PipelineRunError('This image was withdrawn; it cannot be tested again.');
    const parameters = candidateTestParameters(job);
    if (!parameters?.sourceReference || !parameters.candidateReference) {
      throw new PipelineRunError('The job has no immutable source and candidate references.');
    }
    return {
      action,
      role: definition.role,
      templateParameters: { ...parameters, deliverToSsi: true },
    };
  }

  requireDryRunForScan(job);
  const sourceDigest = requireSourceDigest(job);
  const sourceRepository = harborRepositoryPath(job.image, harborProject);

  if (action === 'canonical-scan') {
    return {
      action,
      role: definition.role,
      // The worker delivers the report back to this Dry Run (scripts/canonical-report.mjs).
      templateParameters: {
        sourceRepository,
        sourceDigest,
        remediationJobId: job.id,
        deliverToSsi: true,
      },
    };
  }

  // One plan, one verified result: patching it again would leave two candidates for the same
  // plan. A new Dry Run is the way to patch the image again.
  if (verifiedExecutionId) {
    throw new PipelineRunError(
      `This plan already has a verified result (${verifiedExecutionId}). Create a new Dry Run to patch the image again.`,
    );
  }
  if (job.mode === 'dry-run' && !job.canonicalReport) {
    throw new PipelineRunError('Upload the canonical Trivy JSON for this source digest first.');
  }
  requirePlannedDryRun(job);
  const contentDigest = requireCanonicalPlan(job);
  if (!pipelines.canonicalScan) {
    throw new PipelineRunError(
      'The canonical scan pipeline ID is not configured (SSI_ADO_PIPELINE_CANONICAL_SCAN).',
    );
  }
  const execute = action === 'copa-execute';
  let buildId;
  if (execute) {
    // The patch uses exactly the canonical input the succeeded input check accepted.
    const prepared = runsOf(job).find(
      (run) =>
        run.action === 'copa-prepare' &&
        isRunSucceeded(run) &&
        run.parameters?.sourceDigest === sourceDigest &&
        run.parameters?.canonicalReceiptContentDigest === contentDigest,
    );
    if (!prepared) {
      throw new PipelineRunError(
        'Run the Copa input check for this canonical input first; the patch starts only after it succeeds.',
      );
    }
    buildId = prepared.parameters.canonicalBuildId;
  } else {
    buildId = canonicalBuildIdFor(job, sourceDigest, canonicalBuildId);
  }
  return {
    action,
    role: definition.role,
    templateParameters: {
      sourceRepository,
      sourceDigest,
      remediationJobId: job.id,
      canonicalPipelineDefinitionId: String(pipelines.canonicalScan),
      canonicalBuildId: buildId,
      canonicalReceiptContentDigest: contentDigest,
      outputRepository: copaOutputRepository(sourceRepository, { publishPrefix, quarantinePrefix }),
      outputTag: copaOutputTag(job, now),
      executeRemediation: execute,
    },
  };
}

// The verified, not withdrawn RM-EXEC job made from this Dry Run, if any (its ID).
export function verifiedExecutionOf(dryRunJob, jobs = []) {
  if (dryRunJob?.mode !== 'dry-run') return '';
  const child = jobs.find(
    (item) =>
      item?.mode === 'execution' &&
      item.parentJobId === dryRunJob.id &&
      item.lifecycleState === REMEDIATION_LIFECYCLE_STATES.VERIFIED &&
      !item.publishWithdrawal,
  );
  return child?.id || '';
}

// The record kept on the job for a started run (parameters hold no secret).
export function createRunRecord({ plan, pipelineId, run, actor, at }) {
  return {
    action: plan.action,
    role: plan.role,
    pipelineId,
    runId: run.id,
    runName: run.name,
    state: run.state,
    result: run.result,
    webUrl: run.webUrl,
    parameters: plan.templateParameters,
    requestedBy: actor,
    requestedAt: at,
    updatedAt: at,
    finishedAt: run.finishedDate || null,
  };
}

export function withRun(job, record) {
  return { ...job, pipelineRuns: [record, ...runsOf(job)].slice(0, MAX_STORED_RUNS) };
}

// Applies a fresh state from Azure DevOps to a stored run.
export function refreshedRun(record, live, at) {
  if (!live || (live.state === record.state && live.result === record.result)) return record;
  return {
    ...record,
    state: live.state,
    result: live.result,
    webUrl: live.webUrl || record.webUrl,
    finishedAt: live.finishedDate || record.finishedAt,
    updatedAt: at,
  };
}

// What the Remediation screen shows: each action that belongs to this kind of job, whether
// it can start now (and why not), and the runs.
export function pipelineRunsView(
  job,
  { enabled, harborProject, pipelines = {}, verifiedExecutionId = '' } = {},
) {
  const kinds =
    job?.mode === 'execution'
      ? ['candidate-test']
      : ['canonical-scan', 'copa-prepare', 'copa-execute'];
  const runs = runsOf(job);
  const actions = kinds.map((action) => {
    const { role, label } = PIPELINE_ACTIONS[action];
    let reason = '';
    if (!enabled) reason = 'Azure DevOps automation is not configured.';
    else if (!pipelines[role]) reason = 'This pipeline is not configured for automatic runs.';
    else if (runs.some((run) => run.role === role && isRunActive(run)))
      reason = 'A run of this pipeline is in progress.';
    else {
      try {
        // A missing Build ID is not a blocker here: the person can still enter one.
        planPipelineRun(job, action, {
          harborProject,
          pipelines,
          verifiedExecutionId,
          canonicalBuildId: copaNeedsBuildId(job, action),
        });
      } catch (error) {
        if (!(error instanceof PipelineRunError)) throw error;
        reason = error.message;
      }
    }
    return {
      action,
      role,
      label,
      available: reason === '',
      reason,
      needsBuildId: copaNeedsBuildId(job, action) === '1',
    };
  });
  return { enabled: Boolean(enabled), actions, runs };
}

// Placeholder Build ID for the availability check when SSI has no succeeded canonical scan.
function copaNeedsBuildId(job, action) {
  if (action !== 'copa-prepare') return undefined;
  const digest = text(job?.sourceDigest).toLowerCase();
  const recorded = runsOf(job).some(
    (run) =>
      run.action === 'canonical-scan' &&
      isRunSucceeded(run) &&
      run.parameters?.sourceDigest === digest,
  );
  return recorded ? undefined : '1';
}
