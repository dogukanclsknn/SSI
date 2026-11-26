// Worker pipelines started for records other than remediation jobs (Azure DevOps automation,
// Phase 4a). Pure: no I/O. The remediation job actions live in src/lib/pipelineRuns.js; this
// module reuses its run records and adds:
//
//   onboard-check       Requested/Importing onboarding request  SSI - Onboard Import   executeImport=false
//   onboard-import      same, after a succeeded onboard-check    SSI - Onboard Import   executeImport=true
//   publish-check       Approved publish request                 SSI - Controlled Publish executePublish=false
//   publish-execute     same, after a succeeded publish-check    SSI - Controlled Publish executePublish=true
//   supply-chain-sign   Published publish request                SSI - Supply-Chain Sign postToSsi=true
//   image-inspection    a scanned image (project/repo@digest)    SSI - Image Inspection  deliverToSsi=true
//   os-template-build   Requested Windows template build (OST-…) SSI - OS Template (Windows) deliverToSsi=true
//   os-template-build-ubuntu  Requested Ubuntu 24.04 build (OST-…) SSI - OS Template (Ubuntu) deliverToSsi=true
//
// Every parameter comes from SSI's record; the pipelines keep validating their inputs and fail
// closed. Steps that write to the registry (import, publish, sign) need a confirmation in the
// UI, and import/publish also need a succeeded check run of the same record first.

import { OPEN_ONBOARDING_STATES } from './onboarding.js';
import { OS_TEMPLATE_BUILD_ID, OS_TEMPLATE_OS, osTemplateOsOf } from './osTemplate.js';
import { isRunActive, isRunSucceeded, PipelineRunError, runsOf } from './pipelineRuns.js';

export const WORKER_ACTIONS = Object.freeze({
  'onboard-check': { role: 'onboardImport', subject: 'onboarding', label: 'Import check' },
  'onboard-import': {
    role: 'onboardImport',
    subject: 'onboarding',
    label: 'Import into quarantine',
    confirm: true,
  },
  'publish-check': { role: 'controlledPublish', subject: 'publish', label: 'Publish check' },
  'publish-execute': {
    role: 'controlledPublish',
    subject: 'publish',
    label: 'Publish to approved/',
    confirm: true,
  },
  'supply-chain-sign': {
    role: 'supplyChainSign',
    subject: 'publish',
    label: 'Sign + SBOM + provenance',
    confirm: true,
  },
  'image-inspection': { role: 'imageInspection', subject: 'image', label: 'Image inspection' },
  // About 4.5 hours on the build machine: started on purpose, never by a stray click.
  'os-template-build': {
    role: 'osTemplateWindows',
    subject: 'os-template',
    label: 'Build the template ISO',
    confirm: true,
  },
  // Occupies a LinuxPool agent for about 15 minutes and publishes multi-gigabyte artifacts.
  'os-template-build-ubuntu': {
    role: 'osTemplateUbuntu',
    subject: 'os-template-ubuntu',
    label: 'Build the Ubuntu template',
    confirm: true,
  },
});

const ACTIONS_BY_SUBJECT = Object.freeze({
  onboarding: ['onboard-check', 'onboard-import'],
  publish: ['publish-check', 'publish-execute', 'supply-chain-sign'],
  image: ['image-inspection'],
  'os-template': ['os-template-build'],
  'os-template-ubuntu': ['os-template-build-ubuntu'],
});

// The worker subject of an OS template request: one per operating system, so each request
// offers only the pipeline of its own OS.
export function osTemplateSubjectOf(build) {
  return osTemplateOsOf(build?.request) === OS_TEMPLATE_OS.UBUNTU
    ? 'os-template-ubuntu'
    : 'os-template';
}

const fullDigestPattern = /^sha256:[a-f0-9]{64}$/;
const repositoryPathPattern = /^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*$/;
const text = (value) => (value == null ? '' : String(value).trim());

// The SSI address the onboard, publish and sign workers call back (their ssiApiBaseUrl
// parameter). Plain HTTP is allowed only because it was configured explicitly; the pipelines
// then need allowInsecurePocApi=true, which SSI sends.
export function workerApiParameters(workerApiBaseUrl) {
  const value = text(workerApiBaseUrl);
  if (!value) {
    throw new PipelineRunError(
      'The SSI address for workers is not configured (SSI_ADO_WORKER_API_BASE_URL).',
    );
  }
  return { ssiApiBaseUrl: value, allowInsecurePocApi: value.startsWith('http://') };
}

function requireSucceededCheck(record, checkAction, message) {
  if (!runsOf(record).some((run) => run.action === checkAction && isRunSucceeded(run))) {
    throw new PipelineRunError(message);
  }
}

// Onboarding request (ONB-…): the worker reads its work order from SSI and imports into the
// team's quarantine folder.
export function planOnboardingRun(request, action, { workerApiBaseUrl } = {}) {
  if (WORKER_ACTIONS[action]?.subject !== 'onboarding')
    throw new PipelineRunError('Unknown pipeline action.', 422);
  if (!request?.id) throw new PipelineRunError('Onboarding request not found.', 404);
  if (!OPEN_ONBOARDING_STATES.includes(request.status)) {
    throw new PipelineRunError(
      `This onboarding request is ${text(request.status) || 'closed'}; it cannot be imported.`,
    );
  }
  const execute = action === 'onboard-import';
  if (execute) {
    requireSucceededCheck(
      request,
      'onboard-check',
      'Run the import check for this request first; the import starts only after it succeeds.',
    );
  }
  return {
    action,
    role: WORKER_ACTIONS[action].role,
    templateParameters: {
      onboardingRequestId: request.id,
      ...workerApiParameters(workerApiBaseUrl),
      executeImport: execute,
    },
  };
}

// Publish request (PUB-…): publish an Approved request, then sign what was published.
// `job` is the request's RM-EXEC job (for the provenance source digest).
export function planPublishRun(request, action, { workerApiBaseUrl, harborProject, job } = {}) {
  if (WORKER_ACTIONS[action]?.subject !== 'publish')
    throw new PipelineRunError('Unknown pipeline action.', 422);
  if (!request?.id) throw new PipelineRunError('Publish request not found.', 404);
  const worker = workerApiParameters(workerApiBaseUrl);

  if (action === 'supply-chain-sign') {
    if (request.status !== 'Published') {
      throw new PipelineRunError('Only a published image can be signed.');
    }
    const digest = text(request.source?.digest).toLowerCase();
    const repository = text(request.target?.repository);
    if (!fullDigestPattern.test(digest) || !repositoryPathPattern.test(repository)) {
      throw new PipelineRunError('The publish request has no immutable target to sign.');
    }
    if (text(request.target?.project) !== text(harborProject)) {
      throw new PipelineRunError(
        `The image was published outside the Harbor project the signing worker uses (${text(harborProject)}).`,
      );
    }
    const sourceDigest = text(job?.sourceDigest).toLowerCase();
    return {
      action,
      role: WORKER_ACTIONS[action].role,
      templateParameters: {
        approvedRepository: repository,
        approvedDigest: digest,
        remediationJobId: text(request.jobId),
        sourceDigest: fullDigestPattern.test(sourceDigest) ? sourceDigest : '',
        postToSsi: true,
        ...worker,
      },
    };
  }

  if (request.status !== 'Approved') {
    throw new PipelineRunError(
      request.status === 'Published'
        ? 'This request is already published.'
        : 'Only an approved publish request can be published.',
    );
  }
  const execute = action === 'publish-execute';
  if (execute) {
    requireSucceededCheck(
      request,
      'publish-check',
      'Run the publish check for this request first; the publish starts only after it succeeds.',
    );
  }
  return {
    action,
    role: WORKER_ACTIONS[action].role,
    templateParameters: { publishRequestId: request.id, ...worker, executePublish: execute },
  };
}

// A scanned image, addressed like the comparison does: <project>/<repository>@sha256:<64 hex>.
export function parseScanReference(reference, harborProject) {
  const value = text(reference).toLowerCase();
  const at = value.lastIndexOf('@');
  const path = at > 0 ? value.slice(0, at) : '';
  const digest = at > 0 ? value.slice(at + 1) : '';
  const [project, ...rest] = path.split('/');
  const repository = rest.join('/');
  if (!fullDigestPattern.test(digest) || !repositoryPathPattern.test(repository)) {
    throw new PipelineRunError(
      'The image must be given as <project>/<repository>@sha256:<digest>.',
      422,
    );
  }
  if (project !== text(harborProject)) {
    throw new PipelineRunError(
      `The image is not in the Harbor project the workers use (${text(harborProject)}).`,
    );
  }
  return { reference: `${project}/${repository}@${digest}`, project, repository, digest };
}

export function planInspectionRun(reference, { harborProject, registryHost } = {}) {
  const image = parseScanReference(reference, harborProject);
  if (!text(registryHost))
    throw new PipelineRunError('The Harbor registry host is not configured.');
  return {
    action: 'image-inspection',
    role: WORKER_ACTIONS['image-inspection'].role,
    templateParameters: {
      imageReference: `${text(registryHost).toLowerCase()}/${image.reference}`,
      deliverToSsi: true,
    },
  };
}

// OS template build request (OST-…): every pipeline parameter comes from the request.
export function planOsTemplateRun(build, action, { workerApiBaseUrl } = {}) {
  const subject = WORKER_ACTIONS[action]?.subject;
  if (subject !== 'os-template' && subject !== 'os-template-ubuntu')
    throw new PipelineRunError('Unknown pipeline action.', 422);
  if (!OS_TEMPLATE_BUILD_ID.test(text(build?.id)))
    throw new PipelineRunError('OS template build request not found.', 404);
  if (subject !== osTemplateSubjectOf(build)) {
    throw new PipelineRunError(
      `This build request is for ${osTemplateOsOf(build.request)}; ${WORKER_ACTIONS[action].label} does not build it.`,
      422,
    );
  }
  if (build.status !== 'Requested') {
    throw new PipelineRunError(
      `This build request is ${text(build.status)}; it is not built again.`,
    );
  }
  if (subject === 'os-template-ubuntu') {
    const { baseImageUrl, baseImageSha256, templateName, diskSizeGb, aptMirror } =
      build.request || {};
    return {
      action,
      role: WORKER_ACTIONS[action].role,
      templateParameters: {
        osTemplateBuildId: build.id,
        baseImageUrl,
        baseImageSha256,
        templateName,
        diskSizeGb: String(diskSizeGb),
        // The pipeline takes "none" for no mirror: Azure DevOps refuses an empty parameter.
        aptMirror: text(aptMirror) || 'none',
        deliverToSsi: true,
        ...workerApiParameters(workerApiBaseUrl),
      },
    };
  }
  const { isoFile, isoSha256, imageIndex, product, templateName } = build.request || {};
  return {
    action,
    role: WORKER_ACTIONS[action].role,
    templateParameters: {
      osTemplateBuildId: build.id,
      isoFile,
      isoSha256,
      // Azure DevOps template parameters are text (src/lib/azureDevOps.js).
      imageIndex: String(imageIndex),
      product,
      templateName,
      deliverToSsi: true,
      ...workerApiParameters(workerApiBaseUrl),
    },
  };
}

// The actions of one record for the screen: whether each can start now, and why not.
export function workerActionsView(subject, record, { enabled, pipelines = {}, plan } = {}) {
  const runs = runsOf(record);
  const actions = (ACTIONS_BY_SUBJECT[subject] || []).map((action) => {
    const { role, label, confirm = false } = WORKER_ACTIONS[action];
    let reason = '';
    if (!enabled) reason = 'Azure DevOps automation is not configured.';
    else if (!pipelines[role]) reason = 'This pipeline is not configured for automatic runs.';
    else if (runs.some((run) => run.role === role && isRunActive(run)))
      reason = 'A run of this pipeline is in progress.';
    else {
      try {
        plan(action);
      } catch (error) {
        if (!(error instanceof PipelineRunError)) throw error;
        reason = error.message;
      }
    }
    return { action, role, label, confirm, available: reason === '', reason };
  });
  return { enabled: Boolean(enabled), actions, runs };
}

export function actionsOf(subject) {
  return ACTIONS_BY_SUBJECT[subject] || [];
}
