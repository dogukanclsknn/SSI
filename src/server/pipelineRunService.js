// Starts worker pipelines in Azure DevOps and reports their state (Azure DevOps automation,
// Phases 2 and 4a). Rules live in src/lib/pipelineRuns.js (remediation jobs) and
// src/lib/workerPipelineActions.js (onboarding, publish requests, scanned images); this module
// does the I/O.
//
// A run is started while its record is locked: the in-progress check, the Azure DevOps call and
// the stored run record happen as one step, so two clicks never start two runs of the same
// pipeline for the same record.
//   remediation job    job row lock (updateJobWith)
//   onboarding request request row lock (updateOnboardingRequestWith)
//   publish request    job row + request row lock (updateJobAndPublishRequests)
//   scanned image      advisory lock on its runs (updateResourceRunsWith, migration 012)
//   OS template build  build row lock (updateOsTemplateBuildWith, migration 013)
import {
  createRunRecord,
  isRunActive,
  PIPELINE_ACTIONS,
  PipelineRunError,
  pipelineRunsView,
  planPipelineRun,
  refreshedRun,
  runsOf,
  verifiedExecutionOf,
  withRun,
} from '../lib/pipelineRuns.js';
import {
  parseScanReference,
  planInspectionRun,
  planOnboardingRun,
  osTemplateSubjectOf,
  planOsTemplateRun,
  planPublishRun,
  WORKER_ACTIONS,
  workerActionsView,
} from '../lib/workerPipelineActions.js';
import { AzureDevOpsError } from '../lib/azureDevOps.js';
import { onboardingProgress } from '../lib/onboardingProgress.js';

// Live Azure DevOps lookups per request: bounded so a long history never slows a screen.
const MAX_LIVE_REFRESH = 5;
const REFRESH_ERROR = 'Azure DevOps could not be asked for the current state.';

export function createPipelineRunService({
  azureDevOps,
  config,
  harborProject,
  // The approved catalog and quarantine folders: a Copa candidate never lands in the former.
  publishPrefix = 'approved',
  quarantinePrefix = 'onboarded',
  registryHost = '',
  store,
  now = () => new Date(),
}) {
  const settings = () => ({
    enabled: azureDevOps.enabled,
    harborProject,
    publishPrefix,
    quarantinePrefix,
    pipelines: config.pipelines || {},
  });
  const workerApiBaseUrl = () => config.workerApiBaseUrl || '';

  // Newest active runs get their state from Azure DevOps. A lookup that fails keeps the stored
  // state (and marks the run), so a short Azure DevOps outage never hides a run.
  async function refreshActiveRuns(record) {
    if (!azureDevOps.enabled) return { record, failed: new Set() };
    const at = now().toISOString();
    const failed = new Set();
    let budget = MAX_LIVE_REFRESH;
    const runs = [];
    for (const run of runsOf(record)) {
      if (!isRunActive(run) || budget === 0) {
        runs.push(run);
        continue;
      }
      budget -= 1;
      try {
        runs.push(refreshedRun(run, await azureDevOps.getRun(run.role, run.runId), at));
      } catch (error) {
        if (!(error instanceof AzureDevOpsError)) throw error;
        failed.add(run.runId);
        runs.push(run);
      }
    }
    return { record: runs.length ? { ...record, pipelineRuns: runs } : record, failed };
  }

  const markFailed = (view, failed) => ({
    ...view,
    runs: view.runs.map((run) =>
      failed.has(run.runId) ? { ...run, refreshError: REFRESH_ERROR } : run,
    ),
  });

  function assertEnabled() {
    if (!azureDevOps.enabled) {
      throw new AzureDevOpsError('Azure DevOps automation is not configured.', {
        statusCode: 503,
        code: 'ado_not_configured',
      });
    }
  }

  // The shared start step on a locked record: refresh, one run per pipeline, plan, run, record.
  // Returns { record (with the new run), run, auditEvent }.
  async function launch(
    locked,
    { role, label, plan, actorId, audit, resourceType, resourceId, eventPrefix },
  ) {
    const { record: current, failed } = await refreshActiveRuns(locked);
    const active = runsOf(current).find((run) => run.role === role && isRunActive(run));
    if (active) {
      throw new PipelineRunError(
        failed.has(active.runId)
          ? `Run ${active.runId} of this pipeline could not be checked in Azure DevOps; try again shortly.`
          : `Run ${active.runId} of this pipeline is still in progress.`,
      );
    }
    const at = now();
    const planned = await plan(current, at);
    const pipelineId = config.pipelines[role];
    const run = await azureDevOps.runPipeline(role, planned.templateParameters);
    const started = createRunRecord({
      plan: planned,
      pipelineId,
      run,
      actor: actorId,
      at: at.toISOString(),
    });
    return {
      record: { ...withRun(current, started), updatedAt: at.toISOString() },
      run: started,
      auditEvent: audit({
        eventType: `${eventPrefix}.pipeline-run.started`,
        action: 'start-pipeline-run',
        resourceType,
        resourceId,
        summary: `${label} started in Azure DevOps for ${resourceId} (run ${run.id})`,
        metadata: {
          pipelineAction: planned.action,
          pipelineId,
          runId: run.id,
          webUrl: run.webUrl,
          parameters: planned.templateParameters,
        },
      }),
    };
  }

  function requireAction(action, subject) {
    if (WORKER_ACTIONS[action]?.subject !== subject)
      throw new PipelineRunError('Unknown pipeline action.', 422);
    return WORKER_ACTIONS[action];
  }

  async function verifiedExecution(job, scope) {
    if (job?.mode !== 'dry-run') return '';
    return verifiedExecutionOf(job, await store.listJobs(scope));
  }

  return {
    // ── Remediation jobs ────────────────────────────────────────────────────────────────────
    // `scope`: the caller's team scope, to find a verified result made from a Dry Run.
    async view(job, scope) {
      const { record: current, failed } = await refreshActiveRuns(job);
      const verifiedExecutionId = await verifiedExecution(current, scope);
      return markFailed(pipelineRunsView(current, { ...settings(), verifiedExecutionId }), failed);
    },

    // Returns { job, run } or null when the job is not visible in `scope`.
    async start({ jobId, action, canonicalBuildId, actorId, scope, audit }) {
      assertEnabled();
      if (!PIPELINE_ACTIONS[action]) throw new PipelineRunError('Unknown pipeline action.', 422);
      const { role, label } = PIPELINE_ACTIONS[action];
      let started = null;
      const job = await store.updateJobWith(
        jobId,
        async (locked) => {
          const result = await launch(locked, {
            role,
            label,
            actorId,
            audit,
            resourceType: 'remediation-job',
            resourceId: locked.id,
            eventPrefix: 'remediation',
            plan: async (current, at) =>
              planPipelineRun(current, action, {
                ...settings(),
                canonicalBuildId,
                verifiedExecutionId: await verifiedExecution(current, scope),
                now: at.getTime(),
              }),
          });
          started = result.run;
          return { job: result.record, auditEvent: result.auditEvent };
        },
        scope,
      );
      return job ? { job, run: started } : null;
    },

    // ── Onboarding requests ─────────────────────────────────────────────────────────────────
    async viewOnboarding(request) {
      const { record: current, failed } = await refreshActiveRuns(request);
      const view = workerActionsView('onboarding', current, {
        ...settings(),
        plan: (action) =>
          planOnboardingRun(current, action, { workerApiBaseUrl: workerApiBaseUrl() }),
      });
      const latest = view.runs.find((run) => ['onboard-check', 'onboard-import'].includes(run.action));
      let timeline = null;
      let progressError = '';
      if (latest && isRunActive(latest) && azureDevOps.getRunProgress) {
        try {
          timeline = await azureDevOps.getRunProgress(latest.role, latest.runId);
        } catch (error) {
          if (!(error instanceof AzureDevOpsError)) throw error;
          progressError = 'Live step progress is temporarily unavailable.';
        }
      }
      const progress = onboardingProgress(request, view.runs, failed.has(latest?.runId) ? null : timeline);
      if (failed.has(latest?.runId)) progress.percent = null;
      return { ...markFailed(view, failed), progress: { ...progress, error: progressError || (failed.has(latest?.runId) ? REFRESH_ERROR : '') } };
    },

    // Returns { request, run } or null when the request is not visible in `scope`.
    async startOnboarding({ requestId, action, actorId, scope, audit }) {
      assertEnabled();
      const { role, label } = requireAction(action, 'onboarding');
      let started = null;
      const result = await store.updateOnboardingRequestWith(
        requestId,
        async (locked) => {
          const launched = await launch(locked, {
            role,
            label,
            actorId,
            audit,
            resourceType: 'onboarding-request',
            resourceId: locked.id,
            eventPrefix: 'onboarding',
            plan: async (current) =>
              planOnboardingRun(current, action, { workerApiBaseUrl: workerApiBaseUrl() }),
          });
          started = launched.run;
          return { request: launched.record, auditEvent: launched.auditEvent };
        },
        scope,
      );
      return result ? { request: result.request, run: started } : null;
    },

    // ── Publish requests ────────────────────────────────────────────────────────────────────
    async viewPublish(request, job) {
      const { record: current, failed } = await refreshActiveRuns(request);
      const view = workerActionsView('publish', current, {
        ...settings(),
        plan: (action) =>
          planPublishRun(current, action, {
            workerApiBaseUrl: workerApiBaseUrl(),
            harborProject,
            job,
          }),
      });
      return markFailed(view, failed);
    },

    // Returns { request, run } or null when the request is not visible in `scope`. The job row
    // and the request row are locked in the same order as every other publish decision.
    async startPublish({ requestId, action, actorId, scope, audit }) {
      assertEnabled();
      const { role, label } = requireAction(action, 'publish');
      const visible = await store.getPublishRequest(requestId, scope);
      if (!visible) return null;
      let started = null;
      const outcome = await store.updateJobAndPublishRequests(
        visible.jobId,
        async (job, loadPublishRequests) => {
          const [locked] = await loadPublishRequests({ ids: [requestId] });
          if (!locked) throw new PipelineRunError('Publish request not found.', 404);
          const launched = await launch(locked, {
            role,
            label,
            actorId,
            audit,
            resourceType: 'publish-request',
            resourceId: locked.id,
            eventPrefix: 'publish',
            plan: async (current) =>
              planPublishRun(current, action, {
                workerApiBaseUrl: workerApiBaseUrl(),
                harborProject,
                job,
              }),
          });
          started = launched.run;
          return { requests: [{ request: launched.record, auditEvent: launched.auditEvent }] };
        },
        scope,
      );
      return { request: outcome.requests[0], run: started };
    },

    // ── Scanned images (image inspection) ──────────────────────────────────────────────────
    // The caller has already checked that its team scope can see the image's scan.
    async viewImage(reference) {
      const image = parseScanReference(reference, harborProject);
      const runs = await store.listResourceRuns('image', image.reference);
      const { record: current, failed } = await refreshActiveRuns({ pipelineRuns: runs });
      const view = workerActionsView('image', current, {
        ...settings(),
        plan: () => planInspectionRun(image.reference, { harborProject, registryHost }),
      });
      return markFailed(view, failed);
    },

    async startImage({ reference, action, actorId, audit, tenantId }) {
      assertEnabled();
      const { role, label } = requireAction(action, 'image');
      const image = parseScanReference(reference, harborProject);
      let started = null;
      await store.updateResourceRunsWith('image', image.reference, async (runs) => {
        const launched = await launch(
          { pipelineRuns: runs },
          {
            role,
            label,
            actorId,
            audit: (values) => audit({ ...values, tenantId }),
            resourceType: 'image',
            resourceId: image.reference,
            eventPrefix: 'scan',
            plan: async () => planInspectionRun(image.reference, { harborProject, registryHost }),
          },
        );
        started = launched.run;
        // Runs whose state was refreshed are written back too.
        return { runs: runsOf(launched.record), auditEvent: launched.auditEvent };
      });
      return { reference: image.reference, run: started };
    },

    // ── OS template builds (platform-wide, no team scope) ──────────────────────────────────
    async viewOsTemplate(build) {
      const { record: current, failed } = await refreshActiveRuns(build);
      const view = workerActionsView(osTemplateSubjectOf(current), current, {
        ...settings(),
        plan: (action) =>
          planOsTemplateRun(current, action, { workerApiBaseUrl: workerApiBaseUrl() }),
      });
      return markFailed(view, failed);
    },

    // Returns { build, run }; a missing request is a 404 PipelineRunError.
    async startOsTemplate({ buildId, action, actorId, audit }) {
      assertEnabled();
      // Either OS's action; planOsTemplateRun refuses the one that is not the request's own.
      const { role, label } = requireAction(
        action,
        WORKER_ACTIONS[action]?.subject === 'os-template-ubuntu'
          ? 'os-template-ubuntu'
          : 'os-template',
      );
      let started = null;
      const build = await store.updateOsTemplateBuildWith(buildId, async (locked) => {
        if (!locked) throw new PipelineRunError('OS template build request not found.', 404);
        const launched = await launch(locked, {
          role,
          label,
          actorId,
          audit,
          resourceType: 'os-template',
          resourceId: locked.id,
          eventPrefix: 'os-template',
          plan: async (current) =>
            planOsTemplateRun(current, action, { workerApiBaseUrl: workerApiBaseUrl() }),
        });
        started = launched.run;
        return { build: launched.record, auditEvent: launched.auditEvent };
      });
      return { build, run: started };
    },
  };
}
