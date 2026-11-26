// Image Journey (Azure DevOps automation, Phase 4b): one image's way from quarantine to a signed
// approved/ image, as nine steps derived from SSI's own records. Pure: no state, fetch or React.
//
// A journey is anchored on a Dry Run (RM-DRY) and follows its records:
//   onboarding request (same repository) → Dry Run → RM-EXEC (parentJobId) → publish request
//   (selectCurrentPublishRequest) → supply-chain evidence on the RM-EXEC job.
// Nothing here decides anything new: every status is read from an existing rule (canonical
// report, Copa runs, candidate test, consumer acceptance, publish policy, signing evidence), and
// human gates stay human gates. A step is never "done" because the wizard says so.

import { candidateStageView } from './candidateTestView.js';
import { selectCurrentPublishRequest } from './publishGateView.js';
import { isRunActive, isRunSucceeded, runsOf, verifiedExecutionOf } from './pipelineRuns.js';

export const JOURNEY_STEPS = Object.freeze([
  { id: 'onboard', label: 'Onboard', owner: 'Operator' },
  { id: 'canonical-scan', label: 'Canonical scan', owner: 'Operator' },
  { id: 'copa-check', label: 'Copa input check', owner: 'Operator' },
  { id: 'patch', label: 'Patch + re-scan', owner: 'Operator' },
  { id: 'candidate-test', label: 'Candidate test', owner: 'Operator' },
  { id: 'acceptance', label: 'Consumer acceptance', owner: 'Consumer team', human: true },
  { id: 'approval', label: 'Publish approval', owner: 'Requester, then approver', human: true },
  { id: 'publish', label: 'Publish', owner: 'Approver' },
  { id: 'sign', label: 'Sign + SBOM', owner: 'Approver' },
]);

// done: finished · skipped: not needed · running: a run is in progress · action: can be started
// now · waiting: waiting for a person · failed: the last attempt failed and can be retried ·
// blocked: cannot continue (a rule says no) · locked: an earlier step is not done yet.
const FINISHED = new Set(['done', 'skipped']);

const text = (value) => (value == null ? '' : String(value).trim());

function repositoryOf(reference) {
  const value = text(reference).toLowerCase().split('@')[0];
  const lastSlash = value.lastIndexOf('/');
  const lastColon = value.lastIndexOf(':');
  const path = lastColon > lastSlash ? value.slice(0, lastColon) : value;
  const segments = path.split('/');
  // Drop a registry host (it has a dot or a port); keep <project>/<repository>.
  if (segments.length > 2 && (segments[0].includes('.') || segments[0].includes(':')))
    segments.shift();
  return segments.join('/');
}

function latestRun(record, actions) {
  return runsOf(record).find((run) => actions.includes(run.action)) || null;
}

// The Dry Runs a journey can follow, newest first.
export function journeyCandidates(jobs = []) {
  return (Array.isArray(jobs) ? jobs : [])
    .filter((job) => job?.mode === 'dry-run')
    .sort((left, right) => text(right.createdAt).localeCompare(text(left.createdAt)));
}

function step(definition, status, summary, extra = {}) {
  return { ...definition, status, summary, ...extra };
}

// Status of a step driven by one pipeline action on one record.
function pipelineStep(
  definition,
  { record, actions, done, doneSummary, ready, readySummary, panel },
) {
  if (done) return step(definition, 'done', doneSummary, { panel });
  const run = latestRun(record, actions);
  if (run && isRunActive(run)) {
    return step(
      definition,
      'running',
      `Run #${run.runName || run.runId} is in progress in Azure DevOps.`,
      { panel, run },
    );
  }
  if (!ready) return step(definition, 'locked', 'Waits for the step before.', { panel });
  if (run && run.state === 'completed' && !isRunSucceeded(run)) {
    return step(
      definition,
      'failed',
      `The last run (#${run.runName || run.runId}) did not succeed. Check it in Azure DevOps and run it again.`,
      {
        panel,
        run,
      },
    );
  }
  return step(definition, 'action', readySummary, { panel });
}

export function buildImageJourney({
  dryRun,
  jobs = [],
  publishRequests = [],
  onboardingRequests = [],
} = {}) {
  if (!dryRun?.id || dryRun.mode !== 'dry-run') return null;
  const [
    onboardDef,
    scanDef,
    checkDef,
    patchDef,
    testDef,
    acceptDef,
    approvalDef,
    publishDef,
    signDef,
  ] = JOURNEY_STEPS;
  const repository = repositoryOf(dryRun.image);
  const executionId = verifiedExecutionOf(dryRun, jobs);
  const execution = executionId ? jobs.find((job) => job.id === executionId) : null;
  const request = execution
    ? selectCurrentPublishRequest({ job: execution, publishRequests })
    : null;
  // A withdrawn result does not count (the plan may be patched again), but the journey says so.
  const withdrawnExecution = execution
    ? null
    : jobs.find(
        (job) =>
          job?.mode === 'execution' && job.parentJobId === dryRun.id && job.publishWithdrawal,
      );
  const steps = [];

  // 1. Onboard: how the image entered quarantine. Images already in Harbor skip it.
  const onboarding = (Array.isArray(onboardingRequests) ? onboardingRequests : []).find(
    (item) => repositoryOf(item?.target?.tagReference) === repository,
  );
  if (!onboarding) {
    steps.push(
      step(
        onboardDef,
        'skipped',
        'The image was already in Harbor; it was not onboarded through SSI.',
      ),
    );
  } else if (onboarding.status === 'Imported') {
    steps.push(
      step(onboardDef, 'done', `Imported into quarantine (${onboarding.id}).`, {
        record: onboarding.id,
        view: 'onboard',
      }),
    );
  } else if (['Requested', 'Importing'].includes(onboarding.status)) {
    steps.push(
      step(
        onboardDef,
        'action',
        `${onboarding.id} is ${onboarding.status.toLowerCase()}; import it from the Onboard screen.`,
        { record: onboarding.id, view: 'onboard' },
      ),
    );
  } else {
    steps.push(
      step(
        onboardDef,
        'skipped',
        `${onboarding.id} is ${onboarding.status}; the image in Harbor is used as it is.`,
        { record: onboarding.id, view: 'onboard' },
      ),
    );
  }

  // 2–4. Canonical scan, Copa input check, patch: the Dry Run's own runs.
  const contentDigest = text(dryRun.canonicalReport?.contentDigest).toLowerCase();
  steps.push(
    pipelineStep(scanDef, {
      record: dryRun,
      actions: ['canonical-scan'],
      done: Boolean(dryRun.canonicalReport),
      doneSummary: `Canonical report accepted: ${dryRun.plannedFixes?.length || 0} OS package finding(s) can be fixed.`,
      ready: true,
      readySummary: 'Scan the source digest; the report comes back to this plan on its own.',
      panel: 'plan',
    }),
  );
  const checked = runsOf(dryRun).some(
    (run) =>
      run.action === 'copa-prepare' &&
      isRunSucceeded(run) &&
      run.parameters?.canonicalReceiptContentDigest === contentDigest,
  );
  const planBlocked = Boolean(dryRun.canonicalReport) && dryRun.lifecycleState === 'blocked';
  steps.push(
    planBlocked
      ? step(
          checkDef,
          'blocked',
          'The canonical report has no OS package finding with a fixed version; there is nothing to patch.',
          { panel: 'plan' },
        )
      : pipelineStep(checkDef, {
          record: dryRun,
          actions: ['copa-prepare'],
          done: checked || Boolean(execution),
          doneSummary: 'The canonical input was verified by the Copa worker.',
          ready: Boolean(dryRun.canonicalReport),
          readySummary: 'Verify the canonical input. Nothing is patched or pushed.',
          panel: 'plan',
        }),
  );
  steps.push(
    pipelineStep(patchDef, {
      record: dryRun,
      actions: ['copa-execute'],
      done: Boolean(execution),
      doneSummary: execution
        ? `Verified result ${execution.id}: ${execution.fixed?.length ?? 0} finding(s) fixed.`
        : '',
      ready: checked && !planBlocked,
      readySummary: withdrawnExecution
        ? `${withdrawnExecution.id} was withdrawn. Patch again for a new candidate; asks for confirmation.`
        : 'Patch, push a copa-poc test tag and re-scan it. Asks for confirmation.',
      panel: 'plan',
    }),
  );

  // 5–6. Pre-release testing on the RM-EXEC job.
  const stage = execution ? candidateStageView(execution) : null;
  if (stage?.testStatus === 'failed') {
    steps.push(
      step(
        testDef,
        'failed',
        'The candidate did not behave like the source image. See Pre-release testing.',
        { panel: 'execution', view: 'remediation', record: execution.id },
      ),
    );
  } else {
    steps.push(
      pipelineStep(testDef, {
        record: execution,
        actions: ['candidate-test'],
        done: stage?.testStatus === 'passed',
        doneSummary: 'The candidate starts and runs like the source image.',
        ready: Boolean(execution),
        readySummary: 'Test the candidate side by side with the source image.',
        panel: 'execution',
      }),
    );
  }
  if (!stage || stage.testStatus !== 'passed') {
    steps.push(step(acceptDef, 'locked', 'Waits for the candidate test.'));
  } else if (stage.acceptanceStatus === 'accepted') {
    const decision = stage.acceptance;
    steps.push(
      step(
        acceptDef,
        'done',
        `Accepted${decision ? ` by ${decision.decidedBy} in ${decision.environment}` : ''}.`,
        { view: 'remediation', record: execution.id },
      ),
    );
  } else if (stage.acceptanceStatus === 'issue-found') {
    steps.push(
      step(
        acceptDef,
        'blocked',
        `${stage.openIssues.length} open issue(s) reported by a consumer team.`,
        { view: 'remediation', record: execution.id },
      ),
    );
  } else {
    steps.push(
      step(
        acceptDef,
        'waiting',
        'A consumer team tries the candidate in its own environment and records the result.',
        {
          view: 'remediation',
          record: execution.id,
        },
      ),
    );
  }

  // 7–9. Publish request, publish and signing.
  const accepted = stage?.acceptanceStatus === 'accepted';
  const withdrawn = Boolean(execution?.publishWithdrawal);
  if (withdrawn) {
    steps.push(
      step(approvalDef, 'blocked', 'This image was withdrawn and can never be published again.', {
        view: 'publish',
        record: request?.id,
      }),
    );
  } else if (!request) {
    steps.push(
      accepted
        ? step(
            approvalDef,
            'action',
            'Request publishing: the policy is evaluated, then an approver decides.',
            { view: 'publish', record: execution.id },
          )
        : step(approvalDef, 'locked', 'Waits for consumer acceptance.'),
    );
  } else if (request.status === 'ApprovalRequired') {
    steps.push(
      step(
        approvalDef,
        'waiting',
        `${request.id} waits for an approver; the requester cannot approve it.`,
        { view: 'publish', record: request.id },
      ),
    );
  } else if (['Approved', 'Published'].includes(request.status)) {
    steps.push(
      step(approvalDef, 'done', `${request.id} approved.`, { view: 'publish', record: request.id }),
    );
  } else {
    steps.push(
      step(
        approvalDef,
        'blocked',
        `${request.id} is ${request.status}. See its policy checks on the Publish screen.`,
        { view: 'publish', record: request.id },
      ),
    );
  }
  const publishable = !withdrawn && ['Approved', 'Published'].includes(request?.status);
  steps.push(
    pipelineStep(publishDef, {
      record: request,
      actions: ['publish-check', 'publish-execute'],
      done: request?.status === 'Published',
      doneSummary: `Published to ${text(request?.target?.tagReference)}.`,
      ready: publishable,
      readySummary:
        'Check the approved handoff, then copy the digest to approved/. Started by an approver.',
      panel: 'publish',
    }),
  );
  const signed =
    execution?.supplyChain?.signature === true && execution?.supplyChain?.sbom === true;
  steps.push(
    pipelineStep(signDef, {
      record: request,
      actions: ['supply-chain-sign'],
      done: signed,
      doneSummary: 'Signed with Cosign; SBOM and provenance attached.',
      ready: !withdrawn && request?.status === 'Published',
      readySummary:
        'Sign the published digest and attach SBOM and provenance. Started by an approver.',
      panel: 'publish',
    }),
  );

  const current = steps.find((item) => !FINISHED.has(item.status)) || null;
  return {
    id: dryRun.id,
    image: text(dryRun.image),
    execution,
    request,
    withdrawn,
    steps,
    currentStepId: current?.id || '',
    complete: !current,
    progress: {
      done: steps.filter((item) => FINISHED.has(item.status)).length,
      total: steps.length,
    },
  };
}
