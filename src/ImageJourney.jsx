// Image Journey (Azure DevOps automation, Phase 4b): one image's nine steps from quarantine to a
// signed approved/ image, with one "next step" at a time. The steps come from
// src/lib/imageJourney.js; this screen only shows them and offers the existing actions:
//   - a worker step embeds the same Azure DevOps panel as its own screen (renderPanel)
//   - a human step (acceptance, approval) names who decides and opens the screen where they do
// Nothing can be skipped here that the other screens would refuse.
import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Ban,
  CheckCircle2,
  Clock3,
  Loader2,
  Lock,
  MinusCircle,
  Route,
  UserCheck,
  XCircle,
} from 'lucide-react';
import { buildImageJourney, journeyCandidates } from './lib/imageJourney.js';

const STATUS = {
  done: { label: 'Done', icon: CheckCircle2, tone: 'ok' },
  skipped: { label: 'Not needed', icon: MinusCircle, tone: 'muted' },
  running: { label: 'Running', icon: Loader2, tone: 'run' },
  action: { label: 'Ready', icon: ArrowRight, tone: 'next' },
  waiting: { label: 'Waiting for a person', icon: Clock3, tone: 'wait' },
  failed: { label: 'Failed', icon: XCircle, tone: 'bad' },
  blocked: { label: 'Blocked', icon: Ban, tone: 'bad' },
  locked: { label: 'Locked', icon: Lock, tone: 'muted' },
};

const VIEW_LABELS = { onboard: 'Onboard', remediation: 'Remediation', publish: 'Publish' };

function StepIcon({ status }) {
  const { icon: Icon } = STATUS[status] || STATUS.locked;
  return <Icon size={16} aria-hidden="true" />;
}

// jobs, publishRequests, onboardingRequests: the screen's already loaded records.
// selectedId / onSelect: the followed Dry Run. onOpen(view, recordId): open another screen.
// renderPanel(kind, record): the Azure DevOps panel of a step ('plan' | 'execution' | 'publish').
export function ImageJourney({
  jobs = [],
  publishRequests = [],
  onboardingRequests = [],
  selectedId,
  onSelect,
  onOpen,
  renderPanel,
}) {
  const candidates = useMemo(() => journeyCandidates(jobs), [jobs]);
  const dryRun = candidates.find((job) => job.id === selectedId) || candidates[0] || null;
  const journey = useMemo(
    () => (dryRun ? buildImageJourney({ dryRun, jobs, publishRequests, onboardingRequests }) : null),
    [dryRun, jobs, publishRequests, onboardingRequests],
  );
  const [focusedStep, setFocusedStep] = useState('');
  // A new journey, or a journey that moved on, shows its next step again.
  useEffect(() => setFocusedStep(''), [journey?.id, journey?.currentStepId]);

  if (!journey) {
    return (
      <section className="panel journey-empty">
        <Route size={22} aria-hidden="true" />
        <div>
          <strong>No remediation plan to follow yet</strong>
          <span>Create a Dry Run for a scanned image on the Remediation screen; its journey starts here.</span>
        </div>
        <button className="primary-action" type="button" onClick={() => onOpen('remediation')}>
          Open Remediation
        </button>
      </section>
    );
  }

  const shown =
    journey.steps.find((step) => step.id === focusedStep) ||
    journey.steps.find((step) => step.id === journey.currentStepId) ||
    journey.steps[journey.steps.length - 1];
  const percent = Math.round((journey.progress.done / journey.progress.total) * 100);
  const panelRecord = { plan: dryRun, execution: journey.execution, publish: journey.request }[shown.panel];

  return (
    <div className="journey">
      <section className="panel journey-head">
        <label className="journey-pick">
          <span>Remediation plan</span>
          <select value={journey.id} onChange={(event) => onSelect(event.target.value)} aria-label="Remediation plan to follow">
            {candidates.map((job) => (
              <option key={job.id} value={job.id}>
                {job.id} · {job.image}
              </option>
            ))}
          </select>
        </label>
        <div className="journey-progress" aria-label={`${journey.progress.done} of ${journey.progress.total} steps done`}>
          <div className="journey-bar">
            <i style={{ width: `${percent}%` }} />
          </div>
          <strong>
            {journey.progress.done} / {journey.progress.total}
          </strong>
          <span className={`journey-state ${journey.complete ? 'ok' : journey.withdrawn ? 'bad' : ''}`}>
            {journey.complete
              ? 'Signed and published'
              : `Next: ${journey.steps.find((step) => step.id === journey.currentStepId)?.label}`}
          </span>
        </div>
      </section>

      <div className="journey-body">
        <ol className="panel journey-steps" aria-label="Journey steps">
          {journey.steps.map((step, index) => {
            const status = STATUS[step.status] || STATUS.locked;
            const current = step.id === journey.currentStepId;
            return (
              <li key={step.id}>
                <button
                  type="button"
                  className={`journey-step tone-${status.tone}${step.id === shown.id ? ' is-shown' : ''}${current ? ' is-current' : ''}`}
                  aria-current={current ? 'step' : undefined}
                  onClick={() => setFocusedStep(step.id)}
                >
                  <span className="journey-dot">
                    <StepIcon status={step.status} />
                  </span>
                  <span className="journey-step-text">
                    <strong>
                      {index + 1}. {step.label}
                    </strong>
                    <em>{status.label}</em>
                  </span>
                </button>
              </li>
            );
          })}
        </ol>

        <section className={`panel journey-detail tone-${(STATUS[shown.status] || STATUS.locked).tone}`}>
          <div className="journey-detail-head">
            <span className="journey-dot">
              <StepIcon status={shown.status} />
            </span>
            <div>
              <h2>{shown.label}</h2>
              <span>
                {(STATUS[shown.status] || STATUS.locked).label} · {shown.owner}
              </span>
            </div>
          </div>
          <p className="journey-summary">{shown.summary}</p>

          {shown.human && ['waiting', 'action'].includes(shown.status) && (
            <p className="journey-gate">
              <UserCheck size={15} aria-hidden="true" />
              {shown.id === 'acceptance'
                ? 'Human gate: a consumer team decides. Four-eyes rule: the person who requests publishing cannot accept the candidate.'
                : 'Human gate: the policy is evaluated, then an approver who did not request it decides.'}
            </p>
          )}
          {shown.status === 'blocked' && (
            <p className="journey-gate bad">
              <AlertTriangle size={15} aria-hidden="true" />
              This journey cannot continue from here. Open the step&apos;s screen for the reason and the next decision.
            </p>
          )}

          {['action', 'running', 'failed'].includes(shown.status) && shown.panel && panelRecord && (
            <div className="journey-panel">{renderPanel(shown.panel, panelRecord)}</div>
          )}

          {shown.view && (
            <button className="secondary-action journey-open" type="button" onClick={() => onOpen(shown.view, shown.record)}>
              Open {VIEW_LABELS[shown.view] || shown.view}
              {shown.record ? ` · ${shown.record}` : ''}
              <ArrowRight size={15} aria-hidden="true" />
            </button>
          )}
          {journey.complete && (
            <p className="journey-done">
              <CheckCircle2 size={16} aria-hidden="true" />
              {journey.request?.target?.tagReference || 'The image'} is published, signed and has an SBOM and provenance.
            </p>
          )}
        </section>
      </div>
    </div>
  );
}
