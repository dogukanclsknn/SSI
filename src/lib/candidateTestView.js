// Read-side view of the pre-release test stage of a verified RM-EXEC job (the Remediation
// screen's "Pre-release testing" panel). Pure: no state, fetch or React.

import { consumerDecisionsFor } from './candidateTestEvidence.js';

const sha256Pattern = /^sha256:[a-f0-9]{64}$/;

function text(value) {
  return value == null ? '' : String(value).trim();
}

function registryHostOf(reference) {
  const value = text(reference);
  const slash = value.indexOf('/');
  const host = slash > 0 ? value.slice(0, slash) : '';
  return host.includes('.') || host.includes(':') ? host : '';
}

function withoutTagOrDigest(reference) {
  const value = text(reference).split('@')[0];
  const lastSlash = value.lastIndexOf('/');
  const lastColon = value.lastIndexOf(':');
  return lastColon > lastSlash ? value.slice(0, lastColon) : value;
}

// The three parameters of the "SSI - Candidate Test" pipeline. New jobs carry the exact
// source reference from the Copa evidence; older jobs derive it from the onboarded image
// name and the registry of the patched output tag.
export function candidateTestParameters(job) {
  const outputDigest = text(job?.patchedImageDigest).toLowerCase();
  const sourceDigest = text(job?.sourceDigest).toLowerCase();
  if (!job?.id || !sha256Pattern.test(outputDigest) || !sha256Pattern.test(sourceDigest)) return null;

  const outputRepository = withoutTagOrDigest(job.patchedImageTag);
  const host = registryHostOf(outputRepository);
  let sourceReference = text(job.verificationEvidence?.sourceReference);
  if (!sourceReference.endsWith(`@${sourceDigest}`)) {
    const imageRepository = withoutTagOrDigest(job.image);
    const sourceRepository = registryHostOf(imageRepository) || !host ? imageRepository : `${host}/${imageRepository}`;
    sourceReference = sourceRepository ? `${sourceRepository}@${sourceDigest}` : '';
  }
  return {
    remediationJobId: job.id,
    sourceReference,
    candidateReference: outputRepository ? `${outputRepository}@${outputDigest}` : '',
  };
}

export function candidateStageView(job) {
  const outputDigest = text(job?.patchedImageDigest).toLowerCase();
  const test = job?.candidateTest;
  const testBound = Boolean(test) && text(test.candidateDigest).toLowerCase() === outputDigest;
  const testStatus = !testBound ? 'not-run' : test.passed === true ? 'passed' : 'failed';
  const withdrawn = Boolean(job?.publishWithdrawal);

  // Every person's latest decision counts (same rule as the publish policy): any open issue
  // wins over acceptances, and only its reporter can withdraw it.
  const newestFirst = (left, right) => text(right.decidedAt).localeCompare(text(left.decidedAt));
  const decisions = sha256Pattern.test(outputDigest) ? consumerDecisionsFor(job).sort(newestFirst) : [];
  const openIssues = decisions.filter((item) => item.decision === 'issue-found');
  const acceptances = decisions.filter((item) => item.decision === 'accepted');
  const acceptanceStatus = openIssues.length > 0 ? 'issue-found' : acceptances.length > 0 ? 'accepted' : 'pending';
  const history = (Array.isArray(job?.consumerAcceptance?.history) ? job.consumerAcceptance.history : []).filter(
    (item) => text(item?.candidateDigest).toLowerCase() === outputDigest,
  );

  return {
    testStatus,
    test: testBound ? test : null,
    acceptanceStatus,
    acceptance: openIssues[0] || acceptances[0] || null,
    openIssues,
    acceptances,
    history,
    manualUploader: testBound && test.intake?.channel === 'manual' ? text(test.intake.actor) : '',
    // A withdrawn image is final: no further consumer decisions and never "ready" again.
    withdrawn,
    canAccept: testStatus === 'passed' && !withdrawn,
    ready: testStatus === 'passed' && acceptanceStatus === 'accepted' && !withdrawn,
  };
}
