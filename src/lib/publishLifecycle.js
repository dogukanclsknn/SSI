// SSI — Publish lifecycle decisions after the policy evaluation: reject a request that waits
// for approval, and withdraw an image that was already published.
//
//   ApprovalRequired ──reject──▶ Rejected     (terminal)
//   Published ───────withdraw──▶ Withdrawn    (terminal; the digest can never be published again)
//   Blocked / ApprovalRequired / Approved ──(its image is withdrawn)──▶ Cancelled (terminal)
//
// A withdrawal is about the image (its digest), not about one tag: every published request
// for the digest is withdrawn together, and the job that produced the digest keeps the
// record, so the publish policy blocks any new or pending request for it
// (image-not-withdrawn, see publishPolicy.js). A publish receipt that arrives after the
// withdrawal (a worker that already had its handoff) is recorded, because the registry write
// really happened, but the request is stored as Withdrawn right away. SSI only records the
// decision; removing the image from the registry is a separate, controlled worker step.
//
// The requests of the digest that were not published yet can never happen any more: the
// withdrawal cancels them in the same transaction, so none stays open (or counted as waiting)
// forever. An Approved one may already be in a worker's hands; if its receipt arrives after
// the cancellation, the registry write is still recorded, exactly like a late publication.
//
// Pure: no I/O. The server persists the results atomically
// (remediationStore.updateJobAndPublishRequests).

import { acceptPublishReceipt, assertPublishApprover, PublishPolicyValidationError } from './publishPolicy.js';

export const WITHDRAWAL_CATEGORIES = ['functional', 'security', 'compliance', 'other'];
// Requests of a digest that are not published yet; a withdrawal cancels them.
export const OPEN_PUBLISH_STATUSES = Object.freeze(['Blocked', 'ApprovalRequired', 'Approved']);
const CANCELLED_FOR_WITHDRAWAL = 'image-withdrawn';

const REASON_MIN_LENGTH = 10;
const REASON_MAX_LENGTH = 1000;
const sha256Pattern = /^sha256:[a-f0-9]{64}$/;
// Control and format characters (incl. bidi overrides) and line/paragraph separators: a
// reason is one line of visible text in banners, reports and the audit trail.
const hiddenOrLineBreakingCharacters = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

function text(value) {
  return value == null ? '' : String(value).trim();
}

function decisionReason(value, action) {
  if (typeof value !== 'string') {
    throw new PublishPolicyValidationError(`${action} reason must be text.`);
  }
  const reason = value.trim();
  if (reason.length < REASON_MIN_LENGTH) {
    throw new PublishPolicyValidationError(`${action} reason must contain at least ${REASON_MIN_LENGTH} characters.`);
  }
  if (reason.length > REASON_MAX_LENGTH) {
    throw new PublishPolicyValidationError(`${action} reason must not exceed ${REASON_MAX_LENGTH} characters.`);
  }
  if (hiddenOrLineBreakingCharacters.test(reason)) {
    throw new PublishPolicyValidationError(`${action} reason must be a single line of printable text.`);
  }
  return reason;
}

function timestampOf(value) {
  return text(value) || new Date().toISOString();
}

// An approver closes a request that waits for approval. Requests that are already approved
// are not rejectable: the isolated worker may be writing to the registry at that moment, and
// a rejected request would then hide a real registry write. Their job-bound checks are
// re-evaluated at the worker handoff instead.
export function rejectPublishRequest(request, { actorId, actorRoles = [], reason, config, rejectedAt } = {}) {
  if (request?.status !== 'ApprovalRequired') {
    throw new PublishPolicyValidationError('Only a publish request that is waiting for approval can be rejected.', 409);
  }
  assertPublishApprover(config, actorId, actorRoles);
  const validReason = decisionReason(reason, 'Rejection');
  const timestamp = timestampOf(rejectedAt);
  return {
    ...request,
    status: 'Rejected',
    updatedAt: timestamp,
    rejection: {
      rejectedBy: text(actorId),
      reason: validReason,
      rejectedAt: timestamp,
    },
  };
}

// Validates who withdraws and why, once for the whole digest. Stopping a bad image must be
// fast, so one authorized person decides; the reason and category are mandatory and audited.
export function buildWithdrawalDecision({ actorId, actorRoles = [], reason, category, config, withdrawnAt } = {}) {
  assertPublishApprover(config, actorId, actorRoles);
  const validReason = decisionReason(reason, 'Withdrawal');
  if (typeof category !== 'string' || !WITHDRAWAL_CATEGORIES.includes(category.trim().toLowerCase())) {
    throw new PublishPolicyValidationError(`Withdrawal category must be one of: ${WITHDRAWAL_CATEGORIES.join(', ')}.`);
  }
  return {
    withdrawnBy: text(actorId),
    reason: validReason,
    category: category.trim().toLowerCase(),
    withdrawnAt: timestampOf(withdrawnAt),
  };
}

function digestOf(request) {
  const digest = text(request?.source?.digest).toLowerCase();
  if (!sha256Pattern.test(digest)) {
    throw new PublishPolicyValidationError('The published request has no immutable digest; withdrawal is fail-closed.', 409);
  }
  return digest;
}

function publishedReference(request) {
  return text(request.publish?.receipt?.targetReference) || text(request.target?.tagReference);
}

// Applies a withdrawal decision (buildWithdrawalDecision) to one published request.
export function withdrawPublishedRequest(request, decision) {
  if (request?.status !== 'Published') {
    throw new PublishPolicyValidationError('Only a published image can be withdrawn.', 409);
  }
  return {
    ...request,
    status: 'Withdrawn',
    updatedAt: decision.withdrawnAt,
    withdrawal: {
      withdrawnBy: decision.withdrawnBy,
      reason: decision.reason,
      category: decision.category,
      withdrawnAt: decision.withdrawnAt,
      digest: digestOf(request),
      targetReference: publishedReference(request),
    },
  };
}

// A receipt accepted for an image that was withdrawn meanwhile: the registry write is kept
// on record, but the request carries the image's withdrawal straight away.
export function withdrawLatePublication(publishedRequest, jobWithdrawal, recordedAt) {
  if (publishedRequest?.status !== 'Published') {
    throw new PublishPolicyValidationError('Only a published request can be marked as withdrawn.', 409);
  }
  const timestamp = timestampOf(recordedAt);
  return {
    ...publishedRequest,
    status: 'Withdrawn',
    updatedAt: timestamp,
    withdrawal: {
      withdrawnBy: text(jobWithdrawal.withdrawnBy),
      reason: text(jobWithdrawal.reason),
      category: text(jobWithdrawal.category),
      withdrawnAt: text(jobWithdrawal.withdrawnAt),
      digest: digestOf(publishedRequest),
      targetReference: publishedReference(publishedRequest),
      publishedAfterWithdrawal: true,
      recordedAt: timestamp,
    },
  };
}

// A request of the withdrawn digest that was not published yet: closed, with the cause.
export function cancelForWithdrawnImage(request, decision) {
  if (!OPEN_PUBLISH_STATUSES.includes(request?.status)) {
    throw new PublishPolicyValidationError('Only an open publish request can be cancelled.', 409);
  }
  return {
    ...request,
    status: 'Cancelled',
    updatedAt: decision.withdrawnAt,
    cancellation: {
      cause: CANCELLED_FOR_WITHDRAWAL,
      previousStatus: request.status,
      cancelledBy: decision.withdrawnBy,
      reason: decision.reason,
      category: decision.category,
      cancelledAt: decision.withdrawnAt,
      digest: digestOf(request),
    },
  };
}

// The request a receipt is checked against. A request that was Approved when its image was
// withdrawn may already have been handed to a worker, so its receipt is still accepted (and
// recorded as published after the withdrawal). Any other cancelled request never had a
// handoff: acceptPublishReceipt refuses it.
export function receiptBaseline(request) {
  const cancellation = request?.cancellation;
  return request?.status === 'Cancelled' &&
    cancellation?.cause === CANCELLED_FOR_WITHDRAWAL &&
    cancellation?.previousStatus === 'Approved'
    ? { ...request, status: 'Approved' }
    : request;
}

// True when `job` carries a withdrawal of exactly this digest.
export function isWithdrawnDigest(job, digest) {
  const recorded = text(job?.publishWithdrawal?.digest).toLowerCase();
  return sha256Pattern.test(recorded) && recorded === text(digest).toLowerCase();
}

// The job keeps one withdrawal record for its output digest. The first record wins, so a
// repeated or concurrent withdrawal never rewrites who withdrew the image and why; later
// request IDs are only added to the record. Returns null when nothing changes.
export function applyJobWithdrawal(job, withdrawal, requestIds = []) {
  if (!job) throw new PublishPolicyValidationError('The remediation job of the published image was not found.', 409);
  const digest = text(job.patchedImageDigest).toLowerCase();
  if (!sha256Pattern.test(digest) || digest !== text(withdrawal?.digest).toLowerCase()) {
    throw new PublishPolicyValidationError(
      'The withdrawn digest is not the output digest of its remediation job; withdrawal is fail-closed.',
      409,
    );
  }
  const ids = requestIds.map(text).filter(Boolean);
  if (job.publishWithdrawal) {
    const known = Array.isArray(job.publishWithdrawal.requestIds) ? job.publishWithdrawal.requestIds : [];
    const added = [...new Set(ids.filter((id) => !known.includes(id)))];
    if (added.length === 0) return null;
    return { ...job, publishWithdrawal: { ...job.publishWithdrawal, requestIds: [...known, ...added] } };
  }
  return {
    ...job,
    publishWithdrawal: {
      digest,
      withdrawnBy: text(withdrawal.withdrawnBy),
      reason: text(withdrawal.reason),
      category: text(withdrawal.category),
      withdrawnAt: text(withdrawal.withdrawnAt),
      targetReference: text(withdrawal.targetReference),
      requestIds: [...new Set(ids)],
    },
  };
}

// The withdrawal of one digest, decided on the requests loaded (and locked) in the
// transaction: `requestId` must still be among the published requests, and all of them are
// withdrawn, the selected one first; the open requests of the digest are cancelled. Returns
// the job update (or null), the withdrawn requests and the cancelled ones.
export function decideDigestWithdrawal({ job, published, open = [], requestId, decision }) {
  const list = Array.isArray(published) ? published : [];
  if (!list.some((item) => item.id === requestId)) {
    throw new PublishPolicyValidationError('Only a published image can be withdrawn.', 409);
  }
  const requests = [...list.filter((item) => item.id === requestId), ...list.filter((item) => item.id !== requestId)].map(
    (item) => withdrawPublishedRequest(item, decision),
  );
  return {
    job: applyJobWithdrawal(job, requests[0].withdrawal, requests.map((item) => item.id)),
    requests,
    cancelled: (Array.isArray(open) ? open : []).map((item) => cancelForWithdrawnImage(item, decision)),
  };
}

// A publish receipt, decided on the request and job loaded (and locked) in the transaction.
// A receipt for an image that was withdrawn meanwhile is still recorded, as Withdrawn.
export function decidePublishReceipt({ job, request, receipt, recordedAt }) {
  const published = acceptPublishReceipt(receiptBaseline(request), receipt, recordedAt);
  if (request?.status === 'Cancelled') {
    // Cancelled because the image was withdrawn, but the worker wrote it anyway.
    const withdrawn = withdrawLatePublication(published, job?.publishWithdrawal || request.cancellation, recordedAt);
    const recorded = { ...withdrawn, cancellation: request.cancellation };
    return { request: recorded, job: applyJobWithdrawal(job, recorded.withdrawal, [recorded.id]), withdrawnLate: true };
  }
  if (!isWithdrawnDigest(job, published.source?.digest)) {
    return { request: published, job: null, withdrawnLate: false };
  }
  const withdrawn = withdrawLatePublication(published, job.publishWithdrawal, recordedAt);
  return {
    request: withdrawn,
    job: applyJobWithdrawal(job, withdrawn.withdrawal, [withdrawn.id]),
    withdrawnLate: true,
  };
}
