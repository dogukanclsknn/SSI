// Publish gate etiketinin okuma tarafında türetilmesi.
//
// remediationEvidence.js'in ürettiği job.publishGate, kanıtın oluşturulduğu andaki
// gerçeği taşır ve değiştirilmez (immutable kanıt). Ancak controlled publish akışı
// sonradan aynı output digest'i onaylayıp yayınlayabilir. Bu yüzden UI, gate
// durumunu kanıt anına değil güncel publish request'lerine bakarak gösterir.
//
// Saf fonksiyon: state, fetch veya React bağımlılığı yoktur.

const digestPattern = /^sha256:[a-f0-9]{64}$/;

// Publish request durumları en ileri aşamadan geriye doğru sıralıdır. A withdrawal is final
// for the image, so it outranks everything; a rejected request is the weakest signal.
const STATUS_PRECEDENCE = ['Withdrawn', 'Published', 'Approved', 'ApprovalRequired', 'Blocked', 'Rejected'];

function normalizeDigest(value) {
  return String(value || '').trim().toLowerCase();
}

// 2026-11-09T10:00:00.000Z → "2026-11-09 10:00 UTC" (the report document has no local time zone).
function utcMinute(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'an unknown date' : `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

function evidenceGateView(job) {
  const gate = job?.publishGate || null;

  return {
    status: gate?.status || 'Blocked',
    label: gate?.allowed ? 'Publish allowed' : 'Publish blocked',
    tone: gate?.allowed ? 'allowed' : 'blocked',
    reason: gate?.reason || 'Patched image is not approved for central publish yet.',
    request: null,
  };
}

// The publish request that represents a job's publish state: among the requests for the
// job (or for its output digest) the most advanced one wins, so a later pending request
// never hides an earlier completed publish. Null when the job has no publish request.
// Single source of truth for the Remediation screen, the report document and Reports.
export function selectCurrentPublishRequest({ job, publishRequests = [] } = {}) {
  if (!job?.id) return null;
  const outputDigest = normalizeDigest(job.patchedImageDigest);
  const related = (Array.isArray(publishRequests) ? publishRequests : []).filter(
    (request) =>
      request?.jobId === job.id ||
      (digestPattern.test(outputDigest) && normalizeDigest(request?.source?.digest) === outputDigest),
  );
  if (related.length === 0) return null;
  return (
    STATUS_PRECEDENCE.map((status) => related.find((request) => request.status === status)).find(Boolean) ||
    related[0]
  );
}

// Bir verified remediation job'ı için gösterilecek publish gate görünümünü döndürür.
export function derivePublishGateView({ job, publishRequests = [] } = {}) {
  if (!job?.id) {
    return evidenceGateView(job);
  }

  const current = selectCurrentPublishRequest({ job, publishRequests });
  // The job's withdrawal record is authoritative for its digest, even when no request is
  // loaded (e.g. a filtered list).
  const withdrawal = job.publishWithdrawal || (current?.status === 'Withdrawn' ? current.withdrawal : null);
  if (withdrawal) {
    const reference = String(withdrawal.targetReference || current?.target?.tagReference || '').trim();
    const reason = String(withdrawal.reason || 'no reason recorded').trim().replace(/[.\s]+$/, '');
    return {
      status: 'Withdrawn',
      label: 'Withdrawn',
      tone: 'withdrawn',
      reason:
        `Withdrawn by ${withdrawal.withdrawnBy || 'unknown'} on ${utcMinute(withdrawal.withdrawnAt)}` +
        `${reference ? ` (${reference})` : ''}: ${reason}. ` +
        'Do not use this image; it can no longer be published.',
      request: current,
      withdrawal,
    };
  }

  if (!current) {
    return evidenceGateView(job);
  }

  if (current.status === 'Published') {
    const reference = String(
      current.publish?.receipt?.targetReference || current.target?.tagReference || '',
    ).trim();

    return {
      status: 'Published',
      label: 'Published',
      tone: 'published',
      reason: reference
        ? `Approved central publish completed: ${reference} (${current.id}).`
        : `Approved central publish completed (${current.id}).`,
      request: current,
    };
  }

  if (current.status === 'Approved') {
    return {
      status: 'Approved',
      label: 'Publish approved',
      tone: 'allowed',
      reason: `Publish request ${current.id} is approved; waiting for the isolated worker to write to the registry.`,
      request: current,
    };
  }

  if (current.status === 'ApprovalRequired') {
    return {
      status: 'ApprovalRequired',
      label: 'Approval required',
      tone: 'pending',
      reason: `Publish request ${current.id} passed the policy checks; waiting for a separate approver.`,
      request: current,
    };
  }

  if (current.status === 'Rejected') {
    return {
      status: 'Rejected',
      label: 'Publish rejected',
      tone: 'blocked',
      reason: `Publish request ${current.id} was rejected by ${current.rejection?.rejectedBy || 'an approver'}: ${
        current.rejection?.reason || 'no reason recorded'
      }`,
      request: current,
    };
  }

  return {
    status: 'Blocked',
    label: 'Publish blocked',
    tone: 'blocked',
    reason: `Publish request ${current.id} was blocked by policy.`,
    request: current,
  };
}
