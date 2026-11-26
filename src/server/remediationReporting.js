import { selectCurrentPublishRequest } from '../lib/publishGateView.js';

const severityKeys = ['critical', 'high', 'medium', 'low'];

function totalFindings(summary) {
  const counts = summary && typeof summary === 'object' ? summary : {};
  return [...severityKeys, 'unknown'].reduce((total, key) => total + (Number(counts[key]) || 0), 0);
}

function isoWeek(dateValue) {
  const date = new Date(dateValue);
  if (Number.isNaN(date.getTime())) return 'Unknown';
  const utc = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const day = utc.getUTCDay() || 7;
  utc.setUTCDate(utc.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(utc.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((utc - yearStart) / 86400000 + 1) / 7);
  return `${utc.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
}

function historyItem(job, publishRequest) {
  const before = totalFindings(job.before);
  const after = totalFindings(job.after);
  const isVerified = String(job.status).toLowerCase() === 'verified';

  return {
    id: job.id,
    image: job.image || job.scanReportId || '-',
    engine: job.engineVersion ? `${job.engine || 'Copacetic'} ${job.engineVersion}` : job.engine || 'Copacetic',
    cvesFixed: isVerified ? job.fixed?.length || Math.max(before - after, 0) : 0,
    before,
    after: isVerified ? after : before,
    at: job.verifiedAt || job.createdAt || '',
    status: job.status || 'Unknown',
    sourceDigest: job.sourceDigest || '',
    outputDigest: job.patchedImageDigest || '',
    publishStatus: job.publishWithdrawal ? 'Withdrawn' : publishRequest?.status || job.publishGate?.status || 'Not evaluated',
    publishRequestId: publishRequest?.id || '',
    publishTarget: publishRequest?.target?.tagReference || '',
  };
}

export function buildRemediationReport(jobs = [], publishRequests = []) {
  // Same selection as the Remediation screen and the report document: a published job
  // stays "Published" even when a newer request for it is still waiting for approval.
  const history = jobs.map((job) => historyItem(job, selectCurrentPublishRequest({ job, publishRequests })));
  const verified = jobs.filter((job) => String(job.status).toLowerCase() === 'verified');
  const weekly = new Map();

  for (const job of verified) {
    const week = isoWeek(job.verifiedAt || job.createdAt);
    const current = weekly.get(week) || { week, critical: 0, high: 0, medium: 0 };
    for (const key of ['critical', 'high', 'medium']) {
      current[key] += Number(job.after?.[key]) || 0;
    }
    weekly.set(week, current);
  }

  return {
    generatedAt: new Date().toISOString(),
    summary: {
      totalJobs: jobs.length,
      verifiedJobs: verified.length,
      plannedJobs: jobs.filter((job) => String(job.status).toLowerCase() === 'planned').length,
      blockedJobs: jobs.filter((job) => String(job.status).toLowerCase() === 'blocked').length,
      cvesRemediated: verified.reduce((total, job) => total + (job.fixed?.length || 0), 0),
      publishBlocked: jobs.filter((job) => String(job.publishGate?.status).toLowerCase() === 'blocked').length,
      publishRequests: publishRequests.length,
      policyBlocked: publishRequests.filter((request) => request.status === 'Blocked').length,
      approvalRequired: publishRequests.filter((request) => request.status === 'ApprovalRequired').length,
      approvedForPublish: publishRequests.filter((request) => request.status === 'Approved').length,
      published: publishRequests.filter((request) => request.status === 'Published').length,
      rejected: publishRequests.filter((request) => request.status === 'Rejected').length,
      withdrawn: publishRequests.filter((request) => request.status === 'Withdrawn').length,
    },
    history,
    trend: [...weekly.values()].sort((left, right) => left.week.localeCompare(right.week)).slice(-8),
  };
}
