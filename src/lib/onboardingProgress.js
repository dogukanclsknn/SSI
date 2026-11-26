// Workflow progress from Azure DevOps task completion, never elapsed time or bytes.
export function parseTimelineProgress(document) {
  const tasks = (Array.isArray(document?.records) ? document.records : [])
    .filter((item) => item.type === 'Task' && item.result !== 'skipped');
  if (!tasks.length) return { percent: null, currentStep: 'Waiting for an agent' };
  const completed = tasks.filter((item) => item.state === 'completed').length;
  const active = tasks.find((item) => item.state === 'inProgress');
  const knownOperations = [
    'Resolving source digest', 'Copying image to Harbor quarantine',
    'Verifying imported digest', 'Scanning imported image with Trivy',
    'Submitting signed import receipt',
  ];
  const partial = active && Number.isFinite(active.percentComplete)
    ? Math.max(0, Math.min(100, active.percentComplete)) / 100 : 0;
  return {
    percent: Math.floor(100 * (completed + partial) / tasks.length),
    currentStep: String((knownOperations.includes(active?.currentOperation) && active.currentOperation) || active?.name || tasks.find((item) => item.state !== 'completed')?.name || 'Worker finished').slice(0, 200),
  };
}

export function onboardingProgress(request, runs = [], timeline = null) {
  if (request.status === 'Imported') return { percent: 100, stage: 'Imported into quarantine', tone: 'success' };
  if (['Failed', 'Cancelled'].includes(request.status)) {
    return { percent: null, stage: request.status === 'Failed' ? 'Import failed' : 'Import cancelled', tone: 'error' };
  }
  const run = runs.find((item) => ['onboard-check', 'onboard-import'].includes(item.action));
  if (!run) return { percent: 0, stage: 'Waiting for import check', tone: 'waiting' };
  const importing = run.action === 'onboard-import';
  if (run.state === 'completed') {
    if (run.result !== 'succeeded') return { percent: null, stage: importing ? 'Import worker failed — open its run' : 'Import check failed — open its run', tone: 'error' };
    return importing
      ? { percent: 95, stage: 'Worker finished — awaiting import receipt', tone: 'waiting' }
      : { percent: 25, stage: 'Check passed — ready to start import', tone: 'waiting' };
  }
  return {
    percent: timeline?.percent == null ? null : Math.min(94, Math.floor((importing ? 25 : 0) + timeline.percent * (importing ? 0.7 : 0.25))),
    stage: `${importing ? 'Copy to Harbor / scan' : 'Import check'} · ${timeline?.currentStep || 'Waiting for worker status'}`,
    tone: 'active',
  };
}
