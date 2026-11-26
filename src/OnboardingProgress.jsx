import { useEffect, useState } from 'react';
import { getRecordPipelineRuns } from './lib/api.js';
import { onboardingProgress } from './lib/onboardingProgress.js';

export function OnboardingProgress({ request }) {
  const [live, setLive] = useState(null);
  const open = ['Requested', 'Importing'].includes(request.status);
  useEffect(() => {
    if (!open) return undefined;
    let cancelled = false;
    let timer;
    async function refresh() {
      const result = await getRecordPipelineRuns('onboarding', request.id);
      if (cancelled) return;
      setLive(result.error ? { percent: null, stage: 'Progress unavailable', error: result.error } : result.data.progress);
      timer = setTimeout(refresh, 15000);
    }
    refresh();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [request.id, request.updatedAt, open]);
  const progress = (open && live) || onboardingProgress(request);
  return (
    <div className={`ingest-progress ${progress.tone || ''}`}>
      <div><span>{progress.stage}</span><b>{progress.percent == null ? '—' : `${progress.percent}%`}</b></div>
      <progress aria-label={`Import workflow progress for ${request.id}`} max="100" {...(progress.percent == null ? {} : { value: progress.percent })} />
      <small>{progress.error || 'Step completion · check → copy / scan → receipt'}</small>
    </div>
  );
}
