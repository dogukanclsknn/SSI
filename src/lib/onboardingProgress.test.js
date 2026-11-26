import { describe, expect, it } from 'vitest';
import { onboardingProgress, parseTimelineProgress } from './onboardingProgress.js';

describe('onboarding progress', () => {
  it('uses real task completion and excludes skipped work', () => {
    expect(parseTimelineProgress({ records: [
      { type: 'Job', state: 'inProgress' },
      { type: 'Task', state: 'completed' },
      { type: 'Task', state: 'inProgress', percentComplete: 50, name: 'Copy image' },
      { type: 'Task', state: 'pending' },
      { type: 'Task', state: 'completed', result: 'skipped' },
    ] })).toEqual({ percent: 50, currentStep: 'Copy image' });
    expect(parseTimelineProgress({})).toMatchObject({ percent: null });
  });
  it('does not claim import completion after a prepare-only check', () => {
    expect(onboardingProgress({ status: 'Importing' }, [{ action: 'onboard-check', state: 'completed', result: 'succeeded' }]))
      .toMatchObject({ percent: 25, stage: 'Check passed — ready to start import' });
  });
  it('waits for the SSI receipt even when the worker succeeded', () => {
    const run = { action: 'onboard-import', state: 'completed', result: 'succeeded' };
    expect(onboardingProgress({ status: 'Importing' }, [run]).percent).toBe(95);
    expect(onboardingProgress({ status: 'Imported' }, [run]).percent).toBe(100);
  });
  it('shows missing telemetry and failed or cancelled imports without a fake percentage', () => {
    expect(onboardingProgress({ status: 'Importing' }, [{ action: 'onboard-import', state: 'inProgress' }]).percent).toBeNull();
    expect(onboardingProgress({ status: 'Importing' }, [{ action: 'onboard-import', state: 'completed', result: 'failed' }]).tone).toBe('error');
    expect(onboardingProgress({ status: 'Cancelled' }).percent).toBeNull();
  });
});
