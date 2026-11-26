import { describe, expect, it } from 'vitest';
import { PipelineRunError } from './pipelineRuns.js';
import {
  parseScanReference,
  planInspectionRun,
  planOnboardingRun,
  planPublishRun,
  workerActionsView,
  workerApiParameters,
} from './workerPipelineActions.js';

const DIGEST = `sha256:${'b'.repeat(64)}`;
const SOURCE = `sha256:${'a'.repeat(64)}`;
const API = 'http://10.0.0.10:5021/api/v1';
const succeeded = (action, role) => ({
  action,
  role,
  runId: 7,
  state: 'completed',
  result: 'succeeded',
});

const refused = (fn, pattern) => {
  let caught;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(PipelineRunError);
  expect(caught.message).toMatch(pattern);
};

describe('workerApiParameters', () => {
  it('sends the configured address and allows HTTP only when it was configured as HTTP', () => {
    expect(workerApiParameters(API)).toEqual({ ssiApiBaseUrl: API, allowInsecurePocApi: true });
    expect(workerApiParameters('https://ssi.example/api/v1').allowInsecurePocApi).toBe(false);
    refused(() => workerApiParameters(''), /SSI_ADO_WORKER_API_BASE_URL/);
  });
});

describe('planOnboardingRun', () => {
  const request = { id: 'ONB-0009', status: 'Requested' };

  it('checks first and imports only after a succeeded check', () => {
    expect(
      planOnboardingRun(request, 'onboard-check', { workerApiBaseUrl: API }).templateParameters,
    ).toEqual({
      onboardingRequestId: 'ONB-0009',
      ssiApiBaseUrl: API,
      allowInsecurePocApi: true,
      executeImport: false,
    });
    refused(
      () => planOnboardingRun(request, 'onboard-import', { workerApiBaseUrl: API }),
      /import check/,
    );
    const checked = {
      ...request,
      status: 'Importing',
      pipelineRuns: [succeeded('onboard-check', 'onboardImport')],
    };
    expect(
      planOnboardingRun(checked, 'onboard-import', { workerApiBaseUrl: API }).templateParameters
        .executeImport,
    ).toBe(true);
  });

  it('refuses a closed request and an action of another record', () => {
    refused(
      () =>
        planOnboardingRun({ ...request, status: 'Cancelled' }, 'onboard-check', {
          workerApiBaseUrl: API,
        }),
      /Cancelled/,
    );
    refused(
      () => planOnboardingRun(request, 'publish-check', { workerApiBaseUrl: API }),
      /Unknown/,
    );
  });
});

describe('planPublishRun', () => {
  const approved = {
    id: 'PUB-0011',
    jobId: 'RM-EXEC-0005',
    status: 'Approved',
    source: { digest: DIGEST },
    target: { project: 'ssi-images', repository: 'approved/nginx', tag: 'alpine-r1' },
  };
  const options = {
    workerApiBaseUrl: API,
    harborProject: 'ssi-images',
    job: { sourceDigest: SOURCE },
  };

  it('publishes an approved request only after a succeeded check', () => {
    expect(planPublishRun(approved, 'publish-check', options).templateParameters).toEqual({
      publishRequestId: 'PUB-0011',
      ssiApiBaseUrl: API,
      allowInsecurePocApi: true,
      executePublish: false,
    });
    refused(() => planPublishRun(approved, 'publish-execute', options), /publish check/);
    const checked = {
      ...approved,
      pipelineRuns: [succeeded('publish-check', 'controlledPublish')],
    };
    expect(
      planPublishRun(checked, 'publish-execute', options).templateParameters.executePublish,
    ).toBe(true);
  });

  it('never publishes a request that is not approved', () => {
    for (const status of ['ApprovalRequired', 'Blocked', 'Rejected', 'Withdrawn']) {
      refused(
        () => planPublishRun({ ...approved, status }, 'publish-check', options),
        /approved publish request/,
      );
    }
    refused(
      () => planPublishRun({ ...approved, status: 'Published' }, 'publish-check', options),
      /already published/,
    );
  });

  it('signs exactly what was published, with the job source digest for provenance', () => {
    const published = { ...approved, status: 'Published' };
    expect(planPublishRun(published, 'supply-chain-sign', options).templateParameters).toEqual({
      approvedRepository: 'approved/nginx',
      approvedDigest: DIGEST,
      remediationJobId: 'RM-EXEC-0005',
      sourceDigest: SOURCE,
      postToSsi: true,
      ssiApiBaseUrl: API,
      allowInsecurePocApi: true,
    });
    refused(() => planPublishRun(approved, 'supply-chain-sign', options), /published image/);
    refused(
      () =>
        planPublishRun(
          { ...published, target: { ...published.target, project: 'other' } },
          'supply-chain-sign',
          options,
        ),
      /outside the Harbor project/,
    );
  });
});

describe('image inspection', () => {
  it('addresses the scanned image by digest under the worker project', () => {
    expect(
      parseScanReference(`ssi-images/onboarded/nginx@${DIGEST}`, 'ssi-images')
        .repository,
    ).toBe('onboarded/nginx');
    expect(
      planInspectionRun(`ssi-images/onboarded/nginx@${DIGEST}`, {
        harborProject: 'ssi-images',
        registryHost: 'registry.example.com',
      }).templateParameters,
    ).toEqual({
      imageReference: `registry.example.com/ssi-images/onboarded/nginx@${DIGEST}`,
      deliverToSsi: true,
    });
    refused(
      () => parseScanReference('ssi-images/nginx:alpine', 'ssi-images'),
      /sha256/,
    );
    refused(
      () => parseScanReference(`other/nginx@${DIGEST}`, 'ssi-images'),
      /Harbor project/,
    );
  });
});

describe('workerActionsView', () => {
  it('explains why each action cannot start and asks to confirm registry writes', () => {
    const request = { id: 'PUB-1', status: 'Approved', pipelineRuns: [] };
    const view = workerActionsView('publish', request, {
      enabled: true,
      pipelines: { controlledPublish: 4441, supplyChainSign: 4522 },
      plan: (action) =>
        planPublishRun(request, action, {
          workerApiBaseUrl: API,
          harborProject: 'ssi-images',
        }),
    });
    expect(
      view.actions.map(({ action, available, confirm }) => [action, available, confirm]),
    ).toEqual([
      ['publish-check', true, false],
      ['publish-execute', false, true],
      ['supply-chain-sign', false, true],
    ]);
    const off = workerActionsView('publish', request, { enabled: false, plan: () => ({}) });
    expect(off.actions.every((item) => /not configured/.test(item.reason))).toBe(true);
  });
});
