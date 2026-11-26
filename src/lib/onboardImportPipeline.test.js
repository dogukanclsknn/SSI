import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { buildOnboardingRequest, buildOnboardingWorkerHandoff } from './onboarding.js';
import {
  nodeHeredoc,
  parameterValues,
  pipelineVariable,
  runNode,
  stepEnv,
  stepScript,
} from './pipelineSteps.testkit.js';

const pipeline = readFileSync(
  new URL('../../azure-pipelines-onboard-import.yml', import.meta.url),
  'utf8',
);

// The retry helper is defined once per script step (steps do not share shell state).
function retryHelpers() {
  return [...pipeline.matchAll(/^ {14}ssi_api_call\(\) \{\n[\s\S]*?^ {14}\}$/gm)].map((match) =>
    match[0].replace(/^ {14}/gm, ''),
  );
}

// Runs the helper against a stubbed curl that replays `outcomes` ("exit:http" per call).
// curl runs inside a command substitution, so the call count lives in a file.
function runHelper(outcomes) {
  const script = `
set -euo pipefail
counter="$(mktemp)"
trap 'rm -f "$counter"' EXIT
echo 0 > "$counter"
outcomes=(${outcomes.map((outcome) => `'${outcome}'`).join(' ')})
sleep() { :; }
curl() {
  local calls
  calls="$(cat "$counter")"
  echo $((calls + 1)) > "$counter"
  local outcome="\${outcomes[$calls]}"
  printf '%s' "\${outcome#*:}"
  return "\${outcome%%:*}"
}
${retryHelpers()[0]}
status="$(ssi_api_call /dev/null https://ssi.example/api/v1/x 2>/dev/null)"
printf '%s %s' "$status" "$(cat "$counter")"
`;
  const [status, calls] = execFileSync('bash', ['-c', script], { encoding: 'utf8' })
    .trim()
    .split(/\s+/);
  return { status, calls: Number(calls) };
}

describe('onboarding import worker pipeline', () => {
  it('is manual and non-mutating unless execution is explicitly requested', () => {
    expect(pipeline).toMatch(/^trigger: none$/m);
    expect(pipeline).toMatch(/^pr: none$/m);
    expect(pipeline).toContain(
      'Prepare-only run completed. No pull or registry write was attempted.',
    );
  });

  it('sends every SSI API call through the retrying helper in both steps', () => {
    expect(retryHelpers()).toHaveLength(2);
    expect(retryHelpers()[0]).toBe(retryHelpers()[1]);
    expect(pipeline).not.toMatch(
      /curl --silent --show-error[^\n]*\n[^\n]*--connect-timeout 5 --max-time 20/,
    );
    expect(pipeline.match(/ssi_api_call (?:"|\/dev\/null)/g)).toHaveLength(3);
  });

  it('retries transient connection timeouts and returns the first definite answer', () => {
    expect(runHelper(['28:000', '28:000', '0:200'])).toEqual({ status: '200', calls: 3 });
    expect(runHelper(['7:000', '0:503', '0:200'])).toEqual({ status: '200', calls: 3 });
  });

  it('never retries a definite client or server answer', () => {
    expect(runHelper(['0:403'])).toEqual({ status: '403', calls: 1 });
    expect(runHelper(['0:422'])).toEqual({ status: '422', calls: 1 });
    expect(runHelper(['0:500'])).toEqual({ status: '500', calls: 1 });
    expect(runHelper(['60:000'])).toEqual({ status: '000', calls: 1 });
  });

  it('gives up after five attempts and reports the last status', () => {
    expect(runHelper(['28:000', '28:000', '28:000', '28:000', '28:000', '0:200'])).toEqual({
      status: '000',
      calls: 5,
    });
  });

  it('tells the operator how to recover when the receipt cannot be delivered', () => {
    expect(pipeline).toContain(
      'The image is already in quarantine. Re-run this pipeline with the same request ID: it resumes without a registry write and resubmits the receipt.',
    );
  });
});

describe('onboarding import worker boundary', () => {
  const FETCH_STEP = 'Fetch and validate onboarding handoff';
  const IMPORT_STEP = 'Import external image into quarantine and submit receipt';
  let directory;

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  // The handoff SSI really builds for an onboarding request.
  function ssiHandoff({ prefix = 'onboarded' } = {}) {
    return buildOnboardingWorkerHandoff(
      buildOnboardingRequest({
        id: 'ONB-0042',
        sourceReference: 'docker.io/library/nginx:alpine',
        target: { registry: 'registry.example.com', project: 'ssi-images', repositoryPrefix: prefix },
        requestedBy: 'operator',
        createdAt: '2026-11-17T09:00:00Z',
        allowedRegistries: ['docker.io'],
      }),
    );
  }

  // Runs the step's handoff validation exactly as the agent does, with the pinned variables.
  function validate(handoff, pinned = true) {
    directory = mkdtempSync(join(tmpdir(), 'ssi-onboard-handoff-'));
    const file = join(directory, 'onboard-handoff.json');
    writeFileSync(file, JSON.stringify(handoff));
    const env = { HANDOFF_FILE: file, EXPECTED_REQUEST_ID: handoff.requestId };
    if (pinned) {
      env.EXPECTED_TARGET_REGISTRY = pipelineVariable(pipeline, 'SSI_ONBOARD_TARGET_REGISTRY');
      env.EXPECTED_TARGET_PROJECT = pipelineVariable(pipeline, 'SSI_ONBOARD_TARGET_PROJECT');
      env.EXPECTED_TARGET_PREFIX = pipelineVariable(pipeline, 'SSI_ONBOARD_TARGET_PREFIX');
    }
    const result = runNode(nodeHeredoc(stepScript(pipeline, FETCH_STEP)), env);
    return result.ok ? '' : result.output;
  }

  const retarget = (handoff, target) => {
    const next = { ...handoff.target, ...target };
    return {
      ...handoff,
      target: { ...next, tagReference: `${next.registry}/${next.project}/${next.repository}:${next.tag}` },
    };
  };

  it('accepts only the SSI addresses listed in the pipeline', () => {
    expect(parameterValues(pipeline, 'ssiApiBaseUrl')).toEqual([
      'http://10.0.0.10:5021/api/v1',
      'http://ssi.example.com/api/v1',
    ]);
  });

  it('pins the quarantine target and the scanner image in the fixed variables block', () => {
    expect(pipelineVariable(pipeline, 'SSI_ONBOARD_TARGET_REGISTRY')).toBe('registry.example.com');
    expect(pipelineVariable(pipeline, 'SSI_ONBOARD_TARGET_PROJECT')).toBe('ssi-images');
    expect(pipelineVariable(pipeline, 'SSI_ONBOARD_TARGET_PREFIX')).toBe('onboarded');
    expect(pipelineVariable(pipeline, 'TRIVY_IMAGE')).toMatch(/@sha256:[a-f0-9]{64}$/);
    expect(stepEnv(pipeline, FETCH_STEP)).toMatchObject({
      SSI_ONBOARD_TARGET_REGISTRY: '$(SSI_ONBOARD_TARGET_REGISTRY)',
      SSI_ONBOARD_TARGET_PROJECT: '$(SSI_ONBOARD_TARGET_PROJECT)',
      SSI_ONBOARD_TARGET_PREFIX: '$(SSI_ONBOARD_TARGET_PREFIX)',
    });
    expect(stepEnv(pipeline, IMPORT_STEP)).toMatchObject({
      SSI_ONBOARD_TARGET_REGISTRY: '$(SSI_ONBOARD_TARGET_REGISTRY)',
    });
  });

  it("accepts SSI's own handoff, including a team's nested quarantine folder", () => {
    expect(validate(ssiHandoff())).toBe('');
    expect(validate(ssiHandoff({ prefix: 'onboarded/payments' }))).toBe('');
  });

  it('refuses a handoff that points the write credential anywhere else', () => {
    const handoff = ssiHandoff();
    expect(validate(retarget(handoff, { registry: 'registry.attacker.example' }))).toContain(
      'Onboarding target registry must be registry.example.com.',
    );
    expect(validate(retarget(handoff, { project: 'other-project' }))).toContain(
      'Onboarding target project must be ssi-images.',
    );
    for (const repository of ['approved/nginx', 'nginx', 'onboarded/../approved/nginx', 'onboarded//nginx', 'onboarded/Nginx']) {
      expect(validate(retarget(handoff, { repository }))).toContain(
        'Onboarding target must be a repository under onboarded/.',
      );
    }
  });

  it('stops before using a credential when the pinned target is missing', () => {
    expect(validate(ssiHandoff(), false)).toContain(
      'The pinned onboarding target is not configured in this pipeline.',
    );
  });

  it('checks the registry again right before the import step logs in', () => {
    const script = stepScript(pipeline, IMPORT_STEP);
    expect(script.indexOf('"${TARGET_REGISTRY}" != "${SSI_ONBOARD_TARGET_REGISTRY}"')).toBeGreaterThan(-1);
    expect(script.indexOf('"${TARGET_REGISTRY}" != "${SSI_ONBOARD_TARGET_REGISTRY}"')).toBeLessThan(
      script.indexOf('regctl registry login'),
    );
  });
});
