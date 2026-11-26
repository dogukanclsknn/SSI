import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  nodeHeredoc,
  parameterValues,
  pipelineVariable,
  runNode,
  runBash,
  stepEnv,
  stepScript,
} from './pipelineSteps.testkit.js';

const pipelineFile = new URL('../../azure-pipelines-controlled-publish.yml', import.meta.url);

describe('controlled publish worker pipeline', () => {
  it('is manual and non-mutating unless explicitly approved for execution', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toMatch(/^trigger: none$/m);
    expect(pipeline).toMatch(/^pr: none$/m);
    expect(pipeline).toContain('default: false');
    expect(pipeline).toContain('Prepare-only run completed. No registry write was attempted.');
    expect(pipeline).toContain(`if [[ "\${EXECUTE_PUBLISH}" != 'true' ]]`);
  });

  it('uses a credential-free handoff and dedicated worker-only write credentials', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toContain('X-SSI-Publish-Handoff-Token');
    expect(pipeline).toContain('PUBLISH_ROBOT_USERNAME');
    expect(pipeline).toContain('PUBLISH_ROBOT_SECRET');
    expect(pipeline).toContain('SSI_PUBLISH_RECEIPT_HMAC_SECRET');
    expect(pipeline).not.toContain('RECEIPT_TOKEN');
    expect(pipeline).not.toContain('HARBOR_ROBOT_SECRET');
    expect(pipeline).toContain('credentialMaterialIncluded');
    expect(pipeline).toContain('overwriteExistingTag');
  });

  it('prevents overwrite and verifies the target digest before reporting success', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toContain(
      'Target tag already exists with a different manifest. Controlled publish never overwrites an existing tag.',
    );
    expect(pipeline).toContain('regctl image copy');
    expect(pipeline).toContain(
      'Published target digest does not preserve the approved source manifest.',
    );
    expect(pipeline).toContain('ssi.publish-receipt/v1');
    expect(pipeline).toContain('"${RECEIPT_CURL_HEADERS[@]}"');
    expect(pipeline).toContain('cleanup_sensitive');
  });

  it('resumes a retried publish only when the target already carries the approved digest', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toContain(`if [[ "\${existing_output}" == "\${SOURCE_DIGEST}" ]]`);
    expect(pipeline).toContain(
      'Target tag already carries the approved manifest digest; resuming this publish without a registry write.',
    );
    expect(pipeline).toContain(`if [[ "\${target_already_published}" == 'true' ]]`);
  });

  it('binds the worker identity to real agent variables', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toContain('${AGENT_MACHINENAME:-unknown}');
    expect(pipeline).not.toContain('${AGENT_MACHINE}');
  });

  it('advances latest from the approved digest only after verifying the immutable publication', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');
    const script = stepScript(pipeline, 'Publish approved digest and submit receipt');
    expect(script.indexOf('LATEST_REFERENCE="${TARGET_REFERENCE%:*}:latest"')).toBeGreaterThan(
      script.indexOf('Published target digest does not preserve the approved source manifest.'),
    );
    expect(script).toContain('regctl image copy "${TARGET_REFERENCE%:*}@${target_digest}" "${LATEST_REFERENCE}"');
    expect(script).toContain('if [[ "${latest_digest}" != "${SOURCE_DIGEST}" ]]');
    expect(script).toContain('latestDigest: process.env.LATEST_DIGEST');
  });

  it('verifies the moving alias and stops on a digest mismatch', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');
    const script = stepScript(pipeline, 'Publish approved digest and submit receipt');
    const alias = script.slice(script.indexOf('LATEST_REFERENCE="'), script.indexOf('REQUEST_ID="${PUBLISH_REQUEST_ID}" \\', script.indexOf('LATEST_REFERENCE="')));
    const digest = `sha256:${'a'.repeat(64)}`;
    const setup = `set -euo pipefail
      regctl() {
        if [[ "$1 $2" == 'image copy' ]]; then
          [[ "$3" == "harbor.example/project/approved/nginx@${digest}" ]]
          [[ "$4" == 'harbor.example/project/approved/nginx:latest' ]]
        elif [[ "$1 $2" == 'image digest' ]]; then
          printf '%s' "$RESOLVED_DIGEST"
        else return 99; fi
      }
    `;
    const env = { TARGET_REFERENCE: 'harbor.example/project/approved/nginx:versioned', SOURCE_DIGEST: digest, target_digest: digest };
    expect(runBash(setup + alias, { ...env, RESOLVED_DIGEST: digest }).ok).toBe(true);
    expect(runBash(setup + alias, { ...env, RESOLVED_DIGEST: `sha256:${'b'.repeat(64)}` })).toMatchObject({
      ok: false, status: 5,
    });
  });
});

describe('controlled publish worker boundary', () => {
  const pipeline = readFileSync(pipelineFile, 'utf8');
  const FETCH_STEP = 'Fetch and validate approved publish handoff';
  const PUBLISH_STEP = 'Publish approved digest and submit receipt';
  const DIGEST = `sha256:${'c'.repeat(64)}`;
  let directory;

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  // The shape src/lib/publishPolicy.js buildPublishWorkerHandoff produces.
  function handoff(target = {}, source = {}) {
    const next = {
      registry: 'registry.example.com',
      project: 'ssi-images',
      repository: 'approved/nginx',
      tag: 'verified-20261117-alpine-r1',
      ...target,
    };
    return {
      contractVersion: 'ssi.publish-handoff/v1',
      requestId: 'PUB-0042',
      generatedAt: '2026-11-17T09:00:00.000Z',
      policy: { version: 'ssi.publish-policy/v1.4', decision: 'Approved', approvedBy: 'approver', approvedAt: '2026-11-17T08:59:00.000Z' },
      source: {
        immutableReference: `registry.example.com/ssi-images/onboarded/nginx@${DIGEST}`,
        digest: DIGEST,
        verificationEvidenceDigest: `sha256:${'d'.repeat(64)}`,
        ...source,
      },
      target: { ...next, tagReference: `${next.registry}/${next.project}/${next.repository}:${next.tag}` },
      constraints: {
        credentialMaterialIncluded: false,
        overwriteExistingTag: false,
        preserveManifestDigest: true,
        verifyTargetDigest: true,
      },
    };
  }

  function validate(document, pinned = true) {
    directory = mkdtempSync(join(tmpdir(), 'ssi-publish-handoff-'));
    const file = join(directory, 'publish-handoff.json');
    writeFileSync(file, JSON.stringify(document));
    const env = { HANDOFF_FILE: file, EXPECTED_REQUEST_ID: document.requestId };
    if (pinned) {
      env.EXPECTED_TARGET_REGISTRY = pipelineVariable(pipeline, 'SSI_PUBLISH_TARGET_REGISTRY');
      env.EXPECTED_TARGET_PROJECT = pipelineVariable(pipeline, 'SSI_PUBLISH_TARGET_PROJECT');
      env.EXPECTED_TARGET_PREFIX = pipelineVariable(pipeline, 'SSI_PUBLISH_TARGET_PREFIX');
    }
    const result = runNode(nodeHeredoc(stepScript(pipeline, FETCH_STEP)), env);
    return result.ok ? '' : result.output;
  }

  it('accepts only the SSI addresses listed in the pipeline', () => {
    expect(parameterValues(pipeline, 'ssiApiBaseUrl')).toEqual([
      'http://10.0.0.10:5021/api/v1',
      'http://ssi.example.com/api/v1',
    ]);
  });

  it('pins the approved catalog in the fixed variables block and maps it into both steps', () => {
    expect(pipelineVariable(pipeline, 'SSI_PUBLISH_TARGET_REGISTRY')).toBe('registry.example.com');
    expect(pipelineVariable(pipeline, 'SSI_PUBLISH_TARGET_PROJECT')).toBe('ssi-images');
    expect(pipelineVariable(pipeline, 'SSI_PUBLISH_TARGET_PREFIX')).toBe('approved');
    expect(stepEnv(pipeline, FETCH_STEP)).toMatchObject({
      SSI_PUBLISH_TARGET_REGISTRY: '$(SSI_PUBLISH_TARGET_REGISTRY)',
      SSI_PUBLISH_TARGET_PROJECT: '$(SSI_PUBLISH_TARGET_PROJECT)',
      SSI_PUBLISH_TARGET_PREFIX: '$(SSI_PUBLISH_TARGET_PREFIX)',
    });
    expect(stepEnv(pipeline, PUBLISH_STEP)).toMatchObject({
      SSI_PUBLISH_TARGET_REGISTRY: '$(SSI_PUBLISH_TARGET_REGISTRY)',
    });
  });

  it("accepts an approved handoff, including a team's approved folder", () => {
    expect(validate(handoff())).toBe('');
    expect(validate(handoff({ repository: 'approved/payments/api' }))).toBe('');
  });

  it('refuses a handoff that would write outside the approved catalog', () => {
    expect(validate(handoff({ registry: 'registry.attacker.example' }))).toContain(
      'Publish target registry must be registry.example.com.',
    );
    expect(validate(handoff({ project: 'other-project' }))).toContain(
      'Publish target project must be ssi-images.',
    );
    for (const repository of ['onboarded/nginx', 'approved', 'approved/../onboarded/x', 'approved/Nginx']) {
      expect(validate(handoff({ repository }))).toContain('Publish target must be a repository under approved/.');
    }
  });

  it('refuses a source that lives on another registry', () => {
    expect(
      validate(handoff({}, { immutableReference: `registry.attacker.example/evil/image@${DIGEST}` })),
    ).toContain('Publish source must be on registry.example.com.');
  });

  it('accepts latest only within the same approved repository', () => {
    const latestReference = 'registry.example.com/ssi-images/approved/nginx:latest';
    expect(validate(handoff({ latestReference }))).toBe('');
    expect(validate(handoff({ latestReference: 'registry.attacker.example/evil:latest' }))).toContain(
      'Latest alias must stay in the approved target repository.',
    );
  });

  it('stops when the pinned target is missing', () => {
    expect(validate(handoff(), false)).toContain('The pinned publish target is not configured in this pipeline.');
  });

  it('checks the registry again right before the publish step logs in', () => {
    const script = stepScript(pipeline, PUBLISH_STEP);
    const check = script.indexOf('"${TARGET_REGISTRY}" != "${SSI_PUBLISH_TARGET_REGISTRY}"');
    expect(check).toBeGreaterThan(-1);
    expect(check).toBeLessThan(script.indexOf('regctl registry login'));
  });
});
