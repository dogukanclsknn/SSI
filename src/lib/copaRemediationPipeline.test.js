import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { runBash, stepScript } from './pipelineSteps.testkit.js';

const pipelineFile = new URL('../../azure-pipelines-copa-remediation-poc.yml', import.meta.url);

describe('Copa remediation PoC pipeline', () => {
  it('is manual and defaults to a non-mutating prepare-only run', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toMatch(/^trigger: none$/m);
    expect(pipeline).toMatch(/^pr: none$/m);
    expect(pipeline).toContain('default: false');
    expect(pipeline).toContain("if [[ \"${EXECUTE_REMEDIATION}\" != 'true' ]]; then");
    expect(pipeline).toContain('Prepare-only run completed. No Copa patch, registry write, or re-scan was attempted.');
    expect(pipeline).toContain("sourceMutation: 'forbidden'");
    expect(pipeline).toContain('approvedPublishAttempted: false');
  });

  it('requires an audited OS-only canonical input before a patch can run', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toContain('Download canonical Trivy JSON artifact');
    expect(pipeline).toContain('canonical-trivy-os-report');
    expect(pipeline).toContain('Canonical report content digest does not match the approved receipt.');
    expect(pipeline).toContain('Canonical report bytes changed after input validation. Refusing to continue.');
    expect(pipeline).toContain('Expected exactly one canonical-trivy.json');
    expect(pipeline).toContain('Canonical input must be SchemaVersion 2');
    expect(pipeline).toContain("--build-arg 'pkg-types=os'");
    expect(pipeline).toContain('--build-context "report=${REPORT_CONTEXT}"');
  });

  it('uses an isolated registry bridge and verifies only a dedicated PoC tag', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toContain('docker buildx create');
    expect(pipeline).toContain('--driver docker-container');
    expect(pipeline).toContain('--buildkitd-config');
    expect(pipeline).toContain('--cacert "${CA_FILE}"');
    expect(pipeline).toContain("--publish '127.0.0.1::5000'");
    expect(pipeline).toContain("HARBOR_USERNAME=\"$(printf '%s' \"${HARBOR_USERNAME_RAW}\"");
    expect(pipeline).toContain('--username "${HARBOR_USERNAME}"');
    expect(pipeline).toContain('--user "${HARBOR_USERNAME}"');
    expect(pipeline).toContain('Validating authenticated access to the immutable Harbor source.');
    expect(pipeline).toContain('REGCTL_SOURCE_DIGEST="$(regctl image digest "${SOURCE_REFERENCE}")"');
    expect(pipeline).toContain('regctl image copy "${SOURCE_REFERENCE}" "${BRIDGE_SOURCE_REFERENCE}"');
    expect(pipeline).toContain('The staged source digest does not match the audited Harbor source digest.');
    expect(pipeline).toContain('--output "type=image,name=${BRIDGE_TARGET_REFERENCE},push=true"');
    expect(pipeline).toContain('regctl image copy "${BRIDGE_TARGET_REFERENCE}" "${TARGET_REFERENCE}"');
    expect(pipeline).toContain('Harbor output digest differs from the patched digest produced by Copa.');
    expect(pipeline).toContain('outputTag must start with copa-poc-');
    expect(pipeline).toContain('reScanPatchedDigest: true');
    expect(pipeline).toContain('bound to the patched immutable digest, and OS-only');
    expect(pipeline).toContain('regctl registry set "${BRIDGE_REGISTRY_HOST}" --tls disabled');
    expect(pipeline).not.toContain('regctl registry set "${HARBOR_HOST}" --tls disabled');
    expect(pipeline).not.toContain('--username "${HARBOR_ROBOT_USERNAME}"');
    expect(pipeline).not.toContain('--user "${HARBOR_ROBOT_USERNAME}"');
    expect(pipeline).not.toContain('/service/token');
    expect(pipeline).not.toContain('--insecure');
    expect(pipeline).not.toMatch(/curl\s+-k\b/);
  });

  it('blocks or restores a Copa output that lost the source runtime configuration before Harbor', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');
    const build = pipeline.indexOf('--output "type=image,name=${BRIDGE_TARGET_REFERENCE},push=true"');
    const gate = pipeline.indexOf('Verifying that the Copa output keeps the source image runtime configuration.');
    const harborCopy = pipeline.indexOf('regctl image copy "${BRIDGE_TARGET_REFERENCE}" "${TARGET_REFERENCE}"');

    expect(build).toBeGreaterThan(-1);
    expect(gate).toBeGreaterThan(build);
    expect(harborCopy).toBeGreaterThan(gate);
    expect(pipeline).toContain('scripts/image-config-integrity.mjs');
    expect(pipeline).toContain('config_tool verify-digest --file "${CONFIG_DIR}/${name}-config.json" --digest "${config_digest}"');
    expect(pipeline).toContain('fetch_image_config "${BRIDGE_SOURCE_REPOSITORY}" "${SOURCE_DIGEST}" "${OUTPUT_PLATFORM}" source');
    expect(pipeline).toContain('regctl blob put "${BRIDGE_TARGET_REPOSITORY}" < "${CONFIG_DIR}/restored-config.json"');
    expect(pipeline).toContain('"${BRIDGE_TARGET_REFERENCE}" < "${CONFIG_DIR}/restored-manifest.json"');
    expect(pipeline).toContain('The job-scoped registry did not store the planned restored manifest.');
    expect(pipeline).toContain('fetch_image_config "${BRIDGE_TARGET_REPOSITORY}" "${BRIDGE_TARGET_DIGEST}" "${OUTPUT_PLATFORM}" final');
    expect(pipeline).toContain('--out "${EVIDENCE_DIR}/config-integrity.json"');
    expect(pipeline).toContain("configIntegrity.verified !== true || configIntegrity.outputDigest !== targetDigest");
    expect(pipeline).toMatch(/passed: verificationPassed,\n\s+},\n\s+configIntegrity,\n/);
    // The registry bridge and Harbor TLS rules stay unchanged; the restore never rebuilds layers.
    expect(pipeline).not.toContain('regctl image mod');
  });

  it('delivers verified evidence through an authenticated and idempotent API callback', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toContain('SSI Dry Run remediation job ID');
    expect(pipeline).toContain('/worker-evidence');
    expect(pipeline).toContain("createHmac('sha256', secret)");
    expect(pipeline).toContain("'X-SSI-Evidence-Content-SHA256': contentDigest");
    expect(pipeline).toContain("'X-SSI-Evidence-Worker-ID': workerId");
    expect(pipeline).toContain("'X-SSI-Evidence-Signature': `sha256=${signature}`");
    expect(pipeline).toContain('SSI_REMEDIATION_EVIDENCE_HMAC_SECRET: $(SSI_REMEDIATION_EVIDENCE_HMAC_SECRET)');
    expect(pipeline).toContain('for (let attempt = 1; attempt <= 3; attempt += 1)');
    expect(pipeline).toContain("require('node:http')");
    expect(pipeline).toContain("require('node:https')");
    expect(pipeline).toContain('const deadline = setTimeout(() => {');
    expect(pipeline).toContain('request.destroy(error)');
    expect(pipeline).toContain('clearTimeout(deadline)');
    expect(pipeline).not.toContain('request.setTimeout(timeoutMs');
    expect(pipeline).toContain("'Content-Length': Buffer.byteLength(requestBody)");
    expect(pipeline).not.toContain('new AbortController()');
    expect(pipeline).not.toContain('await fetch(endpoint');
    expect(pipeline).toContain('api-evidence-receipt.json');
    expect(pipeline).not.toMatch(/echo.*SSI_REMEDIATION_EVIDENCE_HMAC_SECRET/);
  });

  it('preserves evidence and defers delivery when the callback network is temporarily unavailable', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');
    const preflight = pipeline.indexOf('Preflight SSI evidence callback path');
    const download = pipeline.indexOf('Download canonical Trivy JSON artifact');
    const patch = pipeline.indexOf('Patch with Copa frontend and re-scan immutable output');

    expect(preflight).toBeGreaterThan(-1);
    expect(preflight).toBeLessThan(download);
    expect(preflight).toBeLessThan(patch);
    expect(pipeline).toContain('SSI_EVIDENCE_WORKER_ID: $(Agent.Name)');
    expect(pipeline).toContain('SSI_EVIDENCE_WORKER_MACHINE: $(Agent.MachineName)');
    expect(pipeline).toContain("execFileSync('ip', ['route', 'get', routeAddress]");
    expect(pipeline).toContain("healthUrl.pathname = `${healthUrl.pathname.replace(/\\/$/, '')}/health`");
    expect(pipeline).toContain('const status = await probe(healthUrl, 5000)');
    expect(pipeline).toContain('callback-preflight.json');
    expect(pipeline).toContain("kind: 'ssi.remediation.callback-preflight'");
    expect(pipeline).toContain('SSI_CALLBACK_REACHABLE');
    expect(pipeline).toContain("writeEvidence('unreachable'");
    expect(pipeline).toContain('api-evidence-delivery-pending.json');
    expect(pipeline).toContain('ssi.worker-evidence-delivery-pending/v1');
    expect(pipeline).not.toContain('Remediation was not started.');
  });

  it('keeps application, authentication, and integrity failures fail-closed', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');

    expect(pipeline).toContain("error.code = 'EHEALTHSTATUS'");
    expect(pipeline).toContain("writeEvidence('failed'");
    expect(pipeline).toContain('const transient = error.transient !== false;');
    expect(pipeline).toContain('if (!transient) throw error;');
    expect(pipeline).toContain('process.exitCode = 1');
  });

  it('publishes deterministic diagnostics after an early fail-fast stop', async () => {
    const pipeline = await readFile(pipelineFile, 'utf8');
    const finalizer = pipeline.indexOf('Finalize remediation diagnostic evidence');
    const publish = pipeline.indexOf('Publish remediation PoC evidence');

    expect(finalizer).toBeGreaterThan(-1);
    expect(finalizer).toBeLessThan(publish);
    expect(pipeline).toContain('pipeline-diagnostic.json');
    expect(pipeline).toContain("              node <<'NODE'\n");
    expect(pipeline).toContain('\n              NODE\n');
    expect(pipeline).not.toContain("                node <<'NODE'\n");
    expect(pipeline).not.toContain('\n                NODE\n');
    expect(pipeline).toContain(
      '.readdirSync(evidenceDir, { withFileTypes: true })',
    );
    const heredocBody = pipeline.slice(
      pipeline.indexOf("              node <<'NODE'\n", finalizer),
      pipeline.indexOf('\n              NODE\n', finalizer),
    );
    expect(heredocBody).not.toMatch(/^\s*(fi|done|esac)\s*$/m);
    expect(pipeline).not.toContain('if [ -z "$(find "${EVIDENCE_DIR}"');
    expect(pipeline).toMatch(
      /displayName: 'Publish remediation PoC evidence'\n\s+condition: succeededOrFailed\(\)/,
    );
  });
});

describe('Copa output boundary', () => {
  const pipeline = readFileSync(pipelineFile, 'utf8');

  // The output check of a step, run on its own: everything up to and including the guard.
  function outputGuard(displayName, repository) {
    const script = stepScript(pipeline, displayName);
    const end = script.indexOf('fi\n', script.indexOf('== approved/*')) + 3;
    const start = script.indexOf('if [[ "${OUTPUT_REPOSITORY}" == approved');
    return runBash(`set -euo pipefail\nOUTPUT_REPOSITORY='${repository}'\n${script.slice(start, end)}echo passed`, {});
  }

  it('keeps the patched candidate out of the approved catalog in both the check and the patch step', () => {
    for (const step of ['Validate immutable canonical Copa input', 'Patch with Copa frontend and re-scan immutable output']) {
      expect(outputGuard(step, 'onboarded/nginx').output).toContain('passed');
      expect(outputGuard(step, 'onboarded/payments/redis').output).toContain('passed');
      for (const repository of ['approved', 'approved/nginx', 'onboarded/../approved/nginx']) {
        const result = outputGuard(step, repository);
        expect(result.ok, `${step}: ${repository}`).toBe(false);
        expect(result.output).toContain('outputRepository must not be in the approved catalog (approved/)');
      }
    }
  });
});
