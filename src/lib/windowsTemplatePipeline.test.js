import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { stepEnv } from './pipelineSteps.testkit.js';

// azure-pipelines-os-template-windows.yml: the SSI Windows template worker.
const pipeline = readFileSync(
  new URL('../../azure-pipelines-os-template-windows.yml', import.meta.url),
  'utf8',
);
const BUILD_STEP = 'Validate inputs and build the template';

// The PowerShell body of the `- powershell: |` step with this displayName, dedented.
const powershellStep = (displayName) => {
  const step = pipeline
    .split(/\n {10}- /)
    .find((chunk) => chunk.includes(`displayName: '${displayName}'`));
  const body = step?.match(/^powershell: \|\n([\s\S]*?)\n {12}displayName:/);
  if (!body) throw new Error(`No PowerShell step named '${displayName}'.`);
  return body[1].replace(/^ {14}/gm, '');
};

// Each case starts a PowerShell process: 1-2 s of cold start on the CI agent, well over a
// quarter of Vitest's 5 s default. The suites below allow for it.
const PWSH_TIMEOUT = { timeout: 60_000 };

const hasPwsh = (() => {
  try {
    execFileSync('pwsh', ['-NoProfile', '-Command', 'exit 0'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

describe('Windows template pipeline definition', () => {
  it('is manual and runs only in the dedicated SSI-Windows pool', () => {
    expect(pipeline).toMatch(/^trigger: none$/m);
    expect(pipeline).toMatch(/^pr: none$/m);
    expect(pipeline).toMatch(/^pool:\n {2}name: 'SSI-Windows'$/m);
    expect(pipeline).not.toContain('WindowsPool');
  });

  it('hands parameters to PowerShell only through the environment', () => {
    // A parameter expanded into the script text would be code; through env it is only data.
    const script = powershellStep(BUILD_STEP);
    expect(script).not.toContain('${{');
    expect(stepEnv(pipeline, BUILD_STEP)).toEqual({
      SSI_TEMPLATE_ISO_FILE: '${{ parameters.isoFile }}',
      SSI_TEMPLATE_ISO_SHA256: '${{ parameters.isoSha256 }}',
      SSI_TEMPLATE_IMAGE_INDEX: '${{ parameters.imageIndex }}',
      SSI_TEMPLATE_PRODUCT: '${{ parameters.product }}',
      SSI_TEMPLATE_NAME: '${{ parameters.templateName }}',
      SSI_TEMPLATE_DELIVER: '${{ parameters.deliverToSsi }}',
      SSI_TEMPLATE_BUILD_REQUEST: '${{ parameters.osTemplateBuildId }}',
      SSI_API_BASE_URL: '${{ parameters.ssiApiBaseUrl }}',
      SSI_ALLOW_INSECURE_POC_API: '${{ parameters.allowInsecurePocApi }}',
      SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET: '$(SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET)',
    });
  });

  it('declares exactly the parameters SSI sends for a build request', () => {
    // Azure DevOps refuses a run with a template parameter the pipeline does not declare.
    const declared = [...pipeline.matchAll(/^ {2}- name: (\w+)$/gm)]
      .map((match) => match[1])
      .sort();
    expect(declared).toEqual(
      [
        'allowInsecurePocApi',
        'deliverToSsi',
        'imageIndex',
        'isoFile',
        'isoSha256',
        'osTemplateBuildId',
        'product',
        'ssiApiBaseUrl',
        'templateName',
      ].sort(),
    );
  });

  it('can only call this SSI back, like the other workers', () => {
    expect(pipeline).toContain(
      '    values:\n      - http://10.0.0.10:5021/api/v1\n      - http://ssi.example.com/api/v1',
    );
  });

  it('delivers the signed result only when asked, after a successful build, with the tested SSI tool', () => {
    const deliverStep = powershellStep('Deliver the signed result to SSI');
    expect(deliverStep).toContain('scripts\\os-template-evidence.mjs');
    expect(deliverStep).toContain('& node $tool deliver --file $result');
    expect(deliverStep).not.toContain('${{');
    expect(pipeline).toMatch(
      /displayName: 'Deliver the signed result to SSI'\n {12}condition: and\(succeeded\(\), eq\('\$\{\{ parameters\.deliverToSsi \}\}', 'true'\)\)/,
    );
    expect(pipeline).not.toMatch(/Write-Host[^\n]*SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET/);
  });

  it('validates every input before the build script runs', () => {
    const script = powershellStep(BUILD_STEP);
    const build = script.indexOf('& $script');
    for (const check of [
      "Fail 'isoSha256 must be",
      'isoFile must be a plain .iso file name',
      'imageIndex must be 1-16',
      'product must look like',
      'templateName may hold',
      'does not exist on this build machine',
      'must run as an administrator',
    ]) {
      expect(script.indexOf(check), check).toBeGreaterThan(0);
      expect(script.indexOf(check), check).toBeLessThan(build);
    }
  });

  it('publishes evidence and the manifest but never the ISO, and cleans only its own run', () => {
    expect(powershellStep('Collect evidence (no ISO)')).not.toMatch(/Copy-Item[^\n]*\.iso/);
    expect(pipeline).toContain("ArtifactName: 'os-template-windows-evidence'");
    const cleanup = powershellStep('Cleanup (only this run)');
    expect(cleanup).toContain('"ado-$env:BUILD_BUILDID"');
    expect(cleanup).toContain("foreach ($name in 'work', 'scratch')");
    expect(pipeline).toMatch(
      /displayName: 'Cleanup \(only this run\)'\n {12}condition: always\(\)/,
    );
  });
});

describe.skipIf(!hasPwsh)('Windows template pipeline input validation', PWSH_TIMEOUT, () => {
  let directory;
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'ssi-windows-pipeline-'));
    mkdirSync(join(directory, 'staging'));
    writeFileSync(join(directory, 'step.ps1'), powershellStep(BUILD_STEP));
  });
  afterEach(() => rmSync(directory, { recursive: true, force: true }));

  const run = (inputs) => {
    const env = {
      PATH: process.env.PATH,
      HOME: directory,
      SSI_IMAGE_ROOT: join(directory, 'image-root'),
      BUILD_BUILDID: '4242',
      BUILD_ARTIFACTSTAGINGDIRECTORY: join(directory, 'staging'),
      BUILD_SOURCESDIRECTORY: join(directory, 'sources'),
      SSI_TEMPLATE_ISO_FILE: 'WS2025_EVAL_en-us.iso',
      SSI_TEMPLATE_ISO_SHA256: 'a'.repeat(64),
      SSI_TEMPLATE_IMAGE_INDEX: '2',
      SSI_TEMPLATE_PRODUCT: 'Windows Server 2025',
      SSI_TEMPLATE_NAME: 'ssi-ws2025-std-de',
      SSI_TEMPLATE_DELIVER: 'false',
      ...inputs,
    };
    try {
      execFileSync(
        'pwsh',
        ['-NoProfile', '-NonInteractive', '-File', join(directory, 'step.ps1')],
        {
          env,
          encoding: 'utf8',
          stdio: 'pipe',
        },
      );
      return { status: 0, failure: null };
    } catch (error) {
      const failure = readFileSync(
        join(directory, 'staging/os-template-windows/failure.txt'),
        'utf8',
      );
      return { status: error.status, failure: failure.trim(), output: error.stdout };
    }
  };

  it('refuses an unpinned source ISO', () => {
    expect(run({ SSI_TEMPLATE_ISO_SHA256: '' })).toMatchObject({
      status: 1,
      failure: expect.stringContaining('refuses an unpinned ISO'),
    });
  });

  it('refuses a path smuggled into the ISO file name', () => {
    expect(run({ SSI_TEMPLATE_ISO_FILE: '..\\..\\Windows\\x.iso' }).failure).toContain(
      'isoFile must be a plain .iso file name',
    );
  });

  it('refuses a command smuggled into the product name', () => {
    expect(
      run({ SSI_TEMPLATE_PRODUCT: "Windows Server 2025'; Remove-Item C:\\" }).failure,
    ).toContain('product must look like');
  });

  it('neutralises an Azure DevOps logging command in a rejected value', () => {
    const result = run({ SSI_TEMPLATE_NAME: '##vso[task.setvariable variable=x]y' });
    expect(result.failure).toContain('##vso_[task.setvariable');
    expect(result.output).not.toMatch(/##vso\[task\.setvariable/);
  });

  it('checks the delivery to SSI before the four-hour build starts', () => {
    const deliver = {
      SSI_TEMPLATE_DELIVER: 'true',
      SSI_TEMPLATE_BUILD_REQUEST: 'OST-0001',
      SSI_API_BASE_URL: 'http://10.0.0.10:5021/api/v1',
    };
    expect(run({ ...deliver, SSI_TEMPLATE_BUILD_REQUEST: 'RM-DRY-1' }).failure).toContain(
      'osTemplateBuildId must look like OST-0001',
    );
    expect(run({ ...deliver, SSI_API_BASE_URL: 'http://user:pw@ssi/api' }).failure).toContain(
      'ssiApiBaseUrl must be an http(s) URL',
    );
    expect(run(deliver).failure).toContain('allowInsecurePocApi must be true');
    expect(
      run({
        ...deliver,
        SSI_ALLOW_INSECURE_POC_API: 'true',
        SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET: '$(SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET)',
      }).failure,
    ).toContain('SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET is not set');
  });

  it('stops when the ISO is not on the build machine', () => {
    expect(run({}).failure).toMatch(/WS2025_EVAL_en-us\.iso does not exist on this build machine/);
  });
});
