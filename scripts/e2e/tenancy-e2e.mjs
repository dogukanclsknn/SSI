// SSI — multi-tenancy end-to-end test: the real server process, a real PostgreSQL database
// and a fake Harbor with two teams' images.
//
//   DATABASE_URL=postgres://user@host:5432/empty_db DATABASE_SSL_MODE=disable npm run test:e2e:tenancy
//
// The database must be EMPTY (a throwaway test database): the test runs the migrations,
// seeds users, teams, jobs and publish requests, and refuses to run when SSI data exists.
//
// Phase A — SSI_MULTI_TENANCY off: everything is as before (all images, platform targets).
// Phase B — SSI_MULTI_TENANCY on: a member of team "payments" is tried against every route
// that reads or changes a record of team "default"; each must answer as if the record did
// not exist, while the default team's own member still reaches it.

import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as wait } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createPostgresPool } from '../../src/server/database.js';
import { PostgresRemediationStore } from '../../src/server/remediationStore.js';
import { PostgresTenantStore } from '../../src/server/tenantStore.js';
import { PostgresUserStore } from '../../src/server/userStore.js';
import { ALL_TENANTS } from '../../src/lib/tenancy.js';
import { createWorkerEvidenceHeaders, EVIDENCE_PURPOSE } from '../../src/lib/workerEvidenceAuth.js';
import { EXCEPTION_REASONS } from '../../src/lib/policyExceptions.js';
import { buildManifest, buildScanReport, vulnerabilitiesOf } from '../../poc/os-template/host/template-report.mjs';
import {
  acceptPublishReceipt,
  approvePublishRequest,
  buildPublishPolicyConfig,
  evaluatePublishPolicy,
} from '../../src/lib/publishPolicy.js';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
// Overridable so a shared CI agent can pick free ports (azure-pipelines.yml).
function portFrom(name, fallback) {
  const value = Number(process.env[name] || fallback);
  if (!Number.isInteger(value) || value < 1024 || value > 65535) {
    console.error(`${name} must be a port number between 1024 and 65535.`);
    process.exit(2);
  }
  return value;
}
const SSI_PORT = portFrom('E2E_SSI_PORT', 5098);
const HARBOR_PORT = portFrom('E2E_HARBOR_PORT', 5097);
const BASE = `http://127.0.0.1:${SSI_PORT}/api/v1`;
const PROJECT = 'ssi-images';
const REGISTRY = 'harbor.example';
const HANDOFF_TOKEN = 'e2e-onboard-handoff-token-000000000000';
const RECEIPT_TOKEN = 'e2e-publish-receipt-token-000000000000';
const ONBOARD_RECEIPT_TOKEN = 'e2e-onboard-receipt-token-000000000000';
const INSPECTION_SECRET = 'e2e-image-inspection-secret-00000000000000';
const CANONICAL_SECRET = 'e2e-canonical-report-secret-0000000000000';
const PUBLISH_RECEIPT_SECRET = 'e2e-publish-receipt-secret-00000000000000';
const ONBOARD_RECEIPT_SECRET = 'e2e-onboard-receipt-secret-00000000000000';
const OS_TEMPLATE_SECRET = 'e2e-os-template-secret-000000000000000000';
const MIME = 'application/vnd.security.vulnerability.report; version=1.1';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required (an empty, throwaway PostgreSQL database).');
  process.exit(2);
}

const digest = (letter) => `sha256:${letter.repeat(64)}`;
const D = { defaultOnboarded: digest('1'), paymentsOnboarded: digest('2'), defaultApproved: digest('3'), paymentsApproved: digest('4') };

// ---------------------------------------------------------------- fake Harbor
const harborImages = [
  { repository: 'onboarded/nginx', tag: '1.27-alpine', digest: D.defaultOnboarded, cve: 'CVE-2026-1111', pkg: 'openssl' },
  { repository: 'approved/ssi-remediation-test', tag: 'verified-r3', digest: D.defaultApproved, cve: null },
  { repository: 'onboarded/payments/redis', tag: '7.2-alpine', digest: D.paymentsOnboarded, cve: 'CVE-2026-2222', pkg: 'busybox' },
  { repository: 'approved/payments/api', tag: 'verified-r1', digest: D.paymentsApproved, cve: null },
];
const imageId = (image) => `harbor-${PROJECT}-${image.repository}-${image.tag}`.replace(/[^a-zA-Z0-9_-]+/g, '-').toLowerCase();
const scanId = (image) => `${PROJECT}/${image.repository}:${image.tag}`;
const [defaultOnboarded, defaultApproved, paymentsOnboarded, paymentsApproved] = harborImages;
// Real Harbor also lists these next to the images: a Cosign attestation of a published image
// (Harbor cannot scan it) and an unrelated image whose scan failed.
const cosignAttestation = { repository: 'approved/ssi-remediation-test', tag: `sha256-${'3'.repeat(64)}.att`, digest: digest('a'), cve: null, scanStatus: 'Error' };
const brokenScan = { repository: 'onboarded/nginx', tag: '1.26-alpine', digest: digest('7'), cve: null, scanStatus: 'Error' };
const extraArtifacts = [cosignAttestation, brokenScan];
// ssi.image-inspection/v1 of a fake Harbor image, as the worker sends it.
function inspectionOf(image, { generatedAt = '2026-11-11T10:00:00.000Z', env = ['PATH', 'NGINX_VERSION'], os = 'alpine 3.22.2', packages } = {}) {
  return {
    contractVersion: 'ssi.image-inspection/v1',
    generatedAt,
    image: { immutableReference: `${REGISTRY}/${PROJECT}/${image.repository}@${image.digest}`, digest: image.digest },
    platform: 'linux/amd64',
    os,
    runner: { pipeline: 'SSI - Image Inspection', buildId: '1', agent: 'e2e' },
    packages: packages || [
      { name: 'musl', arch: 'x86_64', version: '1.2.5-r10' },
      { name: image.pkg || 'zlib', arch: 'x86_64', version: image.cve ? '1.0.0-r0' : '1.0.1-r0' },
    ],
    facts: { sizeBytes: 50_000_000, diffIds: [digest('d'), ...(image.cve ? [] : [digest('e')])], config: { Cmd: ['nginx'], Env: env } },
  };
}

// POST the signed evidence to the worker route; `secret` and `subject` are overridable to test the signature.
async function postInspection(evidence, { secret = INSPECTION_SECRET, subject = evidence.image.digest } = {}) {
  const body = JSON.stringify(evidence);
  const headers = createWorkerEvidenceHeaders({ jobId: subject, rawBody: body, secret, workerId: 'e2e-agent', purpose: EVIDENCE_PURPOSE.IMAGE_INSPECTION });
  const response = await fetch(`${BASE}/image-inspections/${encodeURIComponent(evidence.image.digest)}/worker`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body,
  });
  return { status: response.status, json: await response.json().catch(() => null), replay: response.headers.get('X-SSI-Evidence-Replay') };
}

// OS templates (src/lib/osTemplate.js): the signed result of the Windows template worker for one
// build request, shaped like the manifest Build-WindowsTemplate.ps1 writes.
const OS_TEMPLATE_ISO = '7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51';
function osTemplateResult(buildId, { isoSha256 = OS_TEMPLATE_ISO } = {}) {
  return {
    contractVersion: 'ssi.os-template-build/v1',
    buildId,
    generatedAt: new Date().toISOString(),
    runner: { pipeline: 'SSI - OS Template (Windows)', buildId: '4711', agent: 'WINBUILD01' },
    location: { host: 'WINBUILD01', path: 'E:\\SSI-Image\\runs\\ado-4711\\out\\ssi-ws2025-std-de-26100.33822.iso' },
    manifest: {
      manifestVersion: 'ssi.os-template-manifest/v1',
      template: { name: 'ssi-ws2025-std-de', version: '26100.33822', os: 'windows-server-2025', edition: 'Windows Server 2025 Standard Evaluation (Desktop Experience)', architecture: 'amd64' },
      build: { id: 'ado-4711', createdAt: new Date().toISOString(), tools: { dism: '10.0.26100.9457', oscdimg: '2.56', powershell: '5.1.20348.5773' } },
      base: { file: 'WS2025_EVAL_en-us.iso', sha256: isoSha256, imageIndex: 2, build: '10.0.26100.32230' },
      updates: [{ kb: 'KB5131080', file: `windows11.0-kb5131080-x64_${'3'.repeat(40)}.msu`, sha256: 'b'.repeat(64), applied: true }],
      scan: {
        source: 'Microsoft Security Update Guide (MSRC CVRF API v3.0)',
        before: { build: '10.0.26100.32230', open: 3388, critical: 210, important: 3173 },
        after: { build: '10.0.26100.33822', open: 0, critical: 0, important: 0 },
        gate: { maxOpenAfter: 0, passed: true },
      },
      artifacts: [{ file: 'ssi-ws2025-std-de-26100.33822.iso', format: 'iso', sizeBytes: 8_101_986_304, sha256: 'c'.repeat(64), signature: null }],
      signing: { signed: false },
    },
  };
}

// The signed result of the Ubuntu template worker: the manifest exactly as
// poc/os-template/host/template-report.mjs writes it from the worker's reports and files.
const UBUNTU_IMAGE_URL = 'https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img';
const UBUNTU_IMAGE_SHA = '04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94';
async function ubuntuTemplateResult(buildId, { scannedOs = { family: 'ubuntu', name: '24.04' } } = {}) {
  const version = '24.04-20261124-ado-883942';
  const directory = mkdtempSync(join(tmpdir(), 'ssi-e2e-ubuntu-'));
  try {
    for (const format of ['qcow2', 'ova', 'vhdx']) writeFileSync(join(directory, `ssi-ubuntu-2404-${version}.${format}`), format);
    const finding = (VulnerabilityID, PkgName, Severity, FixedVersion = '') => ({ VulnerabilityID, PkgName, InstalledVersion: '1', FixedVersion, Severity });
    const trivy = (Vulnerabilities) => ({ Results: [{ Class: 'os-pkgs', Vulnerabilities }] });
    const report = buildScanReport({
      before: vulnerabilitiesOf(trivy([finding('CVE-2026-1000', 'linux-image-6.8.0-147-generic', 'CRITICAL', '6.8.0-151.151'), finding('CVE-2026-3000', 'linux-headers-6.8.0-147-generic', 'HIGH')])),
      after: vulnerabilitiesOf(trivy([finding('CVE-2026-3000', 'linux-headers-6.8.0-151-generic', 'HIGH')])),
      kernelBefore: '6.8.0-147-generic',
      kernelAfter: '6.8.0-151-generic',
      os: scannedOs,
    });
    const manifest = await buildManifest({
      artifactsDir: directory,
      report,
      templateName: 'ssi-ubuntu-2404',
      templateVersion: version,
      buildId: 'ado-883942',
      baseImageUrl: UBUNTU_IMAGE_URL,
      baseImageSha256: UBUNTU_IMAGE_SHA,
      signed: false,
      tools: { libguestfs: 'virt-customize 1.52.0', 'qemu-img': 'qemu-img version 8.2.2', trivy: '0.70.0', trivyDbUpdatedAt: new Date(Date.now() - 3600_000).toISOString() },
    });
    return {
      contractVersion: 'ssi.os-template-build/v1',
      buildId,
      generatedAt: new Date().toISOString(),
      runner: { pipeline: 'SSI - OS Template (Ubuntu)', buildId: '883942', agent: 'LinuxAgent2' },
      location: { host: 'azure-devops', path: `os-template-ubuntu-images/ssi-ubuntu-2404-${version}.qcow2` },
      manifest,
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

async function postOsTemplateResult(buildId, result, { secret = OS_TEMPLATE_SECRET } = {}) {
  const body = JSON.stringify(result);
  const headers = createWorkerEvidenceHeaders({ jobId: buildId, rawBody: body, secret, workerId: 'ado-4711-WINBUILD01', purpose: EVIDENCE_PURPOSE.OS_TEMPLATE });
  const response = await fetch(`${BASE}/os-templates/${encodeURIComponent(buildId)}/worker`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body,
  });
  return { status: response.status, json: await response.json().catch(() => null), replay: response.headers.get('X-SSI-Evidence-Replay') };
}

// The signature headers a publish or onboarding worker sends with a receipt (src/lib/workerReceiptAuth.js).
// `call` sends JSON.stringify(body), so the same string is signed here.
function signedReceipt(subject, body, { purpose = EVIDENCE_PURPOSE.PUBLISH_RECEIPT, secret, workerId = body.workerId } = {}) {
  const defaultSecret = purpose === EVIDENCE_PURPOSE.ONBOARD_RECEIPT ? ONBOARD_RECEIPT_SECRET : PUBLISH_RECEIPT_SECRET;
  return createWorkerEvidenceHeaders({ jobId: subject, rawBody: JSON.stringify(body), secret: secret || defaultSecret, workerId, purpose });
}

// POST a canonical Trivy report as the canonical scan worker would (exact bytes, HMAC-signed).
async function postCanonicalReport(jobId, body, { secret = CANONICAL_SECRET } = {}) {
  const headers = createWorkerEvidenceHeaders({ jobId, rawBody: body, secret, workerId: 'e2e-agent', purpose: EVIDENCE_PURPOSE.CANONICAL_REPORT });
  const response = await fetch(`${BASE}/remediation/${encodeURIComponent(jobId)}/worker-canonical-report`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body,
  });
  return { status: response.status, json: await response.json().catch(() => null), replay: response.headers.get('X-SSI-Evidence-Replay') };
}

const canonicalReportFor = (image) =>
  JSON.stringify({
    SchemaVersion: 2,
    ArtifactName: `${REGISTRY}/${PROJECT}/${image.repository}@${image.digest}`,
    ArtifactType: 'container_image',
    Metadata: { OS: { Family: 'alpine', Name: '3.20.3' }, RepoDigests: [`${REGISTRY}/${PROJECT}/${image.repository}@${image.digest}`] },
    Results: [
      {
        Target: `${REGISTRY}/${PROJECT}/${image.repository}@${image.digest} (alpine 3.20.3)`,
        Class: 'os-pkgs',
        Type: 'alpine',
        Vulnerabilities: [
          { VulnerabilityID: image.cve, PkgName: image.pkg, InstalledVersion: '3.3.0-r0', FixedVersion: '3.3.2-r0', Severity: 'HIGH' },
        ],
      },
    ],
  });

// Immutable scan reference used by GET /scans/compare.
const scanRef = (image) => `${PROJECT}/${image.repository}@${image.digest}`;
const compareQuery = (base, head) => `/scans/compare?${new URLSearchParams({ base, head }).toString()}`;

function artifactOf(image) {
  return {
    digest: image.digest,
    tags: [{ name: image.tag }],
    size: 12 * 1024 * 1024,
    push_time: '2026-11-10T09:00:00.000Z',
    scan_overview: {
      [MIME]: { scan_status: image.scanStatus || 'Success', end_time: '2026-11-10T09:05:00.000Z', summary: { summary: image.cve ? { High: 1 } : {} } },
    },
  };
}

const harbor = createServer((request, response) => {
  const url = new URL(request.url, 'http://harbor');
  const parts = url.pathname.split('/').filter(Boolean); // api v2.0 projects <p> repositories [<repo> artifacts [<ref> additions vulnerabilities]]
  const send = (body) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(body));
  };
  if (parts[3] !== PROJECT) return send([]);
  if (parts.length === 5) return send(url.searchParams.get('page') === '1' ? harborImages.map((image) => ({ name: `${PROJECT}/${image.repository}` })) : []);
  const repository = decodeURIComponent(decodeURIComponent(parts[5] || ''));
  const image = harborImages.find((item) => item.repository === repository);
  if (!image) return send([]);
  const listed = [image, ...extraArtifacts.filter((item) => item.repository === repository)];
  if (parts.length === 7) return send(url.searchParams.get('page') === '1' ? listed.map(artifactOf) : []);
  return send({
    [MIME]: {
      vulnerabilities: image.cve
        ? [{ id: image.cve, package: image.pkg, version: '1.0.0-r0', fix_version: '1.0.1-r0', severity: 'High' }]
        : [],
    },
  });
});

// ---------------------------------------------------------------- database seed
const policyEnvironment = {
  SSI_RBAC_ENFORCED: 'true',
  SSI_SESSION_SECRET: 'x'.repeat(40),
  PUBLISH_TARGET_REGISTRY: REGISTRY,
  PUBLISH_TARGET_PROJECT: PROJECT,
  PUBLISH_TARGET_REPOSITORY_PREFIX: 'approved',
};
const platformPolicy = buildPublishPolicyConfig(policyEnvironment);
const paymentsPolicy = { ...platformPolicy, target: { ...platformPolicy.target, repositoryPrefix: 'approved/payments' } };

function verifiedJob(id, tenantId, output, source = digest(id.endsWith('4') ? '5' : '6')) {
  return {
    id,
    tenantId,
    mode: 'execution',
    status: 'Verified',
    lifecycleState: 'verified',
    verificationStatus: 'Passed',
    image: `${PROJECT}/onboarded/nginx:alpine`,
    sourceDigest: source,
    patchedImageDigest: output,
    patchedImageTag: `${REGISTRY}/${PROJECT}/onboarded/nginx:copa-${id.toLowerCase()}`,
    fixed: [{ cve: 'CVE-2026-0001' }],
    before: { critical: 1, high: 2, medium: 0, low: 0 },
    after: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    verificationEvidence: {
      evidenceDigest: digest('e'),
      outputDigest: output,
      configIntegrity: { status: 'restored', verified: true, platform: 'linux/amd64', restoredFields: ['Cmd'], outputDigest: output },
    },
    fullImageComparison: {
      status: 'available',
      source: { digest: source, findings: 1, severity: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 } },
      output: { digest: output, findings: 0, severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } },
    },
    supplyChain: {},
    candidateTest: { passed: true, candidateDigest: output, platform: 'linux/amd64', checks: [], packageChanges: { summary: { changed: 1, unplanned: 0 } } },
    consumerAcceptance: { decision: 'accepted', environment: 'e2e', note: 'ok', decidedBy: 'consumer.tester', candidateDigest: output, decidedAt: '2026-11-10T08:00:00.000Z' },
    createdAt: '2026-11-10T07:00:00.000Z',
    verifiedAt: '2026-11-10T07:10:00.000Z',
  };
}

function publishedRequest(id, job, repository, tag, config) {
  const target = { registry: REGISTRY, project: PROJECT, repository, tag };
  const evaluated = { ...evaluatePublishPolicy({ job, target, config, actorId: 'seed.requester', requestId: id }), tenantId: job.tenantId };
  const approved = approvePublishRequest(evaluated, { actorId: 'seed.approver', actorRoles: ['approver'], reason: 'e2e seed approval', config, currentJob: job });
  return acceptPublishReceipt(approved, {
    contractVersion: 'ssi.publish-receipt/v1',
    requestId: id,
    sourceDigest: job.patchedImageDigest,
    targetDigest: job.patchedImageDigest,
    targetReference: approved.target.tagReference,
    status: 'published',
    verified: true,
    workerId: 'e2e-worker',
  });
}

async function seed() {
  const pool = await createPostgresPool();
  try {
    const existing = await pool.query("SELECT to_regclass('public.users') AS users");
    if (existing.rows[0].users) {
      const users = await pool.query('SELECT count(*)::int AS n FROM users');
      if (users.rows[0].n > 0) throw new Error('Refusing to run: the database already holds SSI users. Use an empty database.');
    }
  } finally {
    await pool.end();
  }
  const migrate = spawnSync('node', ['scripts/migrate.js'], { cwd: REPO, env: process.env, encoding: 'utf8' });
  if (migrate.status !== 0) throw new Error(`Migration failed:\n${migrate.stdout}${migrate.stderr}`);

  const seedPool = await createPostgresPool();
  try {
    const users = new PostgresUserStore(seedPool);
    const tenants = new PostgresTenantStore(seedPool);
    const store = new PostgresRemediationStore(seedPool);
    await users.initialize();
    await tenants.initialize();
    for (const [username, role] of [
      ['def.op', 'operator'],
      ['def.ap', 'approver'],
      ['pay.op', 'operator'],
      ['pay.ap', 'approver'],
      ['plat.admin', 'admin'],
    ]) {
      await users.create({ username, role });
    }
    await tenants.createTenant({ id: 'payments', displayName: 'Payments' });
    for (const [tenantId, username, role] of [
      ['default', 'def.op', 'operator'],
      ['default', 'def.ap', 'approver'],
      ['payments', 'pay.op', 'operator'],
      ['payments', 'pay.ap', 'approver'],
    ]) {
      await tenants.setMembership({ tenantId, username, role, actorId: 'e2e-seed' });
    }

    // Patched from the onboarded nginx (which Harbor scans with one finding) into approved/.
    const defaultJob = verifiedJob('RM-EXEC-0004', 'default', D.defaultApproved, D.defaultOnboarded);
    const paymentsJob = verifiedJob('RM-EXEC-0101', 'payments', D.paymentsApproved);
    await store.createJob(defaultJob, null, ALL_TENANTS);
    await store.createJob(paymentsJob, null, ALL_TENANTS);
    const requests = [
      publishedRequest('PUB-0012', defaultJob, 'approved/ssi-remediation-test', 'verified-r3', platformPolicy),
      publishedRequest('PUB-0013', defaultJob, 'approved/ssi-remediation-test', 'verified-r3-alias', platformPolicy),
      {
        ...evaluatePublishPolicy({
          job: defaultJob,
          target: { registry: REGISTRY, project: PROJECT, repository: 'approved/ssi-remediation-test', tag: 'verified-pending' },
          config: platformPolicy,
          actorId: 'seed.requester',
          requestId: 'PUB-0014',
        }),
        tenantId: 'default',
      },
      publishedRequest('PUB-0101', paymentsJob, 'approved/payments/api', 'verified-r1', paymentsPolicy),
    ];
    for (const request of requests) await store.createPublishRequest(request, null, ALL_TENANTS);
    await seedPool.query("SELECT setval('publish_request_seq', 200)");

    // Migration 012: runs of a scanned image (image inspection), written under the advisory lock.
    const imageReference = `${PROJECT}/${defaultOnboarded.repository}@${defaultOnboarded.digest}`;
    const inspectionRun = (runId, requestedAt) => ({
      action: 'image-inspection',
      role: 'imageInspection',
      runId,
      state: 'inProgress',
      result: null,
      requestedAt,
      parameters: {},
    });
    await store.updateResourceRunsWith('image', imageReference, async () => ({ runs: [inspectionRun(1, '2026-11-17T09:00:00Z')] }));
    const imageRuns = await store.updateResourceRunsWith('image', imageReference, async (runs) => ({
      runs: [{ ...runs[0], state: 'completed', result: 'succeeded' }, inspectionRun(2, '2026-11-17T10:00:00Z')],
    }));
    check(
      'seed: image pipeline runs are stored, updated in place and listed newest first (migration 012)',
      imageRuns.length === 2 && imageRuns[0].runId === 2 && imageRuns[1].result === 'succeeded',
      imageRuns,
    );
  } finally {
    await seedPool.end();
  }
}

// ---------------------------------------------------------------- server control
const serverEnvironment = {
  ...process.env,
  ...policyEnvironment,
  PORT: String(SSI_PORT),
  PERSISTENCE_DRIVER: 'postgres',
  SSI_DEV_LOGIN: 'true',
  SSI_PUBLISH_POLICY_VERSION: 'ssi.publish-policy/v1.4',
  HARBOR_URL: `http://127.0.0.1:${HARBOR_PORT}`,
  HARBOR_PROJECTS: PROJECT,
  HARBOR_ROBOT_USERNAME: 'robot$e2e',
  HARBOR_ROBOT_SECRET: 'e2e-not-a-secret',
  ONBOARD_TARGET_REGISTRY: REGISTRY,
  ONBOARD_TARGET_PROJECT: PROJECT,
  ONBOARD_TARGET_REPOSITORY_PREFIX: 'onboarded',
  ONBOARD_HANDOFF_TOKEN: HANDOFF_TOKEN,
  ONBOARD_RECEIPT_TOKEN,
  ONBOARD_ALLOWED_REGISTRIES: 'docker.io',
  SSI_PUBLISH_RECEIPT_TOKEN: RECEIPT_TOKEN,
  SSI_PUBLISH_RECEIPT_HMAC_SECRET: PUBLISH_RECEIPT_SECRET,
  SSI_ONBOARD_RECEIPT_HMAC_SECRET: ONBOARD_RECEIPT_SECRET,
  SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET: INSPECTION_SECRET,
  SSI_CANONICAL_REPORT_HMAC_SECRET: CANONICAL_SECRET,
  SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET: OS_TEMPLATE_SECRET,
};

async function startServer(extra = {}) {
  const child = spawn('node', ['server.js'], { cwd: REPO, env: { ...serverEnvironment, ...extra } });
  let log = '';
  child.stdout.on('data', (chunk) => (log += chunk));
  child.stderr.on('data', (chunk) => (log += chunk));
  for (let attempt = 0; attempt < 75; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`SSI exited during start-up:\n${log}`);
    try {
      if ((await fetch(`${BASE}/health`)).ok) return { child, log: () => log };
    } catch {
      // not listening yet
    }
    await wait(200);
  }
  child.kill('SIGTERM');
  throw new Error(`SSI did not start:\n${log}`);
}

async function stopServer(server) {
  if (server.child.exitCode !== null) return;
  server.child.kill('SIGTERM');
  await new Promise((resolve) => server.child.once('exit', resolve));
}

const actors = {
  defOp: ['def.op', 'operator'],
  defAp: ['def.ap', 'approver'],
  payOp: ['pay.op', 'operator'],
  payAp: ['pay.ap', 'approver'],
  admin: ['plat.admin', 'admin'],
};

async function call(actor, method, path, { body, team, headers = {} } = {}) {
  const [subject, roles] = actors[actor] || [];
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      ...(subject ? { 'X-SSI-Actor-Id': subject, 'X-SSI-Actor-Roles': roles } : {}),
      ...(team ? { 'X-SSI-Tenant': team } : {}),
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const raw = await response.text();
  let json = raw;
  try {
    json = JSON.parse(raw);
  } catch {
    // HTML document routes
  }
  return {
    status: response.status,
    json,
    dataError: response.headers.get('X-SSI-Data-Error') || '',
    receiptReplay: response.headers.get('X-SSI-Receipt-Replay') || '',
  };
}

// A GET with the raw answer: status, body text and headers (paging cursor, CSV export).
async function rawGet(actor, path) {
  const [subject, roles] = actors[actor] || [];
  const response = await fetch(`${BASE}${path}`, { headers: subject ? { 'X-SSI-Actor-Id': subject, 'X-SSI-Actor-Roles': roles } : {} });
  // Decoded without dropping a byte order mark, so the test can see it.
  const text = new TextDecoder('utf-8', { ignoreBOM: true }).decode(await response.arrayBuffer());
  return { status: response.status, text, headers: response.headers };
}

// RFC 4180 rows of a CSV text (quoted fields may hold commas, quotes and line breaks).
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (character === '"') quoted = false;
      else field += character;
    } else if (character === '"') quoted = true;
    else if (character === ',') {
      row.push(field);
      field = '';
    } else if (character === '\r' && text[index + 1] === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      index += 1;
    } else field += character;
  }
  return rows;
}

// Every audit event the actor may read for a query, page by page (src/lib/auditQuery.js).
async function readAuditPages(actor, query, limit = 7) {
  const events = [];
  let before = '';
  let pages = 0;
  do {
    const page = await rawGet(actor, `/audit-events?${query}&limit=${limit}${before ? `&before=${encodeURIComponent(before)}` : ''}`);
    if (page.status !== 200) return { status: page.status, events, pages };
    events.push(...JSON.parse(page.text));
    before = page.headers.get('X-SSI-Next-Cursor') || '';
    pages += 1;
  } while (before && pages < 500);
  return { status: 200, events, pages };
}

const results = [];
function check(name, condition, detail) {
  results.push({ name, ok: Boolean(condition), detail: condition ? '' : JSON.stringify(detail)?.slice(0, 400) });
}
const ids = (list) => (Array.isArray(list) ? list.map((item) => item.id).sort() : list);

// ---------------------------------------------------------------- run
async function phaseFlagOff() {
  // Platform guard: without approved source registries nothing is onboarded (fail-closed).
  const unconfigured = await startServer({ ONBOARD_ALLOWED_REGISTRIES: '' });
  try {
    const refused = await call('defOp', 'POST', '/onboarding', { body: { sourceReference: 'docker.io/library/nginx:1.27' } });
    check('A: onboarding is refused while no source registry is approved (503)', refused.status === 503, refused);
    check('A: start-up warns about the missing registry list', /ONBOARD_ALLOWED_REGISTRIES is empty/.test(unconfigured.log()), unconfigured.log());
  } finally {
    await stopServer(unconfigured);
  }

  const server = await startServer();
  try {
    const foreignRegistry = await call('defOp', 'POST', '/onboarding', { body: { sourceReference: 'quay.io/org/app:1.0' } });
    check('A: an image from a registry outside the list is refused', foreignRegistry.status === 422, foreignRegistry);
    const images = await call('defOp', 'GET', '/images');
    // The inventory API lists technical artifacts too; the screens hide them (isTechnicalArtifact).
    check('A: every image is listed while multi-tenancy is off', images.status === 200 && images.json.length === 6, images);
    check('A: images carry no team labels while off', images.json.every?.((image) => image.tenantId === undefined), images.json);
    const scans = await call('payOp', 'GET', '/scans');
    check('A: every scan result is listed while off', scans.status === 200 && scans.json.length === 4, scans);
    check(
      'A: a failed scan is reported, a Cosign accessory never is',
      scans.dataError.includes('onboarded/nginx:1.26-alpine') && !scans.dataError.includes('.att'),
      scans.dataError,
    );
    const policy = await call('defOp', 'GET', '/publish-policy');
    check('A: the publish boundary is the platform folder', policy.json?.target?.repositoryPrefix === 'approved', policy.json?.target);
    const onboarding = await call('defOp', 'POST', '/onboarding', { body: { sourceReference: 'docker.io/library/nginx:1.27' } });
    check('A: onboarding lands in the platform quarantine', onboarding.status === 201 && onboarding.json.target.repository === 'onboarded/nginx', onboarding);
    const handoff = await call(null, 'GET', `/onboarding/${onboarding.json.id}/worker-handoff`, { headers: { 'X-SSI-Onboard-Handoff-Token': HANDOFF_TOKEN } });
    check('A: work orders are unchanged (no tenantId)', handoff.status === 200 && !('tenantId' in handoff.json), handoff);

    // Onboarding cancellation: an open request (here Importing after the handoff) that no
    // worker will finish is closed with a reason; a late receipt is kept on record.
    const onboardingId = onboarding.json.id;
    const duplicate = await call('defOp', 'POST', '/onboarding', { body: { sourceReference: 'docker.io/library/nginx:1.27' } });
    check(
      'A: a second open onboarding for the same target is refused and names the open one (409)',
      duplicate.status === 409 && String(duplicate.json?.message).includes(onboardingId),
      duplicate,
    );
    const cancelPath = `/onboarding/${onboardingId}/cancel`;
    const cancelReason = 'The import worker never finished this request.';
    const shortReason = await call('defOp', 'POST', cancelPath, { body: { reason: 'stuck' } });
    check('A: a cancellation without a real reason is refused (422)', shortReason.status === 422, shortReason);
    const approverCancel = await call('defAp', 'POST', cancelPath, { body: { reason: cancelReason } });
    check('A: an approver without onboarding:create cannot cancel (403)', approverCancel.status === 403, approverCancel);
    const cancelled = await call('defOp', 'POST', cancelPath, { body: { reason: cancelReason } });
    check(
      'A: an operator cancels the open onboarding with a reason',
      cancelled.status === 200 &&
        cancelled.json.status === 'Cancelled' &&
        cancelled.json.cancellation?.cancelledBy === 'def.op' &&
        cancelled.json.cancellation?.previousStatus === 'Importing' &&
        cancelled.json.cancellation?.reason === cancelReason,
      cancelled,
    );
    const cancelAgain = await call('defOp', 'POST', cancelPath, { body: { reason: cancelReason } });
    check('A: a closed onboarding cannot be cancelled again (409)', cancelAgain.status === 409, cancelAgain);
    const handoffAfterCancel = await call(null, 'GET', `/onboarding/${onboardingId}/worker-handoff`, { headers: { 'X-SSI-Onboard-Handoff-Token': HANDOFF_TOKEN } });
    check('A: no work order is handed out for a cancelled onboarding (409)', handoffAfterCancel.status === 409, handoffAfterCancel);
    const importReceipt = {
      contractVersion: 'ssi.onboard-receipt/v1',
      requestId: onboardingId,
      status: 'imported',
      importedDigest: digest('7'),
      targetReference: onboarding.json.target.tagReference,
      scanSummary: { critical: 0, high: 0, medium: 0, low: 0 },
      workerId: 'e2e-import-worker',
    };
    const onboardReceiptHeaders = () => signedReceipt(onboardingId, importReceipt, { purpose: EVIDENCE_PURPOSE.ONBOARD_RECEIPT });
    const onboardingReceiptRefusals = [
      ['signed with another secret', signedReceipt(onboardingId, importReceipt, { purpose: EVIDENCE_PURPOSE.ONBOARD_RECEIPT, secret: PUBLISH_RECEIPT_SECRET }), 401],
      ['signed for the publish channel', signedReceipt(onboardingId, importReceipt), 401],
      ['signed for another request', signedReceipt('ONB-9999', importReceipt, { purpose: EVIDENCE_PURPOSE.ONBOARD_RECEIPT }), 401],
      ['signed by a worker the receipt does not name', signedReceipt(onboardingId, importReceipt, { purpose: EVIDENCE_PURPOSE.ONBOARD_RECEIPT, workerId: 'another-worker' }), 401],
      ['with a wrong legacy token', { 'X-SSI-Onboard-Receipt-Token': 'wrong-token' }, 403],
    ];
    for (const [what, headers, status] of onboardingReceiptRefusals) {
      const refused = await call(null, 'POST', `/onboarding/${onboardingId}/import-receipt`, { body: importReceipt, headers });
      check(`A: an onboarding receipt ${what} is refused (${status})`, refused.status === status, refused);
    }
    const lateImport = await call(null, 'POST', `/onboarding/${onboardingId}/import-receipt`, { body: importReceipt, headers: onboardReceiptHeaders() });
    check(
      'A: an import that finished after the cancellation is kept on record; the request stays cancelled',
      lateImport.status === 200 &&
        lateImport.receiptReplay === 'false' &&
        lateImport.json.status === 'Cancelled' &&
        lateImport.json.importAfterCancellation?.importedDigest === digest('7'),
      lateImport,
    );
    // During the migration the legacy token is still accepted (the same receipt, so a replay).
    const lateReplay = await call(null, 'POST', `/onboarding/${onboardingId}/import-receipt`, {
      body: importReceipt,
      headers: { 'X-SSI-Onboard-Receipt-Token': ONBOARD_RECEIPT_TOKEN },
    });
    check('A: the same late receipt again is an idempotent replay', lateReplay.status === 200 && lateReplay.receiptReplay === 'true', lateReplay);
    const otherImport = { ...importReceipt, importedDigest: digest('8') };
    const lateOther = await call(null, 'POST', `/onboarding/${onboardingId}/import-receipt`, {
      body: otherImport,
      headers: signedReceipt(onboardingId, otherImport, { purpose: EVIDENCE_PURPOSE.ONBOARD_RECEIPT }),
    });
    check('A: a different second receipt for the cancelled request is refused (409)', lateOther.status === 409, lateOther);
    const again = await call('defOp', 'POST', '/onboarding', { body: { sourceReference: 'docker.io/library/nginx:1.27' } });
    check('A: after the cancellation the same image can be requested again', again.status === 201 && again.json.id !== onboardingId, again);
    const onboardingAudit = await call('admin', 'GET', '/audit-events?limit=250');
    const onboardingEvents = (Array.isArray(onboardingAudit.json) ? onboardingAudit.json : []).filter((event) => event.resourceId === onboardingId);
    check(
      'A: the cancellation, the refused attempts and the late import are audited',
      onboardingEvents.some((event) => event.eventType === 'onboarding.request.cancelled' && event.metadata?.reason === cancelReason) &&
        onboardingEvents.some(
          (event) => event.eventType === 'onboarding.receipt.after-cancellation' && event.severity === 'warning' && event.metadata?.authentication === 'hmac',
        ) &&
        onboardingEvents.filter((event) => event.eventType === 'onboarding.cancel.rejected').length >= 2,
      onboardingEvents.map((event) => event.eventType),
    );

    // What changed between the source and the patched image (src/lib/imageComparison.js).
    const comparison = await call('defOp', 'GET', '/remediation/RM-EXEC-0004/comparison');
    const current = comparison.json?.dimensions?.find?.((item) => item.id === 'vulnerabilities-current');
    check(
      'A: the comparison compares today\'s Harbor scans of both digests',
      comparison.status === 200 && current?.status === 'available' && current.summary.fixed === 1 && current.summary.new === 0,
      comparison.json,
    );
    check('A: the comparison reports no registry problem when both digests are scanned', comparison.dataError === '', comparison.dataError);
    check('A: the comparison names both immutable digests', comparison.json?.base?.digest === D.defaultOnboarded && comparison.json?.head?.digest === D.defaultApproved, comparison.json);

    // Free comparison of two scanned images (Scan Results).
    const freeCompare = await call('defOp', 'GET', compareQuery(scanRef(defaultOnboarded), scanRef(defaultApproved)));
    const freeVulnerabilities = freeCompare.json?.dimensions?.[0];
    check(
      'A: two scanned images are compared by vulnerability',
      freeCompare.status === 200 &&
        freeCompare.json.kind === 'images' &&
        freeVulnerabilities?.summary?.fixed === 1 &&
        freeVulnerabilities.summary.new === 0 &&
        freeCompare.json.headline?.vulnerabilitiesFixed === 1 &&
        freeCompare.json.headline?.findingsBase === 1 &&
        freeCompare.json.headline?.findingsHead === 0,
      freeCompare.json,
    );
    const compareErrors = [
      ['the same image twice', compareQuery(scanRef(defaultOnboarded), scanRef(defaultOnboarded)), 422],
      ['a tag instead of a digest', compareQuery(scanId(defaultOnboarded), scanRef(defaultApproved)), 422],
      ['an image with no scan', compareQuery(scanRef(defaultOnboarded), `${PROJECT}/onboarded/nginx@${digest('9')}`), 404],
      ['a Cosign attestation', compareQuery(scanRef(defaultOnboarded), scanRef(cosignAttestation)), 404],
    ];
    for (const [label, path, status] of compareErrors) {
      const result = await call('defOp', 'GET', path);
      check(`A: comparing ${label} is refused (${status})`, result.status === status && typeof result.json?.message === 'string', result);
    }

    // Image inspections (SSI - Image Inspection worker) add packages, layers and configuration.
    const notInspected = freeCompare.json?.dimensions?.find?.((item) => item.id === 'packages');
    check(
      'A: without inspections the package comparison names the pipeline to run',
      notInspected?.status === 'unavailable' && /SSI - Image Inspection/.test(notInspected.note) &&
        freeCompare.json.base.registryReference === `${REGISTRY}/${scanRef(defaultOnboarded)}`,
      freeCompare.json?.base,
    );
    const firstInspection = await postInspection(inspectionOf(defaultOnboarded));
    check('A: a signed inspection of a scanned image is accepted', firstInspection.status === 200 && firstInspection.replay === 'false' && firstInspection.json?.packages === 2, firstInspection);
    const replayInspection = await postInspection(inspectionOf(defaultOnboarded));
    check('A: the same inspection again is an idempotent replay', replayInspection.status === 200 && replayInspection.replay === 'true', replayInspection);
    const inspectionRefusals = [
      ['an older inspection', await postInspection(inspectionOf(defaultOnboarded, { generatedAt: '2026-11-11T09:00:00.000Z' })), 409],
      ['an environment variable value', await postInspection(inspectionOf(defaultApproved, { env: ['PATH', 'API_TOKEN=s3cr3t'] })), 422],
      ['an image Harbor has not scanned', await postInspection(inspectionOf({ ...defaultOnboarded, digest: digest('9') })), 409],
      ['a Cosign attestation', await postInspection(inspectionOf(cosignAttestation)), 409],
      ['a wrong signature', await postInspection(inspectionOf(defaultApproved), { secret: 'x'.repeat(40) }), 401],
      ['a signature for another digest', await postInspection(inspectionOf(defaultApproved), { subject: digest('3').replace('3', '4') }), 401],
    ];
    for (const [label, result, status] of inspectionRefusals) {
      check(`A: the inspection intake refuses ${label} (${status})`, result.status === status, result);
    }
    // The approved image is the patched build of the onboarded one: the same openssl, updated.
    const secondInspection = await postInspection(inspectionOf({ ...defaultApproved, pkg: 'openssl' }));
    check('A: the compared image is inspected too', secondInspection.status === 200, secondInspection);
    const inspected = await call('defOp', 'GET', compareQuery(scanRef(defaultOnboarded), scanRef(defaultApproved)));
    const byId = Object.fromEntries((inspected.json?.dimensions || []).map((item) => [item.id, item]));
    check(
      'A: two inspected images are compared by packages, layers and configuration',
      inspected.status === 200 &&
        byId.packages?.status === 'available' && byId.packages.summary.differences === 1 &&
        byId.layers?.status === 'available' && byId.layers.summary.sharedBaseLayers === 1 && byId.layers.summary.added === 1 &&
        byId.configuration?.status === 'available' &&
        inspected.json.headline.sameOs === true && Boolean(inspected.json.base.inspectedAt),
      inspected.json?.headline,
    );
    const auditEvents = await call('admin', 'GET', '/audit-events?limit=250');
    const inspectionEvents = (Array.isArray(auditEvents.json) ? auditEvents.json : []).filter((event) => String(event.eventType).startsWith('image.inspection.'));
    check(
      'A: every accepted and refused inspection is audited, with no Env value',
      inspectionEvents.filter((event) => event.eventType === 'image.inspection.accepted').length === 2 &&
        inspectionEvents.filter((event) => event.eventType === 'image.inspection.rejected').length === inspectionRefusals.length &&
        !JSON.stringify(inspectionEvents).includes('s3cr3t'),
      inspectionEvents.map((event) => event.eventType),
    );
    const document = await call('defOp', 'GET', '/reports/remediation/RM-EXEC-0004/document');
    check('A: the report document says what changed', document.status === 200 && String(document.json).includes('What changed (source'), String(document.json).slice(0, 200));

    // A worker retrying the receipt of an already recorded publish gets the record back.
    const receipt = {
      contractVersion: 'ssi.publish-receipt/v1',
      requestId: 'PUB-0101',
      sourceDigest: D.paymentsApproved,
      targetDigest: D.paymentsApproved,
      targetReference: `${REGISTRY}/${PROJECT}/approved/payments/api:verified-r1`,
      status: 'published',
      verified: true,
      workerId: 'e2e-worker',
    };
    const replay = await call(null, 'POST', '/publish-requests/PUB-0101/receipt', { body: receipt, headers: signedReceipt('PUB-0101', receipt) });
    check('A: a repeated publish receipt is answered with the stored record (200)', replay.status === 200 && replay.json.status === 'Published', replay);
    const legacyReplay = await call(null, 'POST', '/publish-requests/PUB-0101/receipt', {
      body: receipt,
      headers: { 'X-SSI-Publish-Receipt-Token': RECEIPT_TOKEN },
    });
    check('A: during the migration a receipt with the legacy token is still accepted', legacyReplay.status === 200, legacyReplay);
    check(
      'A: the server log reports the open migration and every receipt accepted with the legacy token',
      /Publish receipts: signed and, during the migration, unsigned with SSI_PUBLISH_RECEIPT_TOKEN/.test(server.log()) &&
        /Publish receipt for PUB-0101 was accepted with the legacy SSI_PUBLISH_RECEIPT_TOKEN/.test(server.log()) &&
        !server.log().includes(RECEIPT_TOKEN) &&
        !server.log().includes(PUBLISH_RECEIPT_SECRET),
      server.log(),
    );
    const publishReceiptRefusals = [
      ['signed with another secret', signedReceipt('PUB-0101', receipt, { secret: ONBOARD_RECEIPT_SECRET }), 401],
      ['signed for another request', signedReceipt('PUB-0102', receipt), 401],
      ['whose body was changed after signing', signedReceipt('PUB-0101', { ...receipt, verified: false }), 401],
      ['with a wrong legacy token', { 'X-SSI-Publish-Receipt-Token': 'wrong-token' }, 403],
    ];
    for (const [what, headers, status] of publishReceiptRefusals) {
      const refused = await call(null, 'POST', '/publish-requests/PUB-0101/receipt', { body: receipt, headers });
      check(`A: a publish receipt ${what} is refused (${status})`, refused.status === status, refused);
    }
    const differentReceipt = { ...receipt, targetDigest: D.defaultApproved };
    const different = await call(null, 'POST', '/publish-requests/PUB-0101/receipt', {
      body: differentReceipt,
      headers: signedReceipt('PUB-0101', differentReceipt),
    });
    check('A: a different receipt for a published request is still refused (409)', different.status === 409, different);

    // The audit log: paging, server-side filters, counts and the CSV export.
    const firstHundred = await call('admin', 'GET', '/audit-events?limit=250');
    const allPages = await readAuditPages('admin', 'category=all');
    const pagedIds = allPages.events.map((event) => event.id);
    check(
      'A: the audit log pages through every event exactly once, newest first',
      allPages.status === 200 &&
        allPages.pages > 1 &&
        new Set(pagedIds).size === pagedIds.length &&
        pagedIds.length >= firstHundred.json.length &&
        allPages.events.every((event, index, list) => index === 0 || list[index - 1].occurredAt >= event.occurredAt),
      { pages: allPages.pages, count: pagedIds.length },
    );
    const summary = await call('admin', 'GET', '/audit-events/summary');
    check(
      'A: the audit summary counts every event and each category',
      summary.status === 200 &&
        summary.json.total === pagedIds.length &&
        Object.entries(summary.json.categories)
          .filter(([key]) => key !== 'all')
          .reduce((sum, [, count]) => sum + count, 0) === summary.json.total,
      summary.json,
    );
    const failuresPublish = await readAuditPages('admin', 'category=publish&failures=true');
    check(
      'A: category and failure filters run on the server',
      failuresPublish.events.length > 0 &&
        failuresPublish.events.every((event) => event.eventType.startsWith('publish.') && event.outcome !== 'success'),
      failuresPublish.events.map((event) => [event.eventType, event.outcome]),
    );
    const searched = await readAuditPages('admin', 'q=PUB-0101');
    check(
      'A: the search finds events by resource across all pages',
      searched.events.length > 0 && searched.events.every((event) => JSON.stringify(event).includes('PUB-0101')),
      searched.events.length,
    );
    const wildcard = await call('admin', 'GET', '/audit-events?q=%25');
    check('A: a % in the search is a literal character, not a wildcard', wildcard.status === 200 && wildcard.json.every((event) => JSON.stringify(event).includes('%')), wildcard.json?.length);
    for (const [what, query] of [
      ['an unknown category', 'category=everything'],
      ['a forged cursor', 'before=Zm9yZ2Vk'],
      ['a non-ISO date', 'from=last%20week'],
    ]) {
      const refused = await call('admin', 'GET', `/audit-events?${query}`);
      check(`A: an audit query with ${what} is refused (400)`, refused.status === 400, refused);
    }

    const from = new Date(Date.now() - 86_400_000).toISOString();
    const to = new Date(Date.now() + 60_000).toISOString();
    const period = `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
    const expected = await call('admin', 'GET', `/audit-events/summary?${period}`);
    const csv = await rawGet('admin', `/audit-events/export?${period}`);
    const csvRows = parseCsv(csv.text);
    check(
      'A: the CSV export holds every event of the period, with a header row and a UTF-8 BOM',
      csv.status === 200 &&
        csv.headers.get('Content-Type') === 'text/csv; charset=utf-8' &&
        /^attachment; filename="ssi-audit-\d{8}-\d{8}\.csv"$/.test(csv.headers.get('Content-Disposition') || '') &&
        csv.text.startsWith('\uFEFFTime (UTC),Event ID,Event type,') &&
        Number(csv.headers.get('X-SSI-Audit-Rows')) === expected.json.total &&
        csvRows.length - 1 === expected.json.total &&
        csvRows.every((row) => row.length === 12),
      { status: csv.status, rows: csv.headers.get('X-SSI-Audit-Rows'), csvRows: csvRows.length, expected: expected.json?.total },
    );
    check(
      'A: no CSV cell can run as a spreadsheet formula',
      csvRows.slice(1).every((row) => row.every((cell) => !/^[=+\-@\t\r]/.test(cell))),
      csvRows.slice(1).flat().filter((cell) => /^[=+\-@]/.test(cell)),
    );
    const exportedAudit = await call('admin', 'GET', '/audit-events?category=other&q=audit.exported');
    check(
      'A: the export itself is recorded in the audit log with its period and row count',
      exportedAudit.json.some(
        (event) =>
          event.eventType === 'audit.exported' &&
          event.actorId === 'plat.admin' &&
          event.metadata?.rows === expected.json.total &&
          event.metadata?.filters?.from === from &&
          Boolean(event.metadata?.asOf),
      ),
      exportedAudit.json,
    );
    const noPeriod = await call('admin', 'GET', '/audit-events/export');
    check('A: an export without a period is refused (400)', noPeriod.status === 400, noPeriod);
    const refusedAudit = await call('admin', 'GET', '/audit-events?q=audit.export.rejected');
    check('A: a refused export is recorded too', refusedAudit.json.some((event) => event.eventType === 'audit.export.rejected'), refusedAudit.json);
  } finally {
    await stopServer(server);
  }
}

// OS templates are platform-wide: any team's operator requests one and every role reads it.
async function osTemplateChecks() {
  const request = { isoFile: 'WS2025_EVAL_en-us.iso', isoSha256: OS_TEMPLATE_ISO, imageIndex: 2, product: 'Windows Server 2025', templateName: 'ssi-ws2025-std-de' };
  const created = await call('payOp', 'POST', '/os-templates', { body: request });
  check('B: an operator of any team requests an OS template build (201, Requested)', created.status === 201 && /^OST-\d{4}$/.test(created.json.id) && created.json.status === 'Requested', created);
  const id = created.json.id;
  const badSha = await call('payOp', 'POST', '/os-templates', { body: { ...request, isoSha256: 'abc' } });
  check('B: a build request with an unpinned ISO is refused (422)', badSha.status === 422, badSha);
  const byApprover = await call('defAp', 'POST', '/os-templates', { body: request });
  check('B: an approver cannot request a build (403)', byApprover.status === 403, byApprover);
  const listed = await call('defAp', 'GET', '/os-templates');
  check('B: OS templates are visible to every team (platform-wide)', listed.status === 200 && listed.json.some((item) => item.id === id), listed);
  const runOff = await call('payOp', 'POST', `/os-templates/${id}/pipeline-runs`, { body: { action: 'os-template-build' } });
  check('B: the template build is not started while Azure DevOps automation is off (503)', runOff.status === 503, runOff);
  const runDenied = await call('defAp', 'POST', `/os-templates/${id}/pipeline-runs`, { body: { action: 'os-template-build' } });
  check('B: starting the template build needs os-template:build (403 for an approver)', runDenied.status === 403, runDenied);

  const forged = await postOsTemplateResult(id, osTemplateResult(id), { secret: 'e2e-not-the-os-template-secret-000000000' });
  check('B: a template result with a wrong signature is refused (401)', forged.status === 401, forged);
  const otherIso = await postOsTemplateResult(id, osTemplateResult(id, { isoSha256: 'f'.repeat(64) }));
  check('B: a template built from another ISO is refused (422)', otherIso.status === 422 && /pinned/.test(otherIso.json?.message), otherIso);
  const stillRequested = await call('payOp', 'GET', `/os-templates/${id}`);
  check('B: a refused result leaves the request Requested', stillRequested.json?.status === 'Requested', stillRequested);
  const result = osTemplateResult(id);
  const accepted = await postOsTemplateResult(id, result);
  check(
    'B: the signed template result is recorded (Built, 3388 -> 0 open CVEs)',
    accepted.status === 200 && accepted.replay === 'false' && accepted.json.status === 'Built' && accepted.json.template.openBefore === 3388 && accepted.json.template.openAfter === 0,
    accepted,
  );
  const replay = await postOsTemplateResult(id, result);
  check('B: the same result again is an idempotent replay', replay.status === 200 && replay.replay === 'true', replay);

  const selfApproval = await call('admin', 'POST', '/os-templates', { body: request });
  const ownDecision = await call('admin', 'POST', `/os-templates/${selfApproval.json.id}/reject`, { body: { reason: 'own request' } });
  check('B: the requester cannot decide their own build request (four eyes, 403)', ownDecision.status === 403, ownDecision);
  const noReason = await call('defAp', 'POST', `/os-templates/${selfApproval.json.id}/reject`, { body: {} });
  check('B: a rejection needs a reason (422)', noReason.status === 422, noReason);
  const byOperator = await call('payOp', 'POST', `/os-templates/${id}/approve`, { body: {} });
  check('B: an operator cannot approve a template (403)', byOperator.status === 403, byOperator);
  const approved = await call('defAp', 'POST', `/os-templates/${id}/approve`, { body: {} });
  check('B: an approver accepts the built template into the catalog', approved.status === 200 && approved.json.status === 'Approved' && approved.json.decision.by === 'def.ap', approved);
  const again = await call('defAp', 'POST', `/os-templates/${id}/approve`, { body: {} });
  check('B: an approved template is not approved twice (409)', again.status === 409, again);
  const late = await postOsTemplateResult(id, osTemplateResult(id));
  check('B: an approved request takes no new result (409)', late.status === 409, late);
  const audit = await call('admin', 'GET', '/audit-events?limit=100');
  const types = new Set((audit.json?.events || audit.json || []).map((event) => event.eventType));
  check(
    'B: the request, the result and the approval are audited',
    ['os-template.request.created', 'os-template.build.accepted', 'os-template.approved', 'os-template.build.rejected'].every((type) => types.has(type)),
    [...types].filter((type) => type.startsWith('os-template')),
  );
}

async function ubuntuTemplateChecks() {
  const request = { os: 'ubuntu-24.04', baseImageUrl: UBUNTU_IMAGE_URL, baseImageSha256: UBUNTU_IMAGE_SHA, templateName: 'ssi-ubuntu-2404', diskSizeGb: 20, aptMirror: '' };
  const created = await call('payOp', 'POST', '/os-templates', { body: request });
  check('B: an operator requests an Ubuntu 24.04 template build (201, Requested)', created.status === 201 && created.json.os === 'ubuntu-24.04' && created.json.status === 'Requested', created);
  const id = created.json.id;
  const foreignImage = await call('payOp', 'POST', '/os-templates', { body: { ...request, baseImageUrl: 'https://example.com/ubuntu.img' } });
  check('B: an Ubuntu build from an unofficial image URL is refused (422)', foreignImage.status === 422, foreignImage);
  const runOff = await call('payOp', 'POST', `/os-templates/${id}/pipeline-runs`, { body: { action: 'os-template-build-ubuntu' } });
  check('B: the Ubuntu build is not started while Azure DevOps automation is off (503)', runOff.status === 503, runOff);

  const blind = await postOsTemplateResult(id, await ubuntuTemplateResult(id, { scannedOs: null }));
  check('B: an Ubuntu result whose scan did not recognise Ubuntu is refused (422)', blind.status === 422 && /did not recognise/.test(blind.json?.message), blind);
  const accepted = await postOsTemplateResult(id, await ubuntuTemplateResult(id));
  check(
    'B: the signed Ubuntu result is recorded (Built, 1 -> 0 CVEs with a fix, QCOW2/OVA/VHDX)',
    accepted.status === 200 && accepted.json.status === 'Built' && accepted.json.template.cvesBefore.fixable === 1 && accepted.json.template.cvesAfter.fixable === 0 && accepted.json.template.artifacts.length === 3,
    accepted,
  );
  const approved = await call('defAp', 'POST', `/os-templates/${id}/approve`, { body: {} });
  check('B: an approver accepts the Ubuntu template into the catalog', approved.status === 200 && approved.json.status === 'Approved', approved);
  const audit = await call('admin', 'GET', '/audit-events?limit=100');
  const events = (audit.json?.events || audit.json || []).filter((event) => event.resourceId === id);
  check(
    'B: the Ubuntu build is audited with its files',
    events.some((event) => event.eventType === 'os-template.build.accepted' && /CVEs with a fix/.test(event.summary)) &&
      events.some((event) => event.eventType === 'os-template.approved' && event.metadata?.artifacts?.length === 3),
    events.map((event) => event.eventType),
  );
}

async function phaseFlagOn() {
  const server = await startServer({ SSI_MULTI_TENANCY: 'true', SSI_PUBLISH_RECEIPT_TOKEN: '', ONBOARD_RECEIPT_TOKEN: '' });
  try {
    check('B: start-up reports the team count', /SSI_MULTI_TENANCY=true: 2 team\(s\)/.test(server.log()), server.log());
    check('B: start-up is silent about receipts once only signed ones are accepted', !/receipts?/i.test(server.log()), server.log());

    // Records of the default team that the payments team must not reach.
    const defaultScan = await call('defOp', 'POST', `/images/${encodeURIComponent(scanId(defaultOnboarded))}/remediation`, { body: { dryRun: true } });
    check('B: the default team plans remediation for its own image', defaultScan.status === 201 && defaultScan.json.tenantId === 'default', defaultScan);
    const defaultDryRun = defaultScan.json.id;
    const exceptionBody = {
      cve: defaultOnboarded.cve,
      repository: `${PROJECT}/${defaultOnboarded.repository}`,
      package: defaultOnboarded.pkg,
      reasonCode: Object.keys(EXCEPTION_REASONS)[0],
      justification: 'No upstream fix yet; the component is not reachable in this image.',
      durationDays: 7,
    };
    const defaultException = await call('defOp', 'POST', '/exceptions', { body: exceptionBody });
    check('B: the default team requests a risk acceptance', defaultException.status === 201 && defaultException.json.tenantId === 'default', defaultException);

    const foreign = [
      ['GET', '/remediation/RM-EXEC-0004'],
      ['GET', '/remediation/RM-EXEC-0004/execution-readiness'],
      ['GET', `/remediation/${defaultDryRun}/worker-handoff`],
      ['GET', '/reports/remediation/RM-EXEC-0004/document'],
      ['GET', '/remediation/RM-EXEC-0004/comparison'],
      ['GET', '/remediation/RM-EXEC-0004/pipeline-runs'],
      ['GET', compareQuery(scanRef(defaultOnboarded), scanRef(defaultApproved))],
      ['GET', '/publish-requests/PUB-0012'],
      ['GET', '/publish-requests/PUB-0014/worker-handoff', 'payAp'],
      ['GET', `/images/${imageId(defaultOnboarded)}`],
      ['GET', `/images/${imageId(defaultOnboarded)}/sbom`],
      ['POST', `/images/${encodeURIComponent(scanId(defaultOnboarded))}/remediation`, 'payOp', { dryRun: true }],
      ['POST', `/remediation/${defaultDryRun}/canonical-report`, 'payOp', {}],
      ['POST', `/remediation/${defaultDryRun}/verification-evidence`, 'payOp', {}],
      ['POST', '/remediation/RM-EXEC-0004/supply-chain-evidence', 'payOp', {}],
      ['POST', '/remediation/RM-EXEC-0004/candidate-test', 'payOp', {}],
      ['POST', '/remediation/RM-EXEC-0004/consumer-acceptance', 'payAp', { decision: 'accepted', environment: 'payments-test' }],
      ['POST', '/publish-requests', 'payOp', { jobId: 'RM-EXEC-0004', target: { repository: 'approved/payments/api', tag: 'stolen-r1' } }],
      ['POST', '/publish-requests/PUB-0014/approve', 'payAp', { reason: 'cross-team approval attempt' }],
      ['POST', '/publish-requests/PUB-0014/reject', 'payAp', { reason: 'cross-team rejection attempt' }],
      ['POST', '/publish-requests/PUB-0012/withdraw', 'payAp', { reason: 'cross-team withdrawal attempt', category: 'security' }],
      ['POST', `/exceptions/${defaultException.json.id}/approve`, 'payAp', { note: 'cross-team approval attempt' }],
    ];
    for (const [method, path, actor = 'payOp', body] of foreign) {
      const result = await call(actor, method, path, { body });
      check(`B: payments cannot reach ${method} ${path} (404)`, result.status === 404, result);
    }
    // Control: the same request by the default team's own member is not a 404, so every 404
    // above comes from the team boundary, not from a broken request. (Runs after the
    // cross-team attempts: some controls change state, e.g. the withdrawal.)
    const ownerOf = { payOp: 'defOp', payAp: 'defAp' };
    for (const [method, path, actor = 'payOp', body] of foreign) {
      const own = await call(ownerOf[actor], method, path, { body });
      check(`B: the default team reaches ${method} ${path} (${own.status})`, own.status !== 404 && own.status < 500, own);
    }

    // The withdrawal of PUB-0012 above (control run) closed every open request of that digest:
    // PUB-0014 had just been approved, so it is cancelled and can no longer be handed out.
    const cancelledRequest = await call('defOp', 'GET', '/publish-requests/PUB-0014');
    check(
      'B: withdrawing an image cancels its open publish requests',
      cancelledRequest.json?.status === 'Cancelled' &&
        cancelledRequest.json.cancellation?.cause === 'image-withdrawn' &&
        cancelledRequest.json.cancellation?.previousStatus === 'Approved' &&
        cancelledRequest.json.cancellation?.cancelledBy === 'def.ap',
      cancelledRequest.json,
    );
    const cancelledHandoff = await call('defAp', 'GET', '/publish-requests/PUB-0014/worker-handoff');
    check('B: a cancelled publish request has no worker handoff (409)', cancelledHandoff.status === 409, cancelledHandoff);
    const withdrawalAudit = await call('admin', 'GET', '/audit-events?limit=250');
    check(
      'B: the cancellation is audited with the withdrawal reason',
      (Array.isArray(withdrawalAudit.json) ? withdrawalAudit.json : []).some(
        (event) => event.eventType === 'publish.request.cancelled' && event.resourceId === 'PUB-0014' && event.metadata?.previousStatus === 'Approved',
      ),
      withdrawalAudit.json?.filter?.((event) => event.resourceId === 'PUB-0014').map((event) => event.eventType),
    );
    // A worker that had the approved handoff before the withdrawal may still publish: the
    // receipt is recorded as published after withdrawal, never as a live publish.
    const lateTarget = cancelledRequest.json?.target?.tagReference;
    const latePublishReceipt = {
      contractVersion: 'ssi.publish-receipt/v1',
      requestId: 'PUB-0014',
      sourceDigest: D.defaultApproved,
      targetDigest: D.defaultApproved,
      targetReference: lateTarget,
      status: 'published',
      verified: true,
      workerId: 'e2e-worker',
    };
    // The migration is over in this phase (no legacy tokens): an unsigned receipt is refused.
    const unsignedPublish = await call(null, 'POST', '/publish-requests/PUB-0014/receipt', {
      body: latePublishReceipt,
      headers: { 'X-SSI-Publish-Receipt-Token': RECEIPT_TOKEN },
    });
    check('B: once the legacy token is removed an unsigned publish receipt is refused (401)', unsignedPublish.status === 401, unsignedPublish);
    const latePublish = await call(null, 'POST', '/publish-requests/PUB-0014/receipt', {
      body: latePublishReceipt,
      headers: signedReceipt('PUB-0014', latePublishReceipt),
    });
    check(
      'B: a late publish of a cancelled request is recorded as withdrawn',
      latePublish.status === 200 && latePublish.json.status === 'Withdrawn' && latePublish.json.withdrawal?.publishedAfterWithdrawal === true,
      latePublish,
    );

    // Lists: only the team's own records, plus the shared catalog of published images.
    const images = await call('payOp', 'GET', '/images');
    check(
      'B: payments sees its images and the shared catalog',
      JSON.stringify(ids(images.json)) ===
        JSON.stringify([imageId(defaultApproved), imageId(cosignAttestation), imageId(paymentsApproved), imageId(paymentsOnboarded)].sort()),
      ids(images.json),
    );
    const shared = images.json.find?.((image) => image.id === imageId(defaultApproved));
    check('B: a shared catalog image names the team that published it', shared?.tenantId === 'default' && shared?.tenantArea === 'approved', shared);
    const ownCompare = await call('payOp', 'GET', compareQuery(scanRef(paymentsOnboarded), scanRef(paymentsApproved)));
    check('B: payments compares its own two scanned images', ownCompare.status === 200 && ownCompare.json.kind === 'images', ownCompare);
    const scans = await call('payOp', 'GET', '/scans');
    check('B: payments sees only its own scan results', JSON.stringify(ids(scans.json)) === JSON.stringify([scanId(paymentsApproved), scanId(paymentsOnboarded)].sort()), ids(scans.json));
    const jobs = await call('payOp', 'GET', '/remediation');
    check('B: payments lists only its jobs', JSON.stringify(ids(jobs.json)) === JSON.stringify(['RM-EXEC-0101']), ids(jobs.json));
    const requests = await call('payOp', 'GET', '/publish-requests');
    check('B: payments lists only its publish requests', JSON.stringify(ids(requests.json)) === JSON.stringify(['PUB-0101']), ids(requests.json));
    const exceptions = await call('payOp', 'GET', '/exceptions');
    check('B: payments lists none of the default risk acceptances', Array.isArray(exceptions.json) && exceptions.json.length === 0, exceptions);
    const report = await call('payOp', 'GET', '/reports/remediation');
    check('B: the remediation report counts only payments jobs', report.json?.summary?.totalJobs === 1, report.json?.summary);
    const audit = await call('payOp', 'GET', '/audit-events?limit=250');
    check('B: payments sees only its own audit events', Array.isArray(audit.json) && audit.json.every((event) => event.tenantId === 'payments'), audit.json?.map?.((e) => e.tenantId));
    const paymentsPages = await readAuditPages('payOp', 'category=all', 3);
    check(
      'B: every page payments reads holds only its own audit events',
      paymentsPages.status === 200 && paymentsPages.events.length > 0 && paymentsPages.events.every((event) => event.tenantId === 'payments'),
      paymentsPages.events.map((event) => event.tenantId),
    );
    const paymentsSummary = await call('payOp', 'GET', '/audit-events/summary');
    check('B: the audit summary of payments counts only its own events', paymentsSummary.json?.total === paymentsPages.events.length, paymentsSummary.json);
    const paymentsCsv = await rawGet(
      'payOp',
      `/audit-events/export?from=2020-01-01&to=${encodeURIComponent(new Date(Date.now() + 60_000).toISOString())}`,
    );
    const teamColumn = parseCsv(paymentsCsv.text)
      .slice(1)
      .map((row) => row[10]);
    check(
      'B: the CSV export of payments holds only its own events',
      paymentsCsv.status === 200 && teamColumn.length === paymentsPages.events.length && teamColumn.every((team) => team === 'payments'),
      { status: paymentsCsv.status, teams: [...new Set(teamColumn)], rows: teamColumn.length },
    );

    // The team's own Harbor target.
    const policy = await call('payOp', 'GET', '/publish-policy');
    check('B: the payments publish boundary is its approved folder', policy.json?.target?.repositoryPrefix === 'approved/payments', policy.json?.target);
    const inside = await call('payOp', 'POST', '/publish-requests', { body: { jobId: 'RM-EXEC-0101', target: { repository: 'approved/payments/api', tag: 'verified-r2' } } });
    const insideFailures = inside.json?.decision?.failedCheckIds || [];
    check('B: publishing into its own folder passes the boundary check', inside.status === 201 && !insideFailures.includes('target-boundary'), inside);
    const outside = await call('payOp', 'POST', '/publish-requests', {
      body: { jobId: 'RM-EXEC-0101', target: { repository: 'approved/ssi-remediation-test', tag: 'verified-r9' } },
    });
    check(
      "B: publishing into another team's folder is blocked",
      outside.status === 201 && outside.json.status === 'Blocked' && outside.json.decision.failedCheckIds.includes('target-boundary'),
      outside,
    );
    const ownScan = await call('payOp', 'POST', `/images/${encodeURIComponent(scanId(paymentsOnboarded))}/remediation`, { body: { dryRun: true } });
    check('B: payments plans remediation for its own image', ownScan.status === 201 && ownScan.json.tenantId === 'payments', ownScan);
    const onboarding = await call('payOp', 'POST', '/onboarding', { body: { sourceReference: 'docker.io/library/redis:7.2' } });
    check('B: payments onboards into its quarantine folder', onboarding.status === 201 && onboarding.json.target.repository === 'onboarded/payments/redis', onboarding);
    const handoff = await call(null, 'GET', `/onboarding/${onboarding.json.id}/worker-handoff`, { headers: { 'X-SSI-Onboard-Handoff-Token': HANDOFF_TOKEN } });
    check('B: the work order names the team and its folder', handoff.json?.tenantId === 'payments' && handoff.json?.target?.repository === 'onboarded/payments/redis', handoff);
    const foreignCancel = await call('defOp', 'POST', `/onboarding/${onboarding.json.id}/cancel`, { body: { reason: 'Cross-team cancellation attempt.' } });
    check("B: another team cannot cancel payments' onboarding (404)", foreignCancel.status === 404, foreignCancel);
    const ownCancel = await call('payOp', 'POST', `/onboarding/${onboarding.json.id}/cancel`, { body: { reason: 'Requested the wrong Redis version.' } });
    check('B: payments cancels its own onboarding', ownCancel.status === 200 && ownCancel.json.status === 'Cancelled', ownCancel);

    // Platform administration.
    const all = await call('admin', 'GET', '/images');
    check('B: a platform administrator sees every image', Array.isArray(all.json) && all.json.length === 6, ids(all.json));
    const teams = await call('admin', 'GET', '/tenants');
    const payments = teams.json?.find?.((team) => team.id === 'payments');
    check('B: the team list shows the folders a team uses', payments?.effectiveHarbor?.publish?.repositoryPrefix === 'approved/payments', payments);
    const clash = await call('admin', 'POST', '/tenants', { body: { id: 'cards', displayName: 'Cards', harbor: { approvedPrefix: 'approved/payments' } } });
    check("B: a new team cannot take another team's folder (409)", clash.status === 409, clash);
    // Canonical scan worker: the report reaches the Dry Run without a person uploading it.
    const canonicalBody = canonicalReportFor(defaultOnboarded);
    const forged = await postCanonicalReport(defaultDryRun, canonicalBody, { secret: 'not-the-canonical-secret-000000000000000' });
    check('B: a canonical report with a wrong signature is refused (401)', forged.status === 401, forged);
    const delivered = await postCanonicalReport(defaultDryRun, canonicalBody);
    check(
      'B: the canonical scan worker delivers the report to the Dry Run and it is re-planned',
      delivered.status === 200 && delivered.json?.canonicalReport?.intake?.channel === 'worker' && delivered.json?.plannedFixes?.length === 1 && delivered.replay === 'false',
      delivered,
    );
    const again = await postCanonicalReport(defaultDryRun, canonicalBody);
    check('B: the same canonical report again changes nothing (replay)', again.status === 200 && again.replay === 'true', again);
    const toExecution = await postCanonicalReport('RM-EXEC-0004', canonicalReportFor(defaultApproved));
    check('B: a canonical report is only accepted for a Dry Run (409)', toExecution.status === 409, toExecution);

    // Worker pipelines of onboarding, publish requests and scanned images (Phase 4a).
    const onboardingRuns = await call('payOp', 'GET', `/onboarding/${onboarding.json.id}/pipeline-runs`);
    check('B: an onboarding request shows its pipeline actions (automation off)', onboardingRuns.status === 200 && onboardingRuns.json.enabled === false, onboardingRuns);
    const foreignOnboardingRuns = await call('defOp', 'GET', `/onboarding/${onboarding.json.id}/pipeline-runs`);
    check("B: another team cannot see an onboarding request's runs (404)", foreignOnboardingRuns.status === 404, foreignOnboardingRuns);
    const publishByOperator = await call('defOp', 'POST', '/publish-requests/PUB-0014/pipeline-runs', { body: { action: 'publish-check' } });
    check('B: an operator cannot start the publish pipeline (403)', publishByOperator.status === 403, publishByOperator);
    const publishOff = await call('defAp', 'POST', '/publish-requests/PUB-0014/pipeline-runs', { body: { action: 'publish-check' } });
    check('B: an approver reaches the publish pipeline, refused while automation is off (503)', publishOff.status === 503, publishOff);
    const imageReference = `${PROJECT}/${defaultOnboarded.repository}@${defaultOnboarded.digest}`;
    const imageRuns = await call('defOp', 'GET', `/scans/pipeline-runs?${new URLSearchParams({ reference: imageReference })}`);
    check('B: a visible scanned image lists its inspection runs', imageRuns.status === 200 && imageRuns.json.runs?.length === 2, imageRuns);
    const hiddenImageRuns = await call('payOp', 'GET', `/scans/pipeline-runs?${new URLSearchParams({ reference: imageReference })}`);
    check("B: another team cannot see an image it cannot scan (404)", hiddenImageRuns.status === 404, hiddenImageRuns);
    const inspectByApprover = await call('defAp', 'POST', '/scans/pipeline-runs', { body: { reference: imageReference, action: 'image-inspection' } });
    check('B: starting an image inspection needs remediation:manage (403)', inspectByApprover.status === 403, inspectByApprover);

    const runs = await call('defOp', 'GET', '/remediation/RM-EXEC-0004/pipeline-runs');
    check('B: a job shows no pipeline actions while Azure DevOps automation is off', runs.status === 200 && runs.json.enabled === false, runs);
    const readiness = await call('defOp', 'GET', '/remediation/RM-DRY-0002/execution-readiness');
    check(
      'B: execution readiness reports the worker as not startable from SSI while automation is off',
      readiness.status === 200 &&
        readiness.json.workerConfigured === false &&
        readiness.json.dispatchAllowed === false &&
        readiness.json.requirements.some((item) => item.id === 'isolated-worker' && item.met === false) &&
        !readiness.json.requirements.some((item) => ['registry-output-policy', 'verification-rescan'].includes(item.id)),
      readiness,
    );
    const malformedApi = await fetch(`${BASE}/remediation/%E0%A4%A`);
    const malformedAsset = await fetch(`${BASE.replace('/api/v1', '')}/%E0%A4%A`);
    check(
      'B: a path that is not valid percent-encoding is answered 400, not 500',
      malformedApi.status === 400 && malformedAsset.status === 400,
      { api: malformedApi.status, asset: malformedAsset.status },
    );
    const runOff = await call('defOp', 'POST', '/remediation/RM-EXEC-0004/pipeline-runs', { body: { action: 'candidate-test' } });
    check('B: no pipeline run starts while Azure DevOps automation is off (503)', runOff.status === 503, runOff);
    const runDenied = await call('defAp', 'POST', '/remediation/RM-EXEC-0004/pipeline-runs', { body: { action: 'candidate-test' } });
    check('B: starting a pipeline needs remediation:manage (403 for an approver)', runDenied.status === 403, runDenied);
    const ado = await call('admin', 'GET', '/integrations/azure-devops');
    check('B: the Azure DevOps status reports "not configured" when no SSI_ADO_* is set', ado.status === 200 && ado.json.configured === false && ado.json.checks.length === 0, ado);
    const adoDenied = await call('defAp', 'GET', '/integrations/azure-devops');
    check('B: only a platform administrator can see the Azure DevOps status (403)', adoDenied.status === 403, adoDenied);
    await osTemplateChecks();
    await ubuntuTemplateChecks();
  } finally {
    await stopServer(server);
  }
}

await new Promise((resolve) => harbor.listen(HARBOR_PORT, '127.0.0.1', resolve));
let exitCode = 0;
try {
  await seed();
  await phaseFlagOff();
  await phaseFlagOn();
} catch (error) {
  console.error(error.stack || error);
  exitCode = 1;
} finally {
  harbor.close();
}
for (const result of results) console.log(`${result.ok ? 'PASS' : 'FAIL'}  ${result.name}${result.ok ? '' : `\n      ${result.detail}`}`);
const failed = results.filter((result) => !result.ok).length;
if (exitCode !== 0) console.log(`\nABORTED after ${results.length} checks (${failed} failed); see the error above.`);
else console.log(failed === 0 ? `\nALL ${results.length} CHECKS PASSED` : `\n${failed} of ${results.length} CHECKS FAILED`);
process.exit(failed > 0 ? 1 : exitCode);
