#!/usr/bin/env node
// Image inspection worker tool for azure-pipelines-image-inspection.yml. The pipeline collects
// the raw observations of one image (docker image inspect, Trivy OS package list); this tool
// builds the ssi.image-inspection/v1 evidence (src/lib/imageInspection.js), renders the run
// summary and delivers the evidence to SSI with the worker HMAC signature.
//
// Commands:
//   assemble --image-ref <registry/project/repository@sha256> --image <inspect.json>
//            --trivy <trivy.json> --out <path> [--pipeline <name>] [--build-id <id>] [--agent <name>]
//   summary  --file <evidence> --out <markdown>
//   deliver  --file <evidence> --api-base-url <url> --worker-id <id> [--allow-http true]
//            Secret: SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET (environment only).
//            Exit code 0 = accepted, 2 = SSI temporarily unreachable, 1 = rejected or error.
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { CandidateTestError } from '../src/lib/candidateTest.js';
import { formatBytes } from '../src/lib/imageComparison.js';
import { buildImageInspectionEvidence, ImageInspectionError } from '../src/lib/imageInspection.js';
import { EVIDENCE_PURPOSE } from '../src/lib/workerEvidenceAuth.js';
import { deliverSignedEvidence, DeliveryUsageError, evidenceEndpoint } from './lib/signedEvidenceDelivery.mjs';

const EXIT_UNREACHABLE = 2;
const SECRET_NAME = 'SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET';

class UsageError extends Error {}

function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    if (!name?.startsWith('--') || index + 1 >= args.length) throw new UsageError(`Invalid argument: ${name || '(missing)'}.`);
    options[name.slice(2)] = args[index + 1];
  }
  return options;
}

function required(options, name) {
  const value = options[name];
  if (value == null || value === '') throw new UsageError(`--${name} is required.`);
  return value;
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new UsageError(`${path} is not valid JSON: ${error.message}`);
  }
}

function writeAtomic(path, content) {
  const temporaryPath = `${path}.tmp-${process.pid}`;
  writeFileSync(temporaryPath, content, { mode: 0o600 });
  renameSync(temporaryPath, path);
}

// Markdown cell text: no table breaks, no HTML.
function cell(value) {
  return String(value ?? '')
    .replace(/[|\r\n]/g, ' ')
    .replace(/[<>]/g, '')
    .slice(0, 200);
}

export function renderSummary(evidence) {
  const facts = evidence.facts || {};
  const size = Number.isSafeInteger(facts.sizeBytes) ? formatBytes(facts.sizeBytes) : 'unknown';
  const config = facts.config || {};
  const lines = [
    '## SSI image inspection',
    '',
    `- Image: \`${cell(evidence.image?.immutableReference)}\``,
    `- Platform: \`${cell(evidence.platform)}\` · OS: ${cell(evidence.os)}`,
    `- OS packages: ${(evidence.packages || []).length}`,
    `- Layers: ${(facts.diffIds || []).length} · Size: ${size}`,
    `- Environment variables (names only): ${cell((config.Env || []).join(', ')) || 'none'}`,
    '',
    'SSI compares this image with any other inspected image in Scan Results → "Compare with another image".',
  ];
  return `${lines.join('\n')}\n`;
}

function assemble(options) {
  const evidence = buildImageInspectionEvidence({
    reference: required(options, 'image-ref'),
    image: readJson(required(options, 'image')),
    trivy: readJson(required(options, 'trivy')),
    runner: { pipeline: options.pipeline, buildId: options['build-id'], agent: options.agent },
  });
  writeAtomic(required(options, 'out'), `${JSON.stringify(evidence, null, 2)}\n`);
  return `${evidence.packages.length} OS packages, ${evidence.facts.diffIds.length} layers (${evidence.os}).`;
}

function summary(options) {
  writeAtomic(required(options, 'out'), renderSummary(readJson(required(options, 'file'))));
  return undefined;
}

export async function deliver(options, { env = process.env, sleep } = {}) {
  const workerId = String(required(options, 'worker-id')).replace(/[^A-Za-z0-9._:-]/g, '-').slice(0, 128);
  const secret = env[SECRET_NAME] || '';
  if (!secret || secret.includes('$(')) throw new UsageError(`Secret ${SECRET_NAME} is required.`);
  const body = readFileSync(required(options, 'file'), 'utf8');
  const digest = String(JSON.parse(body).image?.digest || '');
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new UsageError('The evidence does not name an image digest.');
  const endpoint = evidenceEndpoint(required(options, 'api-base-url'), `image-inspections/${encodeURIComponent(digest)}/worker`, {
    allowHttp: String(options['allow-http'] || '').toLowerCase() === 'true',
  });
  return deliverSignedEvidence({ endpoint, subject: digest, body, secret, workerId, purpose: EVIDENCE_PURPOSE.IMAGE_INSPECTION, sleep });
}

async function main(argv) {
  const [command, ...args] = argv;
  const options = parseOptions(args);
  if (command === 'assemble') return { output: assemble(options) };
  if (command === 'summary') return { output: summary(options) };
  if (command === 'deliver') {
    const result = await deliver(options);
    if (result.delivered) return { output: `Image inspection accepted by SSI (HTTP ${result.status}).` };
    return {
      error: `Image inspection ${result.permanent ? 'was rejected by SSI' : 'could not reach SSI'}: ${result.message}`,
      exitCode: result.permanent ? 1 : EXIT_UNREACHABLE,
    };
  }
  throw new UsageError(`Unknown command: ${command || '(missing)'}.`);
}

const invokedDirectly = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  main(process.argv.slice(2))
    .then(({ output, error, exitCode }) => {
      if (output) process.stdout.write(`${output}\n`);
      if (error) {
        process.stderr.write(`${error}\n`);
        process.exitCode = exitCode;
      }
    })
    .catch((error) => {
      const known = [UsageError, DeliveryUsageError, CandidateTestError, ImageInspectionError].some((type) => error instanceof type);
      process.stderr.write(`Image inspection: ${known ? error.message : error.stack || error}\n`);
      process.exitCode = 1;
    });
}
