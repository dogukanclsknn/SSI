#!/usr/bin/env node
// OS template worker tool for azure-pipelines-os-template-windows.yml. The build script
// (poc/os-template/windows/Build-WindowsTemplate.ps1) writes template-manifest.json; this tool
// wraps it into the ssi.os-template-build/v1 result for one build request (src/lib/osTemplate.js)
// and delivers it to SSI with the worker HMAC signature.
//
// Commands:
//   assemble --manifest <template-manifest.json> --build-id <OST-…> --location-host <host>
//            --location-path <path of the ISO> --out <path>
//            [--pipeline <name>] [--ado-build-id <id>] [--agent <name>]
//   deliver  --file <result> --api-base-url <url> --worker-id <id> [--allow-http true]
//            Secret: SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET (environment only).
//            Exit code 0 = accepted, 2 = SSI temporarily unreachable, 1 = rejected or error.
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import {
  OS_TEMPLATE_BUILD_CONTRACT,
  OS_TEMPLATE_BUILD_ID,
  OS_TEMPLATE_MANIFEST_VERSION,
} from '../src/lib/osTemplate.js';
import { EVIDENCE_PURPOSE } from '../src/lib/workerEvidenceAuth.js';
import {
  deliverSignedEvidence,
  DeliveryUsageError,
  evidenceEndpoint,
} from './lib/signedEvidenceDelivery.mjs';

const EXIT_UNREACHABLE = 2;
const SECRET_NAME = 'SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET';

export class UsageError extends Error {}

function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    if (!name?.startsWith('--') || index + 1 >= args.length)
      throw new UsageError(`Invalid argument: ${name || '(missing)'}.`);
    options[name.slice(2)] = args[index + 1];
  }
  return options;
}

function required(options, name) {
  const value = options[name];
  if (value == null || value === '') throw new UsageError(`--${name} is required.`);
  return value;
}

// Windows PowerShell writes UTF-8 with a byte order mark; JSON.parse does not accept one.
function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch (error) {
    throw new UsageError(`${path} is not valid JSON: ${error.message}`);
  }
}

function writeAtomic(path, content) {
  const temporaryPath = `${path}.tmp-${process.pid}`;
  writeFileSync(temporaryPath, content, { mode: 0o600 });
  renameSync(temporaryPath, path);
}

// The result SSI validates; the manifest goes as written, SSI re-checks every field.
export function assembleResult(options, { generatedAt = new Date().toISOString() } = {}) {
  const buildId = String(required(options, 'build-id'));
  if (!OS_TEMPLATE_BUILD_ID.test(buildId))
    throw new UsageError('--build-id must look like OST-0001.');
  const manifest = readJson(required(options, 'manifest'));
  if (manifest?.manifestVersion !== OS_TEMPLATE_MANIFEST_VERSION) {
    throw new UsageError(`The manifest is not ${OS_TEMPLATE_MANIFEST_VERSION}.`);
  }
  return {
    contractVersion: OS_TEMPLATE_BUILD_CONTRACT,
    buildId,
    generatedAt,
    runner: {
      pipeline: String(options.pipeline || '').slice(0, 200),
      buildId: String(options['ado-build-id'] || '').slice(0, 64),
      agent: String(options.agent || '').slice(0, 128),
    },
    location: {
      host: String(required(options, 'location-host')),
      path: String(required(options, 'location-path')),
    },
    manifest,
  };
}

export async function deliver(options, { env = process.env, sleep } = {}) {
  const workerId = String(required(options, 'worker-id'))
    .replace(/[^A-Za-z0-9._:-]/g, '-')
    .slice(0, 128);
  const secret = env[SECRET_NAME] || '';
  if (!secret || secret.includes('$(')) throw new UsageError(`Secret ${SECRET_NAME} is required.`);
  const body = readFileSync(required(options, 'file'), 'utf8');
  const buildId = String(JSON.parse(body).buildId || '');
  if (!OS_TEMPLATE_BUILD_ID.test(buildId))
    throw new UsageError('The result does not name an OS template build request.');
  const endpoint = evidenceEndpoint(
    required(options, 'api-base-url'),
    `os-templates/${encodeURIComponent(buildId)}/worker`,
    {
      allowHttp: String(options['allow-http'] || '').toLowerCase() === 'true',
    },
  );
  return deliverSignedEvidence({
    endpoint,
    subject: buildId,
    body,
    secret,
    workerId,
    purpose: EVIDENCE_PURPOSE.OS_TEMPLATE,
    sleep,
  });
}

async function main(argv) {
  const [command, ...args] = argv;
  const options = parseOptions(args);
  if (command === 'assemble') {
    const result = assembleResult(options);
    writeAtomic(required(options, 'out'), `${JSON.stringify(result, null, 2)}\n`);
    return {
      output: `Result for ${result.buildId}: ${result.manifest.template?.name} ${result.manifest.template?.version}.`,
    };
  }
  if (command === 'deliver') {
    const result = await deliver(options);
    if (result.delivered)
      return { output: `OS template result accepted by SSI (HTTP ${result.status}).` };
    return {
      error: `OS template result ${result.permanent ? 'was rejected by SSI' : 'could not reach SSI'}: ${result.message}`,
      exitCode: result.permanent ? 1 : EXIT_UNREACHABLE,
    };
  }
  throw new UsageError(`Unknown command: ${command || '(missing)'}.`);
}

const invokedDirectly =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
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
      const known = [UsageError, DeliveryUsageError].some((type) => error instanceof type);
      process.stderr.write(`OS template result: ${known ? error.message : error.stack || error}\n`);
      process.exitCode = 1;
    });
}
