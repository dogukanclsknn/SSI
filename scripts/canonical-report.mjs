#!/usr/bin/env node
// Canonical scan worker tool for azure-pipelines-canonical-trivy-scan.yml: delivers the exact
// bytes of canonical-trivy.json to the SSI Dry Run it was scanned for, with the worker HMAC
// signature (src/lib/workerEvidenceAuth.js, purpose ssi-canonical-report-v1). SSI computes the
// content digest from these bytes; it is the digest the Copa worker verifies later.
//
// Command:
//   deliver --file <canonical-trivy.json> --job-id <RM-DRY-...> --api-base-url <url>
//           --worker-id <id> [--allow-http true]
//           Secret: SSI_CANONICAL_REPORT_HMAC_SECRET (environment only).
//           Exit code 0 = accepted, 2 = SSI temporarily unreachable, 1 = rejected or error.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { EVIDENCE_PURPOSE } from '../src/lib/workerEvidenceAuth.js';
import {
  deliverSignedEvidence,
  DeliveryUsageError,
  evidenceEndpoint,
} from './lib/signedEvidenceDelivery.mjs';

const EXIT_UNREACHABLE = 2;
const SECRET_NAME = 'SSI_CANONICAL_REPORT_HMAC_SECRET';
const JOB_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_REPORT_BYTES = 2 * 1024 * 1024;

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

export async function deliver(options, { env = process.env, sleep } = {}) {
  const jobId = String(required(options, 'job-id'));
  if (!JOB_ID_PATTERN.test(jobId)) throw new UsageError('--job-id is not a valid SSI job ID.');
  const workerId = String(required(options, 'worker-id'))
    .replace(/[^A-Za-z0-9._:-]/g, '-')
    .slice(0, 128);
  const secret = env[SECRET_NAME] || '';
  if (!secret || secret.includes('$(')) throw new UsageError(`Secret ${SECRET_NAME} is required.`);
  // The bytes are sent exactly as published: no parsing and re-serialising.
  const body = readFileSync(required(options, 'file'), 'utf8');
  if (Buffer.byteLength(body, 'utf8') > MAX_REPORT_BYTES)
    throw new UsageError('The canonical report is larger than 2 MiB.');
  const endpoint = evidenceEndpoint(
    required(options, 'api-base-url'),
    `remediation/${encodeURIComponent(jobId)}/worker-canonical-report`,
    { allowHttp: String(options['allow-http'] || '').toLowerCase() === 'true' },
  );
  return deliverSignedEvidence({
    endpoint,
    subject: jobId,
    body,
    secret,
    workerId,
    purpose: EVIDENCE_PURPOSE.CANONICAL_REPORT,
    sleep,
  });
}

async function main(argv) {
  const [command, ...args] = argv;
  if (command !== 'deliver') throw new UsageError(`Unknown command: ${command || '(missing)'}.`);
  const result = await deliver(parseOptions(args));
  if (result.delivered)
    return { output: `Canonical report accepted by SSI (HTTP ${result.status}).` };
  return {
    error: `Canonical report ${result.permanent ? 'was rejected by SSI' : 'could not reach SSI'}: ${result.message}`,
    exitCode: result.permanent ? 1 : EXIT_UNREACHABLE,
  };
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
      const known = error instanceof UsageError || error instanceof DeliveryUsageError;
      process.stderr.write(`Canonical report: ${known ? error.message : error.stack || error}\n`);
      process.exitCode = 1;
    });
}
