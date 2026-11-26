#!/usr/bin/env node
// Candidate test worker tool for azure-pipelines-candidate-test.yml. The pipeline collects
// raw observations (docker image/container inspect, Trivy package lists); this tool builds
// the ssi.candidate-test/v1 evidence, renders the run summary and delivers the evidence to
// SSI with the worker HMAC signature. Analysis rules live in src/lib/candidateTest.js.
//
// Commands:
//   assemble --job-id <RM-EXEC-*> --source-ref <repo@sha256> --candidate-ref <repo@sha256>
//            --source-image <path> --candidate-image <path>
//            --source-container <path> --candidate-container <path>
//            --source-trivy <path> --candidate-trivy <path> --out <path>
//            [--pipeline <name>] [--build-id <id>] [--agent <name>]
//            Prints "passed" or "failed".
//   summary  --file <evidence> --out <markdown>
//   deliver  --file <evidence> --job-id <RM-EXEC-*> --api-base-url <url> --worker-id <id>
//            [--allow-http true]
//            Secret: SSI_CANDIDATE_TEST_EVIDENCE_HMAC_SECRET (environment only).
//            Exit code 0 = accepted, 2 = SSI temporarily unreachable, 1 = rejected or error.
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { pathToFileURL } from 'node:url';
import { buildCandidateTestEvidence, CandidateTestError } from '../src/lib/candidateTest.js';
import { formatBytes } from '../src/lib/imageComparison.js';
import { createWorkerEvidenceHeaders, EVIDENCE_PURPOSE } from '../src/lib/workerEvidenceAuth.js';

const EXIT_UNREACHABLE = 2;
const DELIVERY_ATTEMPTS = 3;
const REQUEST_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

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
  const lines = [
    `## SSI candidate test — ${evidence.passed ? 'PASSED' : 'FAILED'}`,
    '',
    `Job **${cell(evidence.remediationJobId)}** · platform \`${cell(evidence.platform)}\``,
    '',
    `- Source: \`${cell(evidence.source.immutableReference)}\``,
    `- Candidate: \`${cell(evidence.candidate.immutableReference)}\``,
    '',
    '| Check | Result | Detail |',
    '| --- | --- | --- |',
    ...evidence.checks.map((item) => `| ${cell(item.id)} | ${cell(item.status)} | ${cell(item.detail)} |`),
    '',
    '**Package changes**',
    '',
  ];
  const changes = evidence.packageChanges.changes;
  if (changes.length === 0) {
    lines.push('No OS package changed.');
  } else {
    lines.push('| Package | Change | From | To | Flag |', '| --- | --- | --- | --- | --- |');
    for (const item of changes.slice(0, 200)) {
      lines.push(
        `| ${cell(item.name)} | ${cell(item.change)} | ${cell(item.from)} | ${cell(item.to)} | ${item.majorVersionChange ? 'major version' : ''} |`,
      );
    }
    if (changes.length > 200) lines.push('', `… and ${changes.length - 200} more (see the evidence artifact).`);
  }
  const facts = evidence.imageFacts;
  if (facts) {
    const size = (value) => (Number.isSafeInteger(value) ? formatBytes(value) : 'unknown');
    lines.push(
      '',
      '**Image facts** (environment variables by name only)',
      '',
      `- Layers: ${facts.source.diffIds.length} → ${facts.candidate.diffIds.length}`,
      `- Size: ${size(facts.source.sizeBytes)} → ${size(facts.candidate.sizeBytes)}`,
    );
  }
  return `${lines.join('\n')}\n`;
}

function assemble(options) {
  const evidence = buildCandidateTestEvidence({
    jobId: required(options, 'job-id'),
    sourceReference: required(options, 'source-ref'),
    candidateReference: required(options, 'candidate-ref'),
    sourceImage: readJson(required(options, 'source-image')),
    candidateImage: readJson(required(options, 'candidate-image')),
    sourceContainer: readJson(required(options, 'source-container')),
    candidateContainer: readJson(required(options, 'candidate-container')),
    sourceTrivy: readJson(required(options, 'source-trivy')),
    candidateTrivy: readJson(required(options, 'candidate-trivy')),
    runner: { pipeline: options.pipeline, buildId: options['build-id'], agent: options.agent },
  });
  writeAtomic(required(options, 'out'), `${JSON.stringify(evidence, null, 2)}\n`);
  return evidence.passed ? 'passed' : 'failed';
}

function summary(options) {
  writeAtomic(required(options, 'out'), renderSummary(readJson(required(options, 'file'))));
  return undefined;
}

function endpointFor(options, jobId) {
  let url;
  try {
    url = new URL(required(options, 'api-base-url'));
  } catch (error) {
    if (error instanceof UsageError) throw error;
    throw new UsageError('--api-base-url is not a valid URL.');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new UsageError('--api-base-url must not contain credentials, query parameters or a fragment.');
  }
  const allowHttp = String(options['allow-http'] || '').toLowerCase() === 'true';
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    throw new UsageError('--api-base-url must use HTTPS unless --allow-http true is set for the internal PoC.');
  }
  url.pathname = `${url.pathname.replace(/\/$/, '')}/remediation/${encodeURIComponent(jobId)}/worker-candidate-test`;
  return url;
}

function postJson(url, headers, body) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      callback(value);
    };
    const request = transport.request(
      url,
      { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      (response) => {
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            const error = new Error('SSI response exceeded the 1 MiB safety limit.');
            error.permanent = true;
            response.destroy(error);
            finish(reject, error);
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => finish(resolve, { status: response.statusCode || 0, text: Buffer.concat(chunks).toString('utf8') }));
        response.on('error', (error) => finish(reject, error));
      },
    );
    const deadline = setTimeout(() => {
      const error = new Error(`SSI request timed out after ${REQUEST_TIMEOUT_MS} ms.`);
      request.destroy(error);
      finish(reject, error);
    }, REQUEST_TIMEOUT_MS);
    request.on('error', (error) => finish(reject, error));
    request.end(body);
  });
}

const isTransientStatus = (status) => [408, 425, 429].includes(status) || status >= 500;

export async function deliver(options, { env = process.env, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {}) {
  const jobId = required(options, 'job-id');
  if (!/^RM-EXEC-[0-9]{4,}$/.test(jobId)) throw new UsageError('--job-id must identify an RM-EXEC job.');
  const workerId = String(required(options, 'worker-id')).replace(/[^A-Za-z0-9._:-]/g, '-').slice(0, 128);
  const secret = env.SSI_CANDIDATE_TEST_EVIDENCE_HMAC_SECRET || '';
  if (!secret || secret.includes('$(')) throw new UsageError('Secret SSI_CANDIDATE_TEST_EVIDENCE_HMAC_SECRET is required.');
  const endpoint = endpointFor(options, jobId);
  const body = readFileSync(required(options, 'file'), 'utf8');
  const evidence = JSON.parse(body);
  if (evidence.remediationJobId !== jobId) throw new UsageError('The evidence belongs to another remediation job.');

  let lastError;
  for (let attempt = 1; attempt <= DELIVERY_ATTEMPTS; attempt += 1) {
    // Fresh timestamp per attempt: SSI rejects signatures older than its replay window.
    const headers = createWorkerEvidenceHeaders({ jobId, rawBody: body, secret, workerId, purpose: EVIDENCE_PURPOSE.CANDIDATE_TEST });
    try {
      const response = await postJson(endpoint, headers, body);
      if (response.status >= 200 && response.status < 300) {
        return { delivered: true, status: response.status, attempts: attempt };
      }
      let message = `HTTP ${response.status}`;
      try {
        message = JSON.parse(response.text).message || message;
      } catch {
        // Non-JSON error body: keep the status line only.
      }
      if (!isTransientStatus(response.status)) {
        return { delivered: false, permanent: true, status: response.status, message: String(message).slice(0, 300), attempts: attempt };
      }
      lastError = new Error(String(message).slice(0, 300));
    } catch (error) {
      if (error.permanent) return { delivered: false, permanent: true, status: 0, message: error.message, attempts: attempt };
      lastError = error;
    }
    if (attempt < DELIVERY_ATTEMPTS) await sleep(attempt * 1000);
  }
  return { delivered: false, permanent: false, status: 0, message: String(lastError?.message || 'unreachable').slice(0, 300), attempts: DELIVERY_ATTEMPTS };
}

async function main(argv) {
  const [command, ...args] = argv;
  const options = parseOptions(args);
  if (command === 'assemble') return { output: assemble(options) };
  if (command === 'summary') return { output: summary(options) };
  if (command === 'deliver') {
    const result = await deliver(options);
    if (result.delivered) return { output: `Candidate test evidence accepted by SSI (HTTP ${result.status}).` };
    return {
      error: `Candidate test evidence ${result.permanent ? 'was rejected by SSI' : 'could not reach SSI'}: ${result.message}`,
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
      const known = error instanceof UsageError || error instanceof CandidateTestError;
      process.stderr.write(`Candidate test: ${known ? error.message : error.stack || error}\n`);
      process.exitCode = 1;
    });
}
