// Shared delivery of HMAC-signed worker evidence to SSI (src/lib/workerEvidenceAuth.js).
//
// The same rules as the candidate test worker's delivery (scripts/candidate-test.mjs, which
// keeps its own copy for now): HTTPS unless the internal PoC opts into HTTP, no credentials
// in the URL, a fresh signature per attempt, three attempts with back-off for transient
// failures only, and a 1 MiB cap on SSI's answer.
//
// Result: { delivered, permanent, status, message, attempts }. A permanent result means SSI
// rejected the evidence (do not retry); otherwise SSI was unreachable.
import http from 'node:http';
import https from 'node:https';
import { createWorkerEvidenceHeaders } from '../../src/lib/workerEvidenceAuth.js';

const DELIVERY_ATTEMPTS = 3;
const REQUEST_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

export class DeliveryUsageError extends Error {}

// <apiBaseUrl>/<path>, refusing credentials, query, fragment and plain HTTP (unless allowed).
export function evidenceEndpoint(apiBaseUrl, path, { allowHttp = false } = {}) {
  let url;
  try {
    url = new URL(String(apiBaseUrl || ''));
  } catch {
    throw new DeliveryUsageError('--api-base-url is not a valid URL.');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new DeliveryUsageError('--api-base-url must not contain credentials, query parameters or a fragment.');
  }
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    throw new DeliveryUsageError('--api-base-url must use HTTPS unless --allow-http true is set for the internal PoC.');
  }
  url.pathname = `${url.pathname.replace(/\/$/, '')}/${path.replace(/^\//, '')}`;
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

// subject: what the signature is bound to (the job ID or the image digest of the route).
export async function deliverSignedEvidence({
  endpoint,
  subject,
  body,
  secret,
  workerId,
  purpose,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  let lastError;
  for (let attempt = 1; attempt <= DELIVERY_ATTEMPTS; attempt += 1) {
    // Fresh timestamp per attempt: SSI rejects signatures older than its replay window.
    const headers = createWorkerEvidenceHeaders({ jobId: subject, rawBody: body, secret, workerId, purpose });
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
  return {
    delivered: false,
    permanent: false,
    status: 0,
    message: String(lastError?.message || 'unreachable').slice(0, 300),
    attempts: DELIVERY_ATTEMPTS,
  };
}
