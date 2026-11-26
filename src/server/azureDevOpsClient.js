// Azure DevOps Pipelines REST client (Phase 1). The only calls it makes:
//   GET  {org}/{project}/_apis/pipelines/{id}                – read a pipeline definition
//   POST {org}/{project}/_apis/pipelines/{id}/runs           – start a run
//   GET  {org}/{project}/_apis/pipelines/{id}/runs/{runId}   – read a run
//   GET  {org}/{project}/_apis/build/builds/{runId}/artifacts?artifactName=…
//                                                            – JSON: does the run hold it;
//                                                              Accept: zip: stream it (OS templates)
//   POST {org}/{project}/_apis/build/retention/leases        – retain a run (approved template)
// where {id} is one of the configured worker pipelines (src/lib/azureDevOps.js).
// Redirects are not followed (an expired token is answered with a sign-in redirect or a
// 203 page), responses are size-limited, and no error message ever carries the token.
import { Readable } from 'node:stream';
import {
  ADO_PIPELINE_ROLES,
  artifactUrl,
  AzureDevOpsError,
  authorizationHeader,
  buildRetentionLeaseBody,
  buildRunRequestBody,
  isAllowedArtifactHost,
  parseRetentionLease,
  parseRun,
  pipelineIdFor,
  pipelineUrl,
  runsUrl,
  retentionLeasesUrl,
  runUrl,
  timelineUrl,
} from '../lib/azureDevOps.js';
import { parseTimelineProgress } from '../lib/onboardingProgress.js';

const DEFAULT_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
// Artifact downloads: the headers must arrive within this time; the body then streams for as
// long as it keeps moving (the caller watches idle time). At most this many redirects.
const ARTIFACT_HEADERS_TIMEOUT_MS = 60000;
const MAX_ARTIFACT_REDIRECTS = 3;
const ARTIFACT_CONTENT_TYPES = ['application/zip', 'application/octet-stream'];
const EMPTY_ZIP_BYTES = 22;

// Azure DevOps error bodies carry a `message`; keep one line of it, never more.
function adoMessage(textBody) {
  try {
    const message = JSON.parse(textBody)?.message;
    return typeof message === 'string' ? message.replace(/[\r\n]+/g, ' ').slice(0, 200) : '';
  } catch {
    return '';
  }
}

export function createAzureDevOpsClient(
  config,
  {
    fetchImpl = globalThis.fetch,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    artifactHeadersTimeoutMs = ARTIFACT_HEADERS_TIMEOUT_MS,
  } = {},
) {
  const enabled = Boolean(config?.configured);

  function assertEnabled() {
    if (!enabled) {
      throw new AzureDevOpsError('Azure DevOps integration is not configured.', {
        statusCode: 503,
        code: 'ado_not_configured',
      });
    }
  }

  async function call(method, url, body) {
    assertEnabled();
    let response;
    try {
      response = await fetchImpl(url, {
        method,
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
        headers: {
          Accept: 'application/json',
          Authorization: authorizationHeader(config.token),
          ...(body ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (error) {
      const timedOut = error?.name === 'TimeoutError' || error?.name === 'AbortError';
      throw new AzureDevOpsError(
        timedOut
          ? `Azure DevOps did not answer within ${Math.round(timeoutMs / 1000)} seconds.`
          : 'Azure DevOps could not be reached.',
        { statusCode: 504, code: 'ado_unreachable' },
      );
    }

    const textBody = await response.text().catch(() => '');
    if (textBody.length > MAX_RESPONSE_BYTES) {
      throw new AzureDevOpsError('Azure DevOps response exceeded the 1 MiB safety limit.', {
        code: 'ado_bad_response',
      });
    }
    const status = response.status;
    const isJson = String(response.headers?.get?.('content-type') || '').includes(
      'application/json',
    );

    if ((status === 200 || status === 201) && isJson) {
      try {
        return JSON.parse(textBody);
      } catch {
        throw new AzureDevOpsError('Azure DevOps returned invalid JSON.', {
          code: 'ado_bad_response',
        });
      }
    }
    // 203 + sign-in page, a redirect or 401: the token was not accepted.
    if (
      status === 203 ||
      status === 401 ||
      (status >= 300 && status < 400) ||
      ((status === 200 || status === 201) && !isJson)
    ) {
      throw new AzureDevOpsError(
        'Azure DevOps did not accept the token (expired, revoked or wrong organization).',
        {
          code: 'ado_auth',
        },
      );
    }
    const detail = adoMessage(textBody);
    if (status === 403) {
      throw new AzureDevOpsError(
        `The token has no permission for this pipeline.${detail ? ` ${detail}` : ''}`,
        { code: 'ado_forbidden' },
      );
    }
    if (status === 404) {
      throw new AzureDevOpsError(
        `The pipeline was not found in the configured project.${detail ? ` ${detail}` : ''}`,
        {
          code: 'ado_not_found',
        },
      );
    }
    if (status === 400) {
      throw new AzureDevOpsError(`Azure DevOps refused the request.${detail ? ` ${detail}` : ''}`, {
        statusCode: 422,
        code: 'ado_rejected',
      });
    }
    throw new AzureDevOpsError(`Azure DevOps answered HTTP ${status}.`, {
      statusCode: 502,
      code: 'ado_unavailable',
    });
  }

  // "Artifacts - Get Artifact" as JSON: whether the run still holds the artifact.
  async function describeArtifact(runId, artifactName) {
    assertEnabled();
    let json;
    try {
      json = await call('GET', artifactUrl(config, runId, artifactName));
    } catch (error) {
      if (error instanceof AzureDevOpsError && error.code === 'ado_not_found') {
        throw new AzureDevOpsError(
          `Azure DevOps run ${runId} has no artifact ${artifactName} (removed by retention, or never published under that name).`,
          { statusCode: 404, code: 'ado_not_found' },
        );
      }
      throw error;
    }
    if (String(json?.name || '') !== artifactName) {
      throw new AzureDevOpsError('Azure DevOps returned an unexpected artifact response.', {
        code: 'ado_bad_response',
      });
    }
    return { name: json.name, id: Number(json.id) || null };
  }

  // Opens a run artifact as a zip stream: "Get Artifact" with Accept: application/zip (in
  // production on 2026-11-25 this streamed the artifact; the resource.downloadUrl of the same
  // artifact answered with an empty body). Redirects are followed only to Azure DevOps and
  // Azure blob storage over https, and the token is sent to the organization's own host only.
  async function openArtifact(runId, artifactName, { signal } = {}) {
    assertEnabled();
    const orgHost = new URL(config.orgUrl).host;
    let url = artifactUrl(config, runId, artifactName);
    for (let hop = 0; hop <= MAX_ARTIFACT_REDIRECTS; hop += 1) {
      const target = new URL(url);
      // The time limit covers the wait for the response headers only. It must not stay on the
      // request: a signal given to fetch also aborts the body, and an AbortSignal.timeout here
      // cut every download after 60 seconds (production, 2026-11-25: 4 GB arrived as 157-298 MB,
      // "The operation was aborted due to timeout"). Once the body flows, the caller's signal
      // (the browser left, or no data for the idle limit) is the only one that ends it.
      const hop = new AbortController();
      const forward = () => hop.abort(signal.reason);
      if (signal?.aborted) forward();
      else signal?.addEventListener('abort', forward, { once: true });
      const headersTimer = setTimeout(
        () => hop.abort(new Error('No response headers in time.')),
        artifactHeadersTimeoutMs,
      );
      let response;
      try {
        response = await fetchImpl(url, {
          method: 'GET',
          redirect: 'manual',
          signal: hop.signal,
          headers: {
            Accept: 'application/zip',
            ...(target.host === orgHost
              ? { Authorization: authorizationHeader(config.token) }
              : {}),
          },
        });
      } catch {
        signal?.removeEventListener('abort', forward);
        throw new AzureDevOpsError('Azure DevOps could not be reached for the artifact.', {
          statusCode: 504,
          code: 'ado_unreachable',
        });
      } finally {
        clearTimeout(headersTimer);
      }
      const status = response.status;
      if (status >= 300 && status < 400 && status !== 304) {
        const location = response.headers?.get?.('location') || '';
        await response.body?.cancel?.().catch(() => {});
        const next = location ? new URL(location, url).href : '';
        if (!next || !isAllowedArtifactHost(next)) {
          // A sign-in redirect lands on another host: the token was not accepted.
          throw new AzureDevOpsError(
            'Azure DevOps did not hand out the artifact (the token was not accepted or the download was redirected to an unexpected host).',
            { code: 'ado_auth' },
          );
        }
        url = next;
        continue;
      }
      const contentType = String(response.headers?.get?.('content-type') || '').toLowerCase();
      if (status === 200 && ARTIFACT_CONTENT_TYPES.some((type) => contentType.startsWith(type))) {
        // Azure DevOps streams artifact zips without a Content-Length (chunked). A missing header
        // is "length unknown", never 0: Number(null) is 0, which once declared every download
        // empty and cut the transfer after the first chunk.
        const rawLength = String(response.headers?.get?.('content-length') ?? '').trim();
        const length = /^[0-9]{1,15}$/.test(rawLength) ? Number(rawLength) : null;
        // 22 bytes is a zip with no file in it: never hand that out as the template.
        if (length !== null && length <= EMPTY_ZIP_BYTES) {
          await response.body?.cancel?.().catch(() => {});
          throw new AzureDevOpsError(
            `Azure DevOps returned an empty archive for ${artifactName} of run ${runId}.`,
            { code: 'ado_bad_response' },
          );
        }
        return {
          stream: Readable.fromWeb(response.body),
          contentLength: length,
        };
      }
      const textBody = await response.text().catch(() => '');
      const detail = adoMessage(textBody.slice(0, MAX_RESPONSE_BYTES));
      if (status === 404) {
        throw new AzureDevOpsError(
          'The artifact is no longer in Azure DevOps (the run or its artifacts were removed by retention).',
          { statusCode: 404, code: 'ado_not_found' },
        );
      }
      if (status === 403) {
        throw new AzureDevOpsError(
          `The token may not read this run's artifacts.${detail ? ` ${detail}` : ''}`,
          { code: 'ado_forbidden' },
        );
      }
      if (status === 203 || status === 401 || status === 200) {
        throw new AzureDevOpsError(
          'Azure DevOps did not accept the token (expired, revoked or wrong organization).',
          { code: 'ado_auth' },
        );
      }
      throw new AzureDevOpsError(`Azure DevOps answered HTTP ${status} for the artifact.`, {
        statusCode: 502,
        code: 'ado_unavailable',
      });
    }
    throw new AzureDevOpsError('Azure DevOps redirected the artifact download too many times.', {
      code: 'ado_bad_response',
    });
  }

  return {
    enabled,

    openArtifact,

    // Whether a run still holds this artifact: checked before a download is offered, so a
    // removed artifact is reported to the screen, not to the link.
    getArtifact: describeArtifact,

    // Keeps an approved template's run (and so its artifacts) from the retention policy.
    async addRetentionLease({ role, runId, ownerId }) {
      assertEnabled();
      const body = buildRetentionLeaseBody({
        definitionId: pipelineIdFor(config, role),
        runId,
        ownerId,
      });
      return parseRetentionLease(await call('POST', retentionLeasesUrl(config), body));
    },

    async getPipeline(role) {
      assertEnabled();
      const json = await call('GET', pipelineUrl(config, role));
      return {
        id: Number(json?.id) || pipelineIdFor(config, role),
        name: String(json?.name || '').slice(0, 200),
        folder: String(json?.folder || ''),
      };
    },

    async runPipeline(role, templateParameters) {
      assertEnabled();
      const body = buildRunRequestBody(config, templateParameters);
      return parseRun(await call('POST', runsUrl(config, role), body));
    },

    async getRun(role, runId) {
      assertEnabled();
      return parseRun(await call('GET', runUrl(config, role, runId)));
    },

    async getRunProgress(role, runId) {
      pipelineIdFor(config, role);
      return parseTimelineProgress(await call('GET', timelineUrl(config, runId)));
    },

    // Read-only health check of every configured pipeline: can SSI see it with this token?
    async checkPipelines() {
      const results = [];
      for (const role of Object.keys(ADO_PIPELINE_ROLES)) {
        const id = config?.pipelines?.[role] ?? null;
        if (id === null) {
          results.push({ role, id, ok: false, name: '', error: 'Not configured' });
          continue;
        }
        try {
          const pipeline = await this.getPipeline(role);
          results.push({ role, id, ok: true, name: pipeline.name, error: '' });
        } catch (error) {
          results.push({
            role,
            id,
            ok: false,
            name: '',
            error: error instanceof AzureDevOpsError ? error.message : 'Unexpected error',
          });
        }
      }
      return results;
    },
  };
}
