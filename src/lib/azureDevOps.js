// Azure DevOps pipeline integration (Phase 1): configuration, request building and response
// parsing for the Pipelines Runs REST API. Pure, no I/O; src/server/azureDevOpsClient.js
// performs the calls.
//
// SSI may start only the worker pipelines listed here (one environment variable per role),
// only in the configured organization and project, and only on the configured branch. The
// token is never part of a URL, a message or a result: it is turned into the Authorization
// header and nothing else. A token with more rights than SSI needs is therefore still
// confined to these calls by SSI itself.

export const ADO_API_VERSION = '7.1';

// Role → environment variable holding that pipeline's definition ID.
export const ADO_PIPELINE_ROLES = Object.freeze({
  onboardImport: 'SSI_ADO_PIPELINE_ONBOARD_IMPORT',
  canonicalScan: 'SSI_ADO_PIPELINE_CANONICAL_SCAN',
  copaRemediation: 'SSI_ADO_PIPELINE_COPA_REMEDIATION',
  candidateTest: 'SSI_ADO_PIPELINE_CANDIDATE_TEST',
  imageInspection: 'SSI_ADO_PIPELINE_IMAGE_INSPECTION',
  controlledPublish: 'SSI_ADO_PIPELINE_CONTROLLED_PUBLISH',
  supplyChainSign: 'SSI_ADO_PIPELINE_SUPPLY_CHAIN_SIGN',
  osTemplateWindows: 'SSI_ADO_PIPELINE_OS_TEMPLATE_WINDOWS',
  osTemplateUbuntu: 'SSI_ADO_PIPELINE_OS_TEMPLATE_UBUNTU',
});

const RUN_STATES = new Set(['unknown', 'inProgress', 'canceling', 'completed']);
const RUN_RESULTS = new Set(['unknown', 'succeeded', 'failed', 'canceled']);
// Azure DevOps Services only: the token must never be sent to any other host.
const allowedHost = (host) =>
  host === 'dev.azure.com' || /^[a-z0-9][a-z0-9-]{0,62}\.visualstudio\.com$/.test(host);
const projectPattern = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const refPattern = /^refs\/heads\/[A-Za-z0-9._/-]{1,200}$/;
const parameterNamePattern = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const controlCharacters = /[\p{Cc}\p{Cf}\u2028\u2029]/u;
const MAX_PARAMETERS = 20;
const MAX_PARAMETER_LENGTH = 2048;

export class AzureDevOpsError extends Error {
  constructor(message, { statusCode = 502, code = 'ado_error' } = {}) {
    super(message);
    this.name = 'AzureDevOpsError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

const text = (value) => String(value ?? '').trim();

// Reads the SSI_ADO_* settings. `configured` is true only when everything needed to call
// Azure DevOps is present and valid; `problems` names what is missing (never a value).
export function buildAzureDevOpsConfig(env = {}) {
  const problems = [];
  const rawUrl = text(env.SSI_ADO_ORG_URL);
  const project = text(env.SSI_ADO_PROJECT);
  const token = text(env.SSI_ADO_PAT);
  const ref = text(env.SSI_ADO_PIPELINE_REF) || 'refs/heads/main';
  const requested = Boolean(rawUrl || project || token);

  let orgUrl = '';
  if (rawUrl) {
    try {
      const url = new URL(rawUrl);
      if (url.protocol !== 'https:') problems.push('SSI_ADO_ORG_URL must use https.');
      else if (url.username || url.password || url.search || url.hash) {
        problems.push('SSI_ADO_ORG_URL must not contain credentials, a query or a fragment.');
      } else if (!allowedHost(url.hostname.toLowerCase())) {
        problems.push(
          'SSI_ADO_ORG_URL must be an Azure DevOps Services address (dev.azure.com or *.visualstudio.com).',
        );
      } else {
        orgUrl = `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
      }
    } catch {
      problems.push('SSI_ADO_ORG_URL is not a valid URL.');
    }
  } else if (requested) {
    problems.push('SSI_ADO_ORG_URL is not set.');
  }
  if (requested && !projectPattern.test(project))
    problems.push('SSI_ADO_PROJECT is missing or not a valid project name.');
  if (requested && (!token || /\s/.test(token) || token.length < 20 || token.length > 1024)) {
    problems.push('SSI_ADO_PAT is missing or malformed.');
  }
  if (!refPattern.test(ref))
    problems.push('SSI_ADO_PIPELINE_REF must look like refs/heads/<branch>.');

  // The SSI address the onboard, publish and sign workers call back (their ssiApiBaseUrl).
  // Optional: without it those three pipelines are simply not offered.
  let workerApiBaseUrl = '';
  const rawWorkerUrl = text(env.SSI_ADO_WORKER_API_BASE_URL);
  if (rawWorkerUrl) {
    try {
      const url = new URL(rawWorkerUrl);
      if (
        !['http:', 'https:'].includes(url.protocol) ||
        url.username ||
        url.password ||
        url.search ||
        url.hash
      ) {
        problems.push(
          'SSI_ADO_WORKER_API_BASE_URL must be an http(s) URL without credentials, a query or a fragment.',
        );
      } else {
        workerApiBaseUrl = `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
      }
    } catch {
      problems.push('SSI_ADO_WORKER_API_BASE_URL is not a valid URL.');
    }
  }

  const pipelines = {};
  for (const [role, variable] of Object.entries(ADO_PIPELINE_ROLES)) {
    const value = text(env[variable]);
    if (!value) continue;
    if (!/^[1-9][0-9]{0,9}$/.test(value))
      problems.push(`${variable} must be a pipeline definition ID (a positive number).`);
    else pipelines[role] = Number(value);
  }
  if (requested && Object.keys(pipelines).length === 0)
    problems.push('No SSI_ADO_PIPELINE_* definition ID is set.');

  return withToken(
    {
      requested,
      configured: requested && problems.length === 0,
      orgUrl,
      project,
      ref,
      workerApiBaseUrl,
      pipelines: Object.freeze(pipelines),
      problems: Object.freeze(problems),
    },
    token,
  );
}

// The token is kept off enumeration, so logging or serialising the config never shows it.
function withToken(config, token) {
  Object.defineProperty(config, 'token', { value: token, enumerable: false });
  return Object.freeze(config);
}

// The definition ID SSI may use for a role; refuses any role that is not configured.
export function pipelineIdFor(config, role) {
  const id = config?.pipelines?.[role];
  if (!Number.isSafeInteger(id)) {
    throw new AzureDevOpsError(`The ${role} pipeline is not configured for automatic runs.`, {
      statusCode: 409,
      code: 'ado_pipeline_not_configured',
    });
  }
  return id;
}

function projectBase(config) {
  return `${config.orgUrl}/${encodeURIComponent(config.project)}/_apis/pipelines`;
}

export function pipelineUrl(config, role) {
  return `${projectBase(config)}/${pipelineIdFor(config, role)}?api-version=${ADO_API_VERSION}`;
}

export function runsUrl(config, role) {
  return `${projectBase(config)}/${pipelineIdFor(config, role)}/runs?api-version=${ADO_API_VERSION}`;
}

export function runUrl(config, role, runId) {
  if (!Number.isSafeInteger(Number(runId)) || Number(runId) <= 0) {
    throw new AzureDevOpsError('Invalid Azure DevOps run ID.', {
      statusCode: 400,
      code: 'ado_bad_request',
    });
  }
  return `${projectBase(config)}/${pipelineIdFor(config, role)}/runs/${Number(runId)}?api-version=${ADO_API_VERSION}`;
}

function buildApiBase(config) {
  return `${config.orgUrl}/${encodeURIComponent(config.project)}/_apis/build`;
}

export function timelineUrl(config, buildId) {
  return `${buildApiBase(config)}/builds/${positiveId(buildId, 'run ID')}/timeline?api-version=${ADO_API_VERSION}`;
}

function positiveId(value, label) {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) {
    throw new AzureDevOpsError(`Invalid Azure DevOps ${label}.`, {
      statusCode: 400,
      code: 'ado_bad_request',
    });
  }
  return id;
}

// "Artifacts - Get Artifact" (Build, 7.1): JSON describes the artifact; with
// Accept: application/zip the same address returns the artifact's files as a zip.
const artifactNamePattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
export function artifactUrl(config, buildId, artifactName) {
  if (!artifactNamePattern.test(String(artifactName))) {
    throw new AzureDevOpsError('Invalid Azure DevOps artifact name.', {
      statusCode: 400,
      code: 'ado_bad_request',
    });
  }
  return `${buildApiBase(config)}/builds/${positiveId(buildId, 'run ID')}/artifacts?artifactName=${encodeURIComponent(artifactName)}&api-version=${ADO_API_VERSION}`;
}

// "Leases - Add" (Build, 7.1): keeps a run, and its artifacts, from the retention policy.
export function retentionLeasesUrl(config) {
  return `${buildApiBase(config)}/retention/leases?api-version=${ADO_API_VERSION}`;
}

// Longer than 36500 days Azure DevOps shows as "retained forever".
export const MAX_LEASE_DAYS = 36500;
const leaseOwnerPattern = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,99}$/;

export function buildRetentionLeaseBody({
  definitionId,
  runId,
  ownerId,
  daysValid = MAX_LEASE_DAYS,
}) {
  if (!leaseOwnerPattern.test(String(ownerId))) {
    throw new AzureDevOpsError('Invalid retention lease owner.', {
      statusCode: 400,
      code: 'ado_bad_request',
    });
  }
  const days = Number(daysValid);
  if (!Number.isSafeInteger(days) || days < 1 || days > MAX_LEASE_DAYS) {
    throw new AzureDevOpsError(`daysValid must be 1-${MAX_LEASE_DAYS}.`, {
      statusCode: 400,
      code: 'ado_bad_request',
    });
  }
  return [
    {
      daysValid: days,
      definitionId: positiveId(definitionId, 'pipeline ID'),
      ownerId: String(ownerId),
      protectPipeline: false,
      runId: positiveId(runId, 'run ID'),
    },
  ];
}

// The lease Azure DevOps created (RetentionLease[] with one entry).
export function parseRetentionLease(json) {
  const lease = Array.isArray(json) ? json[0] : null;
  const leaseId = Number(lease?.leaseId);
  if (!Number.isSafeInteger(leaseId) || leaseId <= 0) {
    throw new AzureDevOpsError('Azure DevOps returned an unexpected retention lease response.', {
      code: 'ado_bad_response',
    });
  }
  return {
    leaseId,
    runId: Number(lease.runId) || null,
    definitionId: Number(lease.definitionId) || null,
    validUntil: text(lease.validUntil) || null,
  };
}

// Where an artifact download may be redirected to: Azure DevOps itself, or the Azure blob
// storage it serves artifact content from. https only.
export function isAllowedArtifactHost(url) {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    return (
      parsed.protocol === 'https:' &&
      !parsed.username &&
      !parsed.password &&
      (allowedHost(host) || /^[a-z0-9-]{1,63}\.blob\.core\.windows\.net$/.test(host))
    );
  } catch {
    return false;
  }
}

export function authorizationHeader(token) {
  return `Basic ${Buffer.from(`:${token}`, 'utf8').toString('base64')}`;
}

// Request body of "Runs - Run Pipeline": the configured branch and the template parameters.
// Parameter values are single-line strings (booleans are sent as 'true' / 'false').
export function buildRunRequestBody(config, templateParameters = {}) {
  if (
    !templateParameters ||
    typeof templateParameters !== 'object' ||
    Array.isArray(templateParameters)
  ) {
    throw new AzureDevOpsError('Template parameters must be an object.', {
      statusCode: 400,
      code: 'ado_bad_request',
    });
  }
  const entries = Object.entries(templateParameters);
  if (entries.length > MAX_PARAMETERS) {
    throw new AzureDevOpsError(`At most ${MAX_PARAMETERS} template parameters are allowed.`, {
      statusCode: 400,
      code: 'ado_bad_request',
    });
  }
  const parameters = {};
  for (const [name, value] of entries) {
    if (!parameterNamePattern.test(name)) {
      throw new AzureDevOpsError(`Invalid template parameter name: ${name.slice(0, 64)}.`, {
        statusCode: 400,
        code: 'ado_bad_request',
      });
    }
    const textValue =
      typeof value === 'boolean' ? String(value) : typeof value === 'string' ? value : null;
    if (
      textValue === null ||
      textValue.length > MAX_PARAMETER_LENGTH ||
      controlCharacters.test(textValue)
    ) {
      throw new AzureDevOpsError(
        `Template parameter ${name} must be a single line of text or a boolean.`,
        {
          statusCode: 400,
          code: 'ado_bad_request',
        },
      );
    }
    parameters[name] = textValue;
  }
  return {
    resources: { repositories: { self: { refName: config.ref } } },
    templateParameters: parameters,
  };
}

// A run as SSI keeps it: identifiers, state, result and the web link (Azure DevOps host only).
export function parseRun(json) {
  const id = Number(json?.id);
  if (!Number.isSafeInteger(id) || id <= 0) {
    throw new AzureDevOpsError('Azure DevOps returned an unexpected run response.', {
      code: 'ado_bad_response',
    });
  }
  const state = RUN_STATES.has(json.state) ? json.state : 'unknown';
  const result = RUN_RESULTS.has(json.result) ? json.result : json.result ? 'unknown' : null;
  let webUrl = '';
  try {
    const url = new URL(String(json?._links?.web?.href || ''));
    if (url.protocol === 'https:' && allowedHost(url.hostname.toLowerCase())) webUrl = url.href;
  } catch {
    // no link
  }
  return {
    id,
    name: text(json.name).slice(0, 200),
    state,
    result,
    webUrl,
    createdDate: text(json.createdDate) || null,
    finishedDate: text(json.finishedDate) || null,
  };
}

// The public view of the configuration (admin status page): no token, no secret.
export function describeAzureDevOpsConfig(config) {
  return {
    configured: Boolean(config?.configured),
    requested: Boolean(config?.requested),
    orgUrl: config?.orgUrl || '',
    project: config?.project || '',
    ref: config?.ref || '',
    workerApiBaseUrl: config?.workerApiBaseUrl || '',
    pipelines: Object.entries(ADO_PIPELINE_ROLES).map(([role, variable]) => ({
      role,
      variable,
      id: config?.pipelines?.[role] ?? null,
    })),
    problems: [...(config?.problems || [])],
  };
}
