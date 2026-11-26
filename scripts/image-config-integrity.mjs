#!/usr/bin/env node
// Image configuration integrity gate for the Copa remediation pipeline
// (azure-pipelines-copa-remediation-poc.yml). The pipeline fetches raw registry
// documents with regctl; this tool verifies their bytes, compares the runtime
// configuration and plans or verifies a metadata-only restore. Comparison rules live in
// src/lib/imageConfigIntegrity.js.
//
// Commands (each prints one value or nothing; any failure exits 1):
//   verify-digest         --file <path> --digest <sha256:...>
//   select-image-manifest --manifest <path> [--platform <os/arch[/variant]>]
//   config-digest         --manifest <path>
//   platform              --config <path>
//   plan                  --source-config <path> --output-config <path> --output-manifest <path> --out-dir <dir>
//   field                 --file <path> --name <key>
//   verify                --plan <path> --source-config <path> --output-config <path>
//                         --output-manifest <path> --copa-output-digest <sha256:...>
//                         --output-digest <sha256:...> --out <path>
import { createHash } from 'node:crypto';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  canonicalJson,
  changedRuntimeFields,
  CONFIG_INTEGRITY_CONTRACT_VERSION,
  configDigestOf,
  ImageConfigIntegrityError,
  layerDigestsOf,
  manifestMediaTypeOf,
  planConfigRestore,
  platformOf,
  restoredImageManifest,
  runtimeConfigOf,
  selectImageManifest,
} from '../src/lib/imageConfigIntegrity.js';

const digestPattern = /^sha256:[a-f0-9]{64}$/;

function fail(message) {
  throw new ImageConfigIntegrityError(message);
}

function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    if (!name?.startsWith('--') || index + 1 >= args.length) fail(`Invalid argument: ${name || '(missing)'}.`);
    options[name.slice(2)] = args[index + 1];
  }
  return options;
}

function required(options, name) {
  const value = options[name];
  if (value == null || value === '') fail(`--${name} is required.`);
  return value;
}

function requiredDigest(options, name) {
  const value = required(options, name);
  if (!digestPattern.test(value)) fail(`--${name} must be a sha256 digest.`);
  return value;
}

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function readBytes(path) {
  return readFileSync(path);
}

function readJson(path) {
  try {
    return JSON.parse(readBytes(path).toString('utf8'));
  } catch (error) {
    return fail(`${path} is not valid JSON: ${error.message}`);
  }
}

function writeAtomic(path, bytes) {
  const temporaryPath = `${path}.tmp-${process.pid}`;
  writeFileSync(temporaryPath, bytes, { mode: 0o600 });
  renameSync(temporaryPath, path);
}

function writeJson(path, value) {
  writeAtomic(path, `${JSON.stringify(value, null, 2)}\n`);
}

const commands = {
  'verify-digest'(options) {
    const expected = requiredDigest(options, 'digest');
    const actual = sha256(readBytes(required(options, 'file')));
    if (actual !== expected) fail(`Content digest ${actual} does not match the expected ${expected}.`);
  },

  'select-image-manifest'(options) {
    const path = required(options, 'manifest');
    return selectImageManifest(readJson(path), options.platform || '') || sha256(readBytes(path));
  },

  'config-digest'(options) {
    return configDigestOf(readJson(required(options, 'manifest')));
  },

  platform(options) {
    return platformOf(readJson(required(options, 'config')));
  },

  plan(options) {
    const outputConfigPath = required(options, 'output-config');
    const outputManifest = readJson(required(options, 'output-manifest'));
    const outDir = required(options, 'out-dir');
    const plan = planConfigRestore({
      sourceConfig: readJson(required(options, 'source-config')),
      outputConfig: readJson(outputConfigPath),
    });
    const result = {
      status: plan.status,
      platform: plan.platform,
      changedFields: plan.changedFields,
      copaConfigDigest: sha256(readBytes(outputConfigPath)),
      copaLayerDigests: layerDigestsOf(outputManifest),
    };

    if (plan.restoredConfig) {
      const configBytes = Buffer.from(JSON.stringify(plan.restoredConfig), 'utf8');
      const configDigest = sha256(configBytes);
      const manifestBytes = Buffer.from(
        JSON.stringify(restoredImageManifest(outputManifest, { digest: configDigest, size: configBytes.length })),
        'utf8',
      );
      writeAtomic(join(outDir, 'restored-config.json'), configBytes);
      writeAtomic(join(outDir, 'restored-manifest.json'), manifestBytes);
      Object.assign(result, {
        restoredConfigDigest: configDigest,
        restoredManifestDigest: sha256(manifestBytes),
        restoredManifestMediaType: manifestMediaTypeOf(outputManifest),
      });
    }

    writeJson(join(outDir, 'plan.json'), result);
    return plan.status;
  },

  field(options) {
    const name = required(options, 'name');
    const value = readJson(required(options, 'file'))[name];
    if (value == null || value === '') fail(`Field ${name} is missing.`);
    return Array.isArray(value) ? value.join(', ') : String(value);
  },

  // Independent re-check of the exact image that will be copied to Harbor; writes the
  // configIntegrity evidence that SSI validates.
  verify(options) {
    const plan = readJson(required(options, 'plan'));
    const sourceConfigPath = required(options, 'source-config');
    const outputConfigPath = required(options, 'output-config');
    const sourceConfig = readJson(sourceConfigPath);
    const outputConfig = readJson(outputConfigPath);
    const copaOutputDigest = requiredDigest(options, 'copa-output-digest');
    const outputDigest = requiredDigest(options, 'output-digest');
    const restored = plan.status === 'restore-required';

    if (!['preserved', 'restore-required'].includes(plan.status)) fail(`Unknown plan status: ${plan.status}.`);
    const stillChanged = changedRuntimeFields(sourceConfig, outputConfig);
    if (stillChanged.length > 0) {
      fail(`The final image still differs from the source runtime configuration: ${stillChanged.join(', ')}.`);
    }
    if (platformOf(outputConfig, 'output') !== plan.platform) fail('The final image platform changed.');
    if (canonicalJson(layerDigestsOf(readJson(required(options, 'output-manifest')))) !== canonicalJson(plan.copaLayerDigests)) {
      fail('The final image layers differ from the Copa output layers.');
    }
    if (restored ? outputDigest !== plan.restoredManifestDigest : outputDigest !== copaOutputDigest) {
      fail('The final image digest does not match the verified Copa output or its restored manifest.');
    }

    const outputConfigDigest = sha256(readBytes(outputConfigPath));
    if (restored && outputConfigDigest !== plan.restoredConfigDigest) fail('The final config blob is not the restored config.');

    writeJson(required(options, 'out'), {
      contractVersion: CONFIG_INTEGRITY_CONTRACT_VERSION,
      status: restored ? 'restored' : 'preserved',
      verified: true,
      platform: plan.platform,
      restoredFields: restored ? plan.changedFields : [],
      layersPreserved: true,
      sourceConfigDigest: sha256(readBytes(sourceConfigPath)),
      copaOutputDigest,
      copaConfigDigest: plan.copaConfigDigest,
      outputDigest,
      outputConfigDigest,
      runtimeConfigDigest: sha256(canonicalJson(runtimeConfigOf(sourceConfig, 'source'))),
    });
    return restored ? 'restored' : 'preserved';
  },
};

try {
  const [command, ...args] = process.argv.slice(2);
  if (!Object.prototype.hasOwnProperty.call(commands, command || '')) fail(`Unknown command: ${command || '(missing)'}.`);
  const output = commands[command](parseOptions(args));
  if (output != null) process.stdout.write(`${output}\n`);
} catch (error) {
  process.stderr.write(`Image configuration integrity: ${error.message}\n`);
  process.exitCode = 1;
}
