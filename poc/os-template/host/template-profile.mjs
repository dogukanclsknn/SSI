#!/usr/bin/env node
// SSI OS template PoC — template profiles on the build host (docs/os-template-poc.md,
// "Template profili"). The rules live in src/lib/templateProfile.js, shared with the SSI screen.
//
//   node template-profile.mjs plan --profile P.json --protected protected-packages.txt --out remove.txt
//     validates the profile and writes the package list guest/minimize.sh removes
//     (exit 1 with the problems when the profile is invalid)
//
//   node template-profile.mjs catalog --impact removal-impact.jsonl --scan scan-after.json \
//       --protected protected-packages.txt --out packages.json
//     the list the screen offers: every installed package, what it takes along, its CVEs,
//     whether it may be chosen
//
//   node template-profile.mjs preview --profile P.json --impact removal-impact.jsonl \
//       --scan scan-after.json --protected protected-packages.txt
//     what the profile would remove and how many CVEs leave the template (exit 1 when blocked)
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  parseProtectedPatterns,
  parseRemovalImpact,
  previewRemoval,
  selectablePackages,
  TemplateProfileError,
  validateProfile,
} from '../../../src/lib/templateProfile.js';
import { vulnerabilitiesOf } from './template-report.mjs';

function options(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    if (!name?.startsWith('--') || argv[index + 1] === undefined)
      throw new Error(`Unexpected argument: ${name}`);
    parsed[name.slice(2)] = argv[index + 1];
  }
  return parsed;
}

const need = (opts, ...names) => {
  for (const name of names) if (!opts[name]) throw new Error(`--${name} is required.`);
};
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));

export function run([command, ...argv]) {
  const opts = options(argv);
  if (command === 'plan') {
    need(opts, 'profile', 'protected', 'out');
    const profile = validateProfile(readJson(opts.profile), {
      protectedPatterns: parseProtectedPatterns(readFileSync(opts.protected, 'utf8')),
    });
    writeFileSync(opts.out, profile.remove.map((name) => `${name}\n`).join(''));
    console.log(`Profile ${profile.name}: ${profile.remove.length} package(s) to remove.`);
    return 0;
  }
  if (command === 'catalog') {
    need(opts, 'impact', 'scan', 'protected', 'out');
    const rows = selectablePackages({
      impact: parseRemovalImpact(readFileSync(opts.impact, 'utf8')),
      vulnerabilities: vulnerabilitiesOf(readJson(opts.scan)),
      protectedPatterns: parseProtectedPatterns(readFileSync(opts.protected, 'utf8')),
    });
    writeFileSync(opts.out, `${JSON.stringify(rows, null, 2)}\n`);
    console.log(
      `${rows.length} packages, ${rows.filter((row) => row.selectable).length} selectable.`,
    );
    return 0;
  }
  if (command === 'preview') {
    need(opts, 'profile', 'impact', 'scan', 'protected');
    const protectedPatterns = parseProtectedPatterns(readFileSync(opts.protected, 'utf8'));
    const profile = validateProfile(readJson(opts.profile), { protectedPatterns });
    const preview = previewRemoval({
      selected: profile.remove,
      impact: parseRemovalImpact(readFileSync(opts.impact, 'utf8')),
      vulnerabilities: vulnerabilitiesOf(readJson(opts.scan)),
      protectedPatterns,
    });
    console.log(JSON.stringify(preview, null, 2));
    return preview.allowed ? 0 : 1;
  }
  throw new Error('usage: template-profile.mjs plan|catalog|preview [options]');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    process.exit(run(process.argv.slice(2)));
  } catch (error) {
    if (error instanceof TemplateProfileError) {
      for (const problem of error.problems) console.error(problem);
      process.exit(1);
    }
    console.error(error.message);
    process.exit(2);
  }
}
