import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  MAX_REMOVALS,
  parseProtectedPatterns,
  parseRemovalImpact,
  previewRemoval,
  PROFILE_VERSION,
  protectionOf,
  selectablePackages,
  validateProfile,
} from './templateProfile.js';

const PROTECTED = parseProtectedPatterns(
  readFileSync(
    new URL('../../poc/os-template/profiles/protected-packages.txt', import.meta.url),
    'utf8',
  ),
);
const profile = (remove, extra = {}) => ({
  profileVersion: PROFILE_VERSION,
  name: 'web-minimal',
  baseTemplate: 'ssi-ubuntu-2404',
  remove,
  ...extra,
});
const line = (entry) =>
  JSON.stringify({ essential: false, required: false, refused: false, version: '1', ...entry });

// A small impact map shaped like guest/removal-impact.py writes it.
const IMPACT = parseRemovalImpact(
  [
    line({ package: 'nano', cascade: ['nano'] }),
    line({ package: 'telnet', cascade: ['telnet'] }),
    line({ package: 'libfoo1', cascade: ['libfoo1', 'foo-tools'] }),
    line({ package: 'foo-tools', cascade: ['foo-tools'] }),
    line({ package: 'libcore', cascade: ['libcore', 'openssh-server'] }),
    line({ package: 'openssh-server', cascade: ['openssh-server'] }),
    line({ package: 'bash', essential: true, cascade: ['bash'] }),
    line({ package: 'libc6', refused: true, cascade: ['libc6'] }),
  ].join('\n'),
);
const VULNS = [
  { id: 'CVE-1', pkg: 'telnet', severity: 'CRITICAL' },
  { id: 'CVE-2', pkg: 'foo-tools', severity: 'HIGH' },
  { id: 'CVE-3', pkg: 'libfoo1', severity: 'MEDIUM' },
  { id: 'CVE-2', pkg: 'libfoo1', severity: 'HIGH' }, // the same CVE in two packages counts once
];

describe('protected packages', () => {
  it('protect boot, access, first boot and the guest agents', () => {
    for (const name of [
      'linux-image-6.8.0-90-generic',
      'grub-efi-amd64-signed',
      'systemd',
      'openssh-server',
      'cloud-init',
      'apt',
      'sudo',
      'open-vm-tools',
      'qemu-guest-agent',
    ]) {
      expect(protectionOf(name, PROTECTED), name).toMatch(/^protected/);
    }
    expect(protectionOf('nano', PROTECTED)).toBeNull();
  });

  it('also protect every essential, required or apt-refused package, listed or not', () => {
    expect(protectionOf('bash', PROTECTED, { essential: true })).toBe('essential package');
    expect(protectionOf('mawk', PROTECTED, { required: true })).toBe('required-priority package');
    expect(protectionOf('libc6', PROTECTED, { refused: true })).toMatch(/apt refuses/);
  });

  it('treat only * as a wildcard and refuse anything else in the list', () => {
    expect(protectionOf('linux-image', ['linux-image-*'])).toBeNull();
    expect(protectionOf('python3x', ['python3'])).toBeNull();
    expect(protectionOf('python3.12', ['python3'])).toBeNull();
    expect(() => parseProtectedPatterns('apt\nrm -rf /\n')).toThrow(
      /Invalid protected package pattern/,
    );
    expect(parseProtectedPatterns('# comment\n\napt # trailing\n')).toEqual(['apt']);
  });
});

describe('validating a profile', () => {
  it('normalises a valid profile', () => {
    expect(
      validateProfile(profile(['telnet', 'nano', 'nano']), { protectedPatterns: PROTECTED }),
    ).toEqual({
      profileVersion: PROFILE_VERSION,
      name: 'web-minimal',
      description: '',
      baseTemplate: 'ssi-ubuntu-2404',
      remove: ['nano', 'telnet'],
    });
  });

  it('refuses typed commands, protected packages and every malformed field, all at once', () => {
    let error;
    try {
      validateProfile(
        profile(['nano;rm -rf /', 'openssh-server', 'Nano', ' x'], {
          name: 'Web Minimal',
          profileVersion: 'v0',
        }),
        {
          protectedPatterns: PROTECTED,
        },
      );
    } catch (caught) {
      error = caught;
    }
    expect(error?.statusCode).toBe(422);
    expect(error.problems).toEqual([
      'profileVersion must be ssi.os-template-profile/v1.',
      'name may hold lower-case letters, digits and dashes (2-63 characters).',
      'Not a package name: "nano;rm -rf /".',
      'openssh-server cannot be removed: protected (openssh-server).',
      'Not a package name: "Nano".',
      'Not a package name: " x".',
    ]);
  });

  it('bounds the size of a profile', () => {
    const many = Array.from({ length: MAX_REMOVALS + 1 }, (_, index) => `pkg${index}`);
    expect(() => validateProfile(profile(many))).toThrow(/at most 500/);
    expect(() => validateProfile(null)).toThrow(/JSON object/);
    expect(() => validateProfile(profile('nano'))).toThrow(/list of package names/);
  });

  it('accepts the shipped baseline profile', () => {
    const baseline = JSON.parse(
      readFileSync(
        new URL('../../poc/os-template/profiles/baseline.json', import.meta.url),
        'utf8',
      ),
    );
    expect(validateProfile(baseline, { protectedPatterns: PROTECTED }).remove).toEqual([]);
  });
});

describe('the selection list and its preview', () => {
  it('lists every package with what it takes along, its CVEs and whether it may be chosen', () => {
    const rows = selectablePackages({
      impact: IMPACT,
      vulnerabilities: VULNS,
      protectedPatterns: PROTECTED,
    });
    expect(rows[0]).toMatchObject({
      package: 'telnet',
      vulnerabilities: { total: 1, critical: 1 },
      selectable: true,
    });
    const byName = Object.fromEntries(rows.map((row) => [row.package, row]));
    expect(byName.libfoo1).toMatchObject({
      alsoRemoves: ['foo-tools'],
      cvesClosed: 2,
      selectable: true,
    });
    expect(byName.libcore).toMatchObject({
      selectable: false,
      reason: 'would also remove openssh-server',
    });
    expect(byName['openssh-server']).toMatchObject({
      selectable: false,
      reason: 'protected (openssh-server)',
    });
    expect(byName.bash.selectable).toBe(false);
    expect(byName.libc6.reason).toMatch(/apt refuses/);
  });

  it('previews the whole removal and counts each CVE once', () => {
    expect(
      previewRemoval({
        selected: ['libfoo1', 'telnet'],
        impact: IMPACT,
        vulnerabilities: VULNS,
        protectedPatterns: PROTECTED,
      }),
    ).toEqual({
      requested: ['libfoo1', 'telnet'],
      alsoRemoved: ['foo-tools'],
      total: 3,
      cvesClosed: 3,
      unknown: [],
      blocked: [],
      allowed: true,
    });
  });

  it('blocks a selection that would take a protected package along or names an unknown one', () => {
    const preview = previewRemoval({
      selected: ['libcore', 'ghost'],
      impact: IMPACT,
      protectedPatterns: PROTECTED,
    });
    expect(preview.allowed).toBe(false);
    expect(preview.blocked).toEqual([
      { package: 'openssh-server', reason: 'protected (openssh-server)' },
    ]);
    expect(preview.unknown).toEqual(['ghost']);
  });

  it('refuses an impact map that is not what the build VM writes', () => {
    expect(() => parseRemovalImpact('not json')).toThrow(/not JSON/);
    expect(() => parseRemovalImpact(line({ package: 'x;y', cascade: [] }))).toThrow(
      /invalid entry/,
    );
    expect(() => parseRemovalImpact(line({ package: 'nano', cascade: ['$(id)'] }))).toThrow(
      /invalid entry/,
    );
  });
});
