import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runBash } from './pipelineSteps.testkit.js';

// The OS template PoC scripts (docs/os-template-poc.md), reused by the vCenter build.
const root = new URL('../../', import.meta.url);
const read = (path) => readFileSync(new URL(path, root), 'utf8');
const pocDir = new URL('poc/os-template/', root).pathname;
const scan = read('poc/os-template/guest/scan.sh');
const patch = read('poc/os-template/guest/patch.sh');
const seal = read('poc/os-template/guest/seal.sh');

const has = (tool) => {
  try {
    execFileSync('sh', ['-c', `command -v ${tool}`], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
};

describe('OS template guest scripts', () => {
  it('scan offline with the scanner and database the build host uploads', () => {
    for (const flag of [
      '--skip-db-update',
      '--offline-scan',
      '--pkg-types os',
      '--scanners vuln',
    ]) {
      expect(scan).toContain(flag);
    }
    // The upload does not always keep the executable bit; the script restores it.
    expect(scan).toContain('chmod 0755 "${TRIVY}"');
  });

  it('refuses a scan phase other than before or after', () => {
    const result = runBash(`bash "${join(pocDir, 'guest/scan.sh')}" during`, {});
    expect(result.ok).toBe(false);
    expect(result.status).toBe(2);
  });

  it('accepts only a plain http(s) URL as the internal package mirror', () => {
    const pattern = patch.match(/\[\[ ! "\$\{APT_MIRROR\}" =~ (\S+) \]\]/)[1];
    const accepts = (url) => runBash(`[[ "$URL" =~ ${pattern} ]]`, { URL: url }).ok;
    expect(accepts('http://mirror.internal/ubuntu')).toBe(true);
    expect(accepts('https://pulp.internal:8443/pulp/content/ubuntu/')).toBe(true);
    expect(accepts('http://user:secret@mirror/ubuntu')).toBe(false);
    expect(accepts('http://mirror/ubuntu?token=x')).toBe(false);
    expect(accepts('ftp://mirror/ubuntu')).toBe(false);
  });

  it('leave no build identity in the template', () => {
    for (const step of [
      'cloud-init clean --logs --seed --machine-id',
      'rm -f /etc/ssh/ssh_host_*',
      'rm -rf /var/tmp/ssi-scan',
      'rm -f /root/.bash_history',
    ]) {
      expect(seal).toContain(step);
    }
    expect(read('poc/os-template/cloud-init/user-data.pkrtpl')).toMatch(
      /lock_passwd: true[\s\S]*ssh_pwauth: false/,
    );
  });

  it('pass shellcheck', () => {
    if (!has('shellcheck')) return;
    const scripts = [
      'guest/wait-cloud-init.sh',
      'guest/scan.sh',
      'guest/patch.sh',
      'guest/seal.sh',
      'guest/prune-kernels.sh',
      'host/export.sh',
      'host/sign.sh',
      'linux/build-ubuntu-template.sh',
    ];
    expect(() =>
      execFileSync(
        'shellcheck',
        scripts.map((script) => join(pocDir, script)),
        { stdio: 'pipe' },
      ),
    ).not.toThrow();
  });
});

// guest/minimize.sh against the real apt of a Debian/Ubuntu machine, in dry-run mode only:
// nothing is ever removed by these tests.
const hasApt = has('apt-get') && has('dpkg-query');
const installed = (name) => {
  try {
    return (
      execFileSync('dpkg-query', ['-W', '-f=${db:Status-Status}', name], { encoding: 'utf8' }) ===
      'installed'
    );
  } catch {
    return false;
  }
};

describe('OS template minimisation (dry run on this machine)', () => {
  let directory;
  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  const minimize = (packages) => {
    directory = mkdtempSync(join(tmpdir(), 'ssi-minimize-'));
    const list = join(directory, 'remove.txt');
    execFileSync('sh', ['-c', 'printf "%s\\n" "$@" > "$0"', list, ...packages]);
    const result = runBash(`bash "${join(pocDir, 'guest/minimize.sh')}"`, {
      SCAN_DIR: directory,
      REMOVE_LIST: list,
      PROTECTED_LIST: join(pocDir, 'profiles/protected-packages.txt'),
      MINIMIZE_DRY_RUN: '1',
    });
    const out = (name) => readFileSync(join(directory, 'out', name), 'utf8');
    return { ...result, out };
  };

  it('refuses a typed command before apt is asked', () => {
    const result = minimize(['nano;rm -rf /']);
    expect(result.status).toBe(2);
    expect(result.output).toContain('not a package name');
  });

  it.skipIf(!hasApt || !installed('systemd'))(
    'refuses a protected package and changes nothing',
    () => {
      const before = execFileSync('dpkg-query', ['-W'], { encoding: 'utf8' });
      const result = minimize(['systemd']);
      expect(result.status).toBe(3);
      expect(result.output).toContain('protected (systemd)');
      expect(execFileSync('dpkg-query', ['-W'], { encoding: 'utf8' })).toBe(before);
    },
  );

  it.skipIf(!hasApt || !(installed('nano') || installed('less')))(
    'plans an ordinary removal and records packages that are not installed',
    () => {
      const target = installed('nano') ? 'nano' : 'less';
      const result = minimize([target, 'ssi-not-a-real-package']);
      expect(result.ok).toBe(true);
      expect(result.output).toContain('Dry run: nothing was removed.');
      expect(result.out('minimize-plan.tsv')).toMatch(
        new RegExp(`^${target}\\t\\S+\\trequested$`, 'm'),
      );
      expect(result.out('minimize-skipped.txt').trim()).toBe('ssi-not-a-real-package');
      expect(result.out('minimize-removed.tsv')).toBe('');
    },
  );
});

describe('OS template signing', () => {
  it('refuses to run without the signing key', () => {
    const result = runBash(`bash "${join(pocDir, 'host/sign.sh')}" /etc/hostname`, {
      COSIGN_PRIVATE_KEY: '$(COSIGN_PRIVATE_KEY)',
    });
    expect(result.ok).toBe(false);
    expect(result.output).toContain('COSIGN_PRIVATE_KEY is not set.');
  });
});

describe('OS template export (needs qemu-img)', () => {
  let directory;
  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  it.skipIf(!has('qemu-img'))(
    'writes a QCOW2 and an OVA whose descriptor comes first and whose manifest matches',
    () => {
      directory = mkdtempSync(join(tmpdir(), 'ssi-os-export-'));
      const source = join(directory, 'source.qcow2');
      execFileSync('qemu-img', ['create', '-q', '-f', 'qcow2', source, '1G']);
      const out = join(directory, 'out');
      execFileSync('bash', [join(pocDir, 'host/export.sh')], {
        env: {
          PATH: process.env.PATH,
          SOURCE_DISK: source,
          OUT_DIR: out,
          TEMPLATE_NAME: 'ssi-ubuntu-2404',
          TEMPLATE_VERSION: '20261120.1',
          BUILD_ID: 'test',
          OVF_TEMPLATE: join(pocDir, 'ovf/ubuntu-2404.ovf.tpl'),
        },
        stdio: 'pipe',
      });
      expect(readdirSync(out).sort()).toEqual([
        'SHA256SUMS',
        'ssi-ubuntu-2404-20261120.1.ova',
        'ssi-ubuntu-2404-20261120.1.qcow2',
      ]);
      const ova = join(out, 'ssi-ubuntu-2404-20261120.1.ova');
      const members = execFileSync('tar', ['-tf', ova], { encoding: 'utf8' }).trim().split('\n');
      expect(members).toEqual([
        'ssi-ubuntu-2404-20261120.1.ovf',
        'ssi-ubuntu-2404-20261120.1.mf',
        'ssi-ubuntu-2404-20261120.1-disk1.vmdk',
      ]);
      const ovf = execFileSync('tar', ['-xOf', ova, members[0]], { encoding: 'utf8' });
      expect(ovf).toContain('ovf:capacity="1073741824"');
      expect(ovf).not.toMatch(/@[A-Z_]+@/);
      expect(() =>
        execFileSync('sha256sum', ['-c', '--quiet', 'SHA256SUMS'], { cwd: out }),
      ).not.toThrow();
    },
  );

  it.skipIf(!has('qemu-img'))('adds a dynamic VHDX for Hyper-V when asked', () => {
    directory = mkdtempSync(join(tmpdir(), 'ssi-os-export-'));
    const source = join(directory, 'source.qcow2');
    execFileSync('qemu-img', ['create', '-q', '-f', 'qcow2', source, '1G']);
    const out = join(directory, 'out');
    execFileSync('bash', [join(pocDir, 'host/export.sh')], {
      env: {
        PATH: process.env.PATH,
        SOURCE_DISK: source,
        OUT_DIR: out,
        TEMPLATE_NAME: 'ssi-ubuntu-2404',
        TEMPLATE_VERSION: '1',
        BUILD_ID: 'test',
        OVF_TEMPLATE: join(pocDir, 'ovf/ubuntu-2404.ovf.tpl'),
        EXPORT_VHDX: 'true',
      },
      stdio: 'pipe',
    });
    const vhdx = join(out, 'ssi-ubuntu-2404-1.vhdx');
    expect(
      JSON.parse(execFileSync('qemu-img', ['info', '--output=json', vhdx], { encoding: 'utf8' })),
    ).toMatchObject({ format: 'vhdx', 'virtual-size': 1073741824 });
    expect(readFileSync(join(out, 'SHA256SUMS'), 'utf8')).toContain('ssi-ubuntu-2404-1.vhdx');
  });

  it.skipIf(!has('qemu-img'))('refuses to overwrite earlier artifacts', () => {
    directory = mkdtempSync(join(tmpdir(), 'ssi-os-export-'));
    const result = runBash(`touch "$OUT_DIR/old.ova"; bash "${join(pocDir, 'host/export.sh')}"`, {
      SOURCE_DISK: '/dev/null',
      OUT_DIR: directory,
      TEMPLATE_NAME: 'ssi-ubuntu-2404',
      TEMPLATE_VERSION: '1',
      BUILD_ID: 'test',
      OVF_TEMPLATE: join(pocDir, 'ovf/ubuntu-2404.ovf.tpl'),
    });
    expect(result.ok).toBe(false);
  });
});

// linux/build-ubuntu-template.sh refuses bad input before it downloads or changes anything.
describe('Ubuntu offline build inputs', () => {
  let directory;
  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  const build = (change) => {
    directory = mkdtempSync(join(tmpdir(), 'ssi-ubuntu-build-'));
    return runBash(`bash "${join(pocDir, 'linux/build-ubuntu-template.sh')}"`, {
      BASE_IMAGE_URL:
        'https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img',
      BASE_IMAGE_SHA256: 'c'.repeat(64),
      TEMPLATE_NAME: 'ssi-ubuntu-2404',
      BUILD_ID: 'test-1',
      WORK_DIR: join(directory, 'work'),
      TRIVY_CACHE_DIR: join(directory, 'no-trivy-cache'),
      ...change,
    });
  };

  it.each([
    [{ BASE_IMAGE_SHA256: 'c'.repeat(63) }, 'refuses an unpinned image'],
    [{ BASE_IMAGE_URL: 'https://user:pw@host/x.img' }, 'BASE_IMAGE_URL must be an https URL'],
    [
      { BASE_IMAGE_URL: 'http://cloud-images.ubuntu.com/x/a.img' },
      'BASE_IMAGE_URL must be an https URL',
    ],
    [{ TEMPLATE_NAME: "x'; rm -rf /" }, 'TEMPLATE_NAME is invalid'],
    [{ APT_MIRROR: 'http://mirror/ubuntu?token=1' }, 'APT_MIRROR must be'],
    [{ APT_PROXY: 'http://user:pw@proxy:3128' }, 'APT_PROXY must be'],
    [{ DISK_SIZE_GB: '20G' }, 'DISK_SIZE_GB must be'],
    [{}, 'prepare the Trivy database first'],
  ])('refuses %o', (change, message) => {
    const result = build(change);
    expect(result.status).toBe(2);
    expect(result.output).toContain(message);
  });
});

// The first ADO run (2026-11-24) scanned an extracted root whose etc/os-release was a symlink
// and had no etc/lsb-release: Trivy found no OS and reported 0 vulnerabilities before and after.
it('scans an extracted root Trivy recognises as Ubuntu, and refuses a scan that did not', () => {
  const script = read('poc/os-template/linux/build-ubuntu-template.sh');
  expect(script).toContain('download /etc/lsb-release ${root}/etc/lsb-release');
  expect(script).toContain('cp "${root}/usr/lib/os-release" "${root}/etc/os-release"');
  expect(script).not.toMatch(/ln -s[f]? [^\n]*os-release/);
  expect(script).toContain('--list-all-pkgs');
  expect(script).toMatch(
    /os_family}" == ubuntu && "\$\{os_name}" == 24\.04 && "\$\{os_packages:-0}" -gt 0/,
  );
});
