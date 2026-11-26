import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// poc/os-template/windows: vulnerability detection for an offline Windows image (MSRC data)
// and the template build (docs/os-template-poc.md, "Windows"). The pure functions run under
// PowerShell 7 here; the build machine runs Windows PowerShell 5.1.
const root = new URL('../../', import.meta.url);
const windowsDir = new URL('poc/os-template/windows/', root).pathname;
const modulePath = join(windowsDir, 'SsiWindowsTemplate.psm1');
const read = (name) => readFileSync(join(windowsDir, name), 'utf8');

const hasPwsh = (() => {
  try {
    execFileSync('pwsh', ['-NoProfile', '-Command', 'exit 0'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

// Each case starts a PowerShell process: 1-2 s of cold start on the CI agent. The suites
// below allow for it instead of Vitest's 5 s default.
const PWSH_TIMEOUT = { timeout: 60_000 };

// Runs PowerShell with the module imported; the script's last output is returned as JSON.
const powershell = (script) =>
  JSON.parse(
    execFileSync(
      'pwsh',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `$ErrorActionPreference='Stop'; Import-Module '${modulePath}' -Force; ${script} | ConvertTo-Json -Depth 6 -Compress`,
      ],
      // stderr is captured (it is in the thrown error), so expected refusals do not clutter the CI log.
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    ) || 'null',
  );

const product = (id, value) => ({ ProductID: id, Value: value });
const fix = (kb, build, ids, type = 2) => ({
  Description: { Value: kb },
  Type: type,
  ProductID: ids,
  ...(build ? { FixedBuild: build } : {}),
});
const severity = (value, ids) => ({ Type: 3, Description: { Value: value }, ProductID: ids });
const month = (id, vulnerabilities) => ({
  DocumentTracking: { Identification: { ID: { Value: id } } },
  ProductTree: {
    FullProductName: [
      product('100', 'Windows Server 2025'),
      product('101', 'Windows Server 2025 (Server Core installation)'),
      product('200', 'Windows 11 Version 24H2 for x64-based Systems'),
    ],
  },
  Vulnerability: vulnerabilities,
});

// Shaped like the MSRC CVRF v3.0 JSON documents.
const DOCUMENTS = [
  month('2026-Feb', [
    {
      CVE: 'CVE-2026-0001',
      Title: { Value: 'Windows SMB Remote Code Execution Vulnerability' },
      Threats: [severity('Critical', ['100', '101'])],
      CVSSScoreSets: [{ BaseScore: 9.8, ProductID: ['100'] }],
      Remediations: [fix('5000001', '10.0.26100.32500', ['100', '101'])],
    },
    {
      CVE: 'CVE-2026-0002',
      Title: { Value: 'Fixed in the image already' },
      Threats: [severity('Important', ['100'])],
      Remediations: [fix('4999999', '10.0.26100.32230', ['100'])],
    },
    {
      CVE: 'CVE-2026-0003',
      Title: { Value: 'Another product only' },
      Threats: [severity('Critical', ['200'])],
      Remediations: [fix('5000001', '10.0.26100.32500', ['200'])],
    },
    {
      CVE: 'CVE-2026-0004',
      Title: { Value: 'No fixed build (not a Windows cumulative update)' },
      Remediations: [fix('5000003', null, ['100'])],
    },
    {
      CVE: 'CVE-2026-0005',
      Title: { Value: 'Workaround only' },
      Remediations: [fix('Workaround', '10.0.26100.32500', ['100'], 0)],
    },
  ]),
  month('2026-Mar', [
    {
      CVE: 'CVE-2026-0001',
      Title: { Value: 'Windows SMB Remote Code Execution Vulnerability' },
      Threats: [severity('Critical', ['100'])],
      Remediations: [fix('5000002', '10.0.26100.32600', ['100'])],
    },
    {
      // Optional fields (Threats, CVSSScoreSets) absent.
      CVE: 'CVE-2026-0006',
      Title: { Value: 'Windows Kernel Elevation of Privilege Vulnerability' },
      Remediations: [fix('5000002', '10.0.26100.32600', ['100'])],
    },
  ]),
];

describe.skipIf(!hasPwsh)(
  'Windows template: open vulnerabilities from MSRC data',
  PWSH_TIMEOUT,
  () => {
    let directory;
    beforeEach(() => {
      directory = mkdtempSync(join(tmpdir(), 'ssi-windows-'));
      writeFileSync(join(directory, 'cvrf.json'), JSON.stringify(DOCUMENTS));
    });
    afterEach(() => rmSync(directory, { recursive: true, force: true }));

    const open = (build) =>
      powershell(
        `$docs = Get-Content -Raw '${join(directory, 'cvrf.json')}' | ConvertFrom-Json; ` +
          `$open = Get-OpenVulnerability -Document $docs -Product 'Windows Server 2025' -ImageBuild ${build}; ` +
          `[pscustomobject]@{ rows = @($open | Select-Object CVE,Severity,CVSS,KB,FixedBuild,Month); summary = Get-VulnerabilitySummary -Vulnerability $open }`,
      );

    it('counts only vendor fixes for the product that are newer than the image', () => {
      const { rows, summary } = open('10.0.26100.32230');
      expect(rows.map((row) => row.CVE)).toEqual(['CVE-2026-0001', 'CVE-2026-0006']);
      expect(summary).toEqual({
        Total: 2,
        Critical: 1,
        Important: 0,
        Other: 1,
        RequiredKb: 'KB5000002',
        RequiredBuild: '10.0.26100.32600',
      });
    });

    it('describes a re-released CVE by its newest fix, the one that closes it', () => {
      const [first] = open('10.0.26100.32230').rows;
      expect(first).toEqual({
        CVE: 'CVE-2026-0001',
        Severity: 'Critical',
        CVSS: null, // the March record carries no score
        KB: 'KB5000002',
        FixedBuild: '10.0.26100.32600',
        Month: '2026-Mar',
      });
    });

    it('reports a current image as clean, with nothing to install', () => {
      const { rows, summary } = open('10.0.26100.32600');
      expect(rows).toEqual([]);
      expect(summary).toMatchObject({ Total: 0, RequiredKb: null, RequiredBuild: null });
    });

    it('writes a readable report even when nothing is open', () => {
      const prefix = join(directory, 'scan-after');
      powershell(
        `Export-VulnerabilityReport -Vulnerability @() -Product 'Windows Server 2025' -ImageBuild 10.0.26100.32600 -Months @('2026-Mar') -Path '${prefix}'`,
      );
      const report = JSON.parse(readFileSync(`${prefix}.json`, 'utf8'));
      expect(report).toMatchObject({
        product: 'Windows Server 2025',
        imageBuild: '10.0.26100.32600',
        months: ['2026-Mar'],
        open: { total: 0, critical: 0, important: 0, other: 0 },
        requiredKb: null,
      });
      expect(
        readFileSync(`${prefix}.csv`, 'utf8')
          .replace(/^\uFEFF/, '')
          .trim(),
      ).toBe('"CVE","Title","Severity","CVSS","KB","FixedBuild","Month"');
    });
  },
);

describe.skipIf(!hasPwsh)('Windows template: inputs', PWSH_TIMEOUT, () => {
  let directory;
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'ssi-windows-'));
  });
  afterEach(() => rmSync(directory, { recursive: true, force: true }));

  const msu = (name, content = 'cumulative update') => {
    const path = join(directory, name);
    writeFileSync(path, content);
    return path;
  };
  const sha1 = (content) => createHash('sha1').update(content).digest('hex');

  it('accepts an update whose content matches the SHA-1 in its catalog name', () => {
    const path = msu(`windows11.0-kb5131080-x64_${sha1('cumulative update')}.msu`);
    expect(powershell(`Assert-MsuIntegrity -Path '${path}' | Select-Object KB,Sha256`)).toEqual({
      KB: 'KB5131080',
      Sha256: createHash('sha256').update('cumulative update').digest('hex'),
    });
  });

  it('refuses a damaged update and one without a hash in its name', () => {
    const damaged = msu(`windows11.0-kb5131080-x64_${sha1('something else')}.msu`);
    expect(() => powershell(`Assert-MsuIntegrity -Path '${damaged}'`)).toThrow(/does not match/);
    const renamed = msu('kb5131080.msu');
    expect(() => powershell(`Assert-MsuIntegrity -Path '${renamed}'`)).toThrow(/carries no SHA-1/);
  });

  it('reads name, build and creation time from DISM output', () => {
    const text = [
      'Deployment Image Servicing and Management tool',
      'Version: 10.0.26100.9457',
      '',
      'Details for image : F:\\sources\\install.wim',
      '',
      'Index : 2',
      'Name : Windows Server 2025 Standard Evaluation (Desktop Experience)',
      'Version : 10.0.26100',
      'ServicePack Build : 32230',
      'Edition : ServerStandardEval',
      'Created : 1/14/2026 - 9:54:19 PM',
    ];
    writeFileSync(join(directory, 'wiminfo.txt'), text.join('\n'));
    const info = powershell(
      `$i = ConvertFrom-DismWimInfo -Text (Get-Content '${join(directory, 'wiminfo.txt')}'); ` +
        `[pscustomobject]@{ Name = $i.Name; Edition = $i.Edition; Build = $i.Build.ToString(); Created = $i.Created.ToString('yyyy-MM-dd HH:mm') }`,
    );
    expect(info).toEqual({
      Name: 'Windows Server 2025 Standard Evaluation (Desktop Experience)',
      Edition: 'ServerStandardEval',
      Build: '10.0.26100.32230',
      Created: '2026-01-14 21:54',
    });
    writeFileSync(join(directory, 'broken.txt'), 'Index : 2\nName : x\n');
    expect(() =>
      powershell(`ConvertFrom-DismWimInfo -Text (Get-Content '${join(directory, 'broken.txt')}')`),
    ).toThrow(/no 'Version' line/);
  });
});

describe('Windows template build script', () => {
  const build = read('Build-WindowsTemplate.ps1');

  it('stays within Windows PowerShell 5.1 and plain ASCII', () => {
    for (const name of [
      'Build-WindowsTemplate.ps1',
      'Find-WindowsVulnerabilities.ps1',
      'SsiWindowsTemplate.psm1',
    ]) {
      // Windows PowerShell 5.1 reads a BOM-less script as ANSI: any non-ASCII byte can turn
      // into a quote character and break the script.
      expect(
        [...read(name)].every(
          (char) => char === '\t' || char === '\n' || char === '\r' || (char >= ' ' && char <= '~'),
        ),
        name,
      ).toBe(true);
      expect(read(name), name).not.toMatch(/\?\?|\?\.|ForEach-Object -Parallel/);
    }
  });

  it('pins the source ISO, verifies updates and gates on the re-scan', () => {
    expect(build).toContain('is not the pinned');
    expect(build).toContain('Assert-MsuIntegrity');
    expect(build).toContain("Invoke-Scan $serviced $since 'scan-after'");
    expect(build).toMatch(/after\.Total -gt \$MaxOpenAfter/);
  });

  it('judges native tools by exit code, not by stderr (Windows PowerShell 5.1)', () => {
    // oscdimg writes progress to stderr; under ErrorActionPreference=Stop, 5.1 would abort it.
    const helper = build.slice(
      build.indexOf('function Invoke-Tool'),
      build.indexOf('function Get-WimImageInfo'),
    );
    expect(helper).toContain("$ErrorActionPreference = 'Continue'");
    expect(helper).toContain('finally { $ErrorActionPreference = $previous }');
    expect(helper).toContain('$Success -notcontains $code');
    const cleanup = build.slice(build.lastIndexOf('finally {'));
    expect(cleanup).toContain("$ErrorActionPreference = 'Continue'");
  });

  it('reads the serviced build from the image itself and never leaves it mounted', () => {
    expect(build).toContain('$currentVersion.UBR');
    expect(build).toContain('/Unmount-Image');
    expect(build).toContain('/Discard');
    expect(build).toContain('Dismount-DiskImage');
  });
});
