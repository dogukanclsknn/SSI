import { describe, expect, it } from 'vitest';
import {
  assertRemediationInScope,
  createDryRunRemediationJob,
  isReportOnlyJob,
  RemediationScopeError,
  WINDOWS_NOT_SUPPORTED_MESSAGE,
} from './remediation.js';

const report = (os) => ({
  id: 'scan-1',
  image: 'harbor.local/app/svc:1.0',
  digest: `sha256:${'a'.repeat(64)}`,
  os,
  scanner: 'Trivy',
  findings: [
    { cve: 'CVE-2026-1', class: 'os-pkgs', package: 'openssl', installed: '1.1', fixed: '1.2', severity: 'High' },
  ],
});

describe('remediation scope — Windows is not supported yet', () => {
  it('plans Linux images as before', () => {
    const job = createDryRunRemediationJob({ id: 'RM-DRY-1', report: report('debian 12') });
    expect(job.status).toBe('Planned');
    expect(job.plannedFixes).toHaveLength(1);
  });

  it('keeps an unknown OS on the normal path', () => {
    expect(createDryRunRemediationJob({ id: 'RM-DRY-2', report: report('') }).status).toBe('Planned');
  });

  it('refuses a Windows image with a clear 422 error instead of creating a job', () => {
    expect(() => createDryRunRemediationJob({ id: 'RM-DRY-3', report: report('windows server core 2022') })).toThrow(
      RemediationScopeError,
    );
    try {
      assertRemediationInScope(report('Windows Server 2022'));
    } catch (error) {
      expect(error.statusCode).toBe(422);
      expect(error.message).toBe(WINDOWS_NOT_SUPPORTED_MESSAGE);
    }
    expect(() => assertRemediationInScope(report('alpine 3.20'))).not.toThrow();
  });

  it('recognizes report-only jobs stored by earlier versions', () => {
    expect(isReportOnlyJob({ remediation: 'report-only' })).toBe(true);
    expect(isReportOnlyJob({ status: 'ReportOnly' })).toBe(true);
    expect(isReportOnlyJob({ status: 'Planned' })).toBe(false);
  });
});
