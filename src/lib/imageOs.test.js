import { describe, expect, it } from 'vitest';
import { classifyImageOs, isRemediableOs, isWindowsImage, osFamilyOf, OS_KIND } from './imageOs.js';

// Only a definite Windows image is out of scope; an unknown or empty OS takes the normal path.

describe('osFamilyOf', () => {
  it('extracts the family from a combined OS string', () => {
    expect(osFamilyOf('debian 12')).toBe('debian');
    expect(osFamilyOf('Ubuntu 22.04')).toBe('ubuntu');
    expect(osFamilyOf('windows server core ltsc2022')).toBe('windows');
    expect(osFamilyOf('')).toBe('');
    expect(osFamilyOf(null)).toBe('');
  });
});

describe('classifyImageOs', () => {
  for (const os of ['debian 12', 'ubuntu 22.04', 'alpine 3.20', 'rhel 9', 'rocky 9', 'amazon 2023']) {
    it(`${os} → linux, remediable`, () => {
      expect(classifyImageOs(os)).toMatchObject({ kind: OS_KIND.LINUX, remediable: true });
    });
  }

  for (const os of ['windows', 'Windows Server 2022', 'windows/servercore:ltsc2022', 'mcr.microsoft.com/windows/nanoserver']) {
    it(`${os} → windows, out of scope`, () => {
      expect(classifyImageOs(os)).toMatchObject({ kind: OS_KIND.WINDOWS, remediable: false });
    });
  }

  it('unknown, empty and non-Copa families stay on the normal path', () => {
    for (const os of ['', 'plan9', 'wolfi', 'chainguard']) {
      expect(classifyImageOs(os)).toMatchObject({ kind: OS_KIND.UNKNOWN, remediable: true });
    }
  });

  it('shortcuts', () => {
    expect(isWindowsImage('Windows Server Core')).toBe(true);
    expect(isWindowsImage('debian 12')).toBe(false);
    expect(isRemediableOs('')).toBe(true);
    expect(isRemediableOs('windows server 2022')).toBe(false);
  });
});
