import { validateHeaderName, validateHeaderValue } from 'node:http';
import { describe, expect, it } from 'vitest';
import {
  isValidHeaderName,
  MAX_HEADER_VALUE_LENGTH,
  sanitizeHeaderValue,
  sanitizeHeaders,
} from './httpHeaders.js';

// Node'un kabul ettiği başlık değeri kümesi: tek satır, ISO-8859-1 içi.
const nodeSafeHeaderValue = /^[\t\u0020-\u007E\u00A0-\u00FF]*$/;

describe('sanitizeHeaderValue', () => {
  it('returns an empty string for missing values', () => {
    expect(sanitizeHeaderValue(undefined)).toBe('');
    expect(sanitizeHeaderValue(null)).toBe('');
    expect(sanitizeHeaderValue('')).toBe('');
  });

  it('keeps already safe values untouched', () => {
    expect(sanitizeHeaderValue('remediation-worker-evidence-memory')).toBe(
      'remediation-worker-evidence-memory',
    );
  });

  it('collapses CR/LF and tabs into single spaces', () => {
    expect(sanitizeHeaderValue('harbor scan failed\r\n  at loadHarborScanReports\tline 12')).toBe(
      'harbor scan failed at loadHarborScanReports line 12',
    );
  });

  it('strips non-ASCII characters such as Turkish letters', () => {
    expect(sanitizeHeaderValue('Harbor taraması başarısız oldu')).toBe('Harbor taramas ba ar s z oldu');
  });

  it('truncates long values with an ASCII-only marker', () => {
    const sanitized = sanitizeHeaderValue('x'.repeat(500));
    expect(sanitized).toHaveLength(MAX_HEADER_VALUE_LENGTH);
    expect(sanitized.endsWith('...')).toBe(true);
    expect(nodeSafeHeaderValue.test(sanitized)).toBe(true);
  });

  it('honours a custom maximum length', () => {
    expect(sanitizeHeaderValue('abcdefghij', { maxLength: 6 })).toBe('abc...');
    expect(sanitizeHeaderValue('abcdefghij', { maxLength: 2 })).toBe('ab');
  });

  // Regresyon: X-SSI-Data-Error'a ham Harbor hatası yazıldığında Node ERR_INVALID_CHAR
  // fırlatıyor, kabul edilmiş remediation kanıtının cevabı yazılamıyordu.
  it('makes a raw multi-line scan error safe to write as a header', () => {
    const rawScanError = [
      'Harbor scan report fetch failed: self signed certificate in certificate chain',
      '    at TLSSocket.onConnectSecure (node:_tls_wrap:1679:34)',
      'çünkü sertifika zinciri doğrulanamadı',
    ].join('\n');

    // Ham hâli Node tarafından reddedilir, sanitize edilmiş hâli kabul edilir.
    expect(() => validateHeaderValue('X-SSI-Data-Error', rawScanError)).toThrow();

    const sanitized = sanitizeHeaderValue(rawScanError);

    expect(() => validateHeaderValue('X-SSI-Data-Error', sanitized)).not.toThrow();
    expect(nodeSafeHeaderValue.test(sanitized)).toBe(true);
    expect(sanitized).not.toContain('\n');
    expect(sanitized.startsWith('Harbor scan report fetch failed')).toBe(true);
  });
});

describe('isValidHeaderName', () => {
  it('accepts RFC 7230 tokens used by the API', () => {
    expect(isValidHeaderName('X-SSI-Data-Error')).toBe(true);
    expect(isValidHeaderName('Cache-Control')).toBe(true);
  });

  it('rejects names Node would refuse to write', () => {
    expect(isValidHeaderName('bad header')).toBe(false);
    expect(isValidHeaderName('bad\nheader')).toBe(false);
    expect(isValidHeaderName('X-SSI-Durum-Başlığı')).toBe(false);
    expect(isValidHeaderName('')).toBe(false);
    expect(isValidHeaderName(undefined)).toBe(false);
  });
});

describe('sanitizeHeaders', () => {
  it('sanitizes every value and preserves header names', () => {
    const sanitized = sanitizeHeaders({
      'X-SSI-Data-Source': 'remediation-worker-evidence-memory',
      'X-SSI-Data-Error': 'scan failed\nretry later',
      'X-SSI-Evidence-Replay': 'false',
    });

    expect(sanitized).toEqual({
      'X-SSI-Data-Source': 'remediation-worker-evidence-memory',
      'X-SSI-Data-Error': 'scan failed retry later',
      'X-SSI-Evidence-Replay': 'false',
    });
  });

  // Boş başlık yazmak yerine hiç yazmamak tercih edilir; istemci yokluğu boş kabul eder.
  it('omits headers whose value is missing or sanitizes to empty', () => {
    expect(
      sanitizeHeaders({
        'X-SSI-Data-Source': 'publish-policy-memory',
        'X-SSI-Data-Error': '',
        'X-SSI-Undefined': undefined,
        'X-SSI-Null': null,
        'X-SSI-Whitespace': '\r\n\t',
      }),
    ).toEqual({ 'X-SSI-Data-Source': 'publish-policy-memory' });
  });

  // Geçersiz bir başlık adı Node'da ERR_INVALID_HTTP_TOKEN fırlatır; bu da geçersiz
  // değer ile aynı mutate-then-fail sınıfına girer.
  it('drops header names Node would refuse, keeping the rest writable', () => {
    expect(
      sanitizeHeaders({
        'X-SSI-Data-Source': 'audit-memory',
        'X-SSI Boşluklu': 'ignored',
        'X-SSI-Satır\nSonu': 'ignored',
      }),
    ).toEqual({ 'X-SSI-Data-Source': 'audit-memory' });
  });

  it('returns an empty object when no headers are supplied', () => {
    expect(sanitizeHeaders()).toEqual({});
    expect(sanitizeHeaders(null)).toEqual({});
    expect(sanitizeHeaders('X-SSI-Data-Source: audit')).toEqual({});
  });

  it('produces names and values that Node accepts for every sanitized header', () => {
    const sanitized = sanitizeHeaders({
      'X-SSI-Data-Error': 'Harbor bağlantısı düştü\r\nsertifika zinciri doğrulanamadı',
      'X-SSI-Data-Source': 'harbor-scan-error',
      'X-SSI Geçersiz Ad': 'dropped',
    });

    for (const [name, value] of Object.entries(sanitized)) {
      expect(() => validateHeaderName(name)).not.toThrow();
      expect(() => validateHeaderValue(name, value)).not.toThrow();
    }
  });
});
