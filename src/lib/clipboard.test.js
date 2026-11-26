import { describe, expect, it, vi } from 'vitest';
import { copyText } from './clipboard.js';

function fakeDocument({ copies = true } = {}) {
  const area = { value: '', style: {}, setAttribute: vi.fn(), select: vi.fn() };
  const body = { appendChild: vi.fn(), removeChild: vi.fn() };
  const doc = { body, createElement: vi.fn(() => area), execCommand: vi.fn(() => copies) };
  return { doc, area, body };
}

describe('copyText', () => {
  it('uses the Clipboard API in a secure context (HTTPS)', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    const { doc } = fakeDocument();
    await copyText('sha256:abc', {
      win: { isSecureContext: true, navigator: { clipboard: { writeText } } },
      doc,
    });
    expect(writeText).toHaveBeenCalledWith('sha256:abc');
    expect(doc.execCommand).not.toHaveBeenCalled();
  });

  it('falls back to a hidden textarea on plain HTTP, where the Clipboard API is missing', async () => {
    const { doc, area, body } = fakeDocument();
    await copyText('harbor/project/repo@sha256:abc', {
      win: { isSecureContext: false, navigator: {} },
      doc,
    });
    expect(area.value).toBe('harbor/project/repo@sha256:abc');
    expect(area.select).toHaveBeenCalled();
    expect(doc.execCommand).toHaveBeenCalledWith('copy');
    expect(body.removeChild).toHaveBeenCalledWith(area);
  });

  it('does not trust a Clipboard API outside a secure context', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    const { doc } = fakeDocument();
    await copyText('x', {
      win: { isSecureContext: false, navigator: { clipboard: { writeText } } },
      doc,
    });
    expect(writeText).not.toHaveBeenCalled();
    expect(doc.execCommand).toHaveBeenCalledWith('copy');
  });

  it('rejects when the browser refuses to copy, and still removes the textarea', async () => {
    const { doc, area, body } = fakeDocument({ copies: false });
    await expect(copyText('x', { win: { isSecureContext: false }, doc })).rejects.toThrow(
      /not available/,
    );
    expect(body.removeChild).toHaveBeenCalledWith(area);
  });
});
