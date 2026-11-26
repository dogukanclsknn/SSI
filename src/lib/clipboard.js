// Copies text to the clipboard. SSI is served over plain HTTP on the intranet, where browsers
// do not offer navigator.clipboard (secure contexts only); the hidden-textarea fallback covers
// that case. Resolves when the text was copied, rejects otherwise.
// The legacy copy command; the textarea is removed whatever happens.
function execCopy(doc, area) {
  try {
    return doc.execCommand('copy');
  } catch {
    return false;
  } finally {
    doc.body.removeChild(area);
  }
}

export function copyText(value, { win = globalThis.window, doc = globalThis.document } = {}) {
  const text = String(value ?? '');
  const clipboard = win?.navigator?.clipboard;
  if (clipboard && win.isSecureContext) return clipboard.writeText(text);
  return new Promise((resolve, reject) => {
    if (!doc?.body) {
      reject(new Error('Copy is not available in this browser.'));
      return;
    }
    const area = doc.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    doc.body.appendChild(area);
    area.select();
    if (execCopy(doc, area)) resolve();
    else reject(new Error('Copy is not available in this browser.'));
  });
}
