// Short-lived, single-use download tickets. A multi-gigabyte file is saved by the browser from
// a plain link, which carries neither the dev-login headers nor the team header; the signed-in
// user therefore asks for a ticket first (a normal API call: RBAC, audit) and the link carries
// only the ticket. A ticket names one subject and one download, expires after five minutes and
// is accepted at most three times: a browser that holds a download back (Chrome blocks downloads
// over plain HTTP until the user chooses "Keep") asks for the same link again. Every use is
// audited by the caller. The key is random per process: a restart only invalidates open tickets.
//
//   issue({ subject, downloadId, actorId })     → { ticket, expiresAt }
//   redeem(ticket, { subject })                 → { downloadId, actorId, use } or DownloadTicketError
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

const DEFAULT_TTL_MS = 5 * 60 * 1000;
const DEFAULT_MAX_USES = 3;
const MAX_TICKET_LENGTH = 1024;

export class DownloadTicketError extends Error {
  constructor(message, statusCode = 403) {
    super(message);
    this.name = 'DownloadTicketError';
    this.statusCode = statusCode;
  }
}

const encode = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

export function createDownloadTickets({
  key = randomBytes(32),
  ttlMs = DEFAULT_TTL_MS,
  maxUses = DEFAULT_MAX_USES,
  now = () => Date.now(),
} = {}) {
  // Nonce → { uses, expiresAt } of every ticket used, kept until it would have expired anyway.
  const redeemed = new Map();
  const sign = (payload) => createHmac('sha256', key).update(payload).digest('base64url');
  const forget = () => {
    const at = now();
    for (const [nonce, entry] of redeemed) if (entry.expiresAt <= at) redeemed.delete(nonce);
  };

  return {
    issue({ subject, downloadId, actorId }) {
      for (const [name, value] of Object.entries({ subject, downloadId, actorId })) {
        if (typeof value !== 'string' || !value || value.length > 200) {
          throw new DownloadTicketError(`A download ticket needs a ${name}.`, 500);
        }
      }
      const expiresAt = now() + ttlMs;
      const payload = encode({
        s: subject,
        d: downloadId,
        a: actorId,
        e: expiresAt,
        n: randomUUID(),
      });
      return {
        ticket: `${payload}.${sign(payload)}`,
        expiresAt: new Date(expiresAt).toISOString(),
      };
    },

    redeem(ticket, { subject }) {
      const value = String(ticket || '');
      const [payload, signature, extra] = value.split('.');
      if (!payload || !signature || extra !== undefined || value.length > MAX_TICKET_LENGTH) {
        throw new DownloadTicketError('The download link is not valid.');
      }
      const expected = Buffer.from(sign(payload));
      const given = Buffer.from(signature);
      if (expected.length !== given.length || !timingSafeEqual(expected, given)) {
        throw new DownloadTicketError('The download link is not valid.');
      }
      let claims;
      try {
        claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      } catch {
        throw new DownloadTicketError('The download link is not valid.');
      }
      if (claims?.s !== subject) {
        throw new DownloadTicketError('The download link is for another template.');
      }
      forget();
      if (!Number.isFinite(claims.e) || claims.e <= now()) {
        throw new DownloadTicketError(
          'The download link has expired; start the download again.',
          410,
        );
      }
      const uses = (redeemed.get(claims.n)?.uses || 0) + 1;
      if (uses > maxUses) {
        throw new DownloadTicketError(
          'The download link was used too often; start the download again.',
          410,
        );
      }
      redeemed.set(claims.n, { uses, expiresAt: claims.e });
      return { downloadId: String(claims.d), actorId: String(claims.a), use: uses };
    },
  };
}
