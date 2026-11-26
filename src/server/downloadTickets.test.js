import { describe, expect, it } from 'vitest';
import { createDownloadTickets } from './downloadTickets.js';

describe('download tickets', () => {
  const clock = () => {
    let at = Date.parse('2026-11-25T10:00:00Z');
    return { now: () => at, advance: (ms) => (at += ms) };
  };

  it('stand for the user who asked, for one download of one template, a few times', () => {
    const tickets = createDownloadTickets();
    const { ticket } = tickets.issue({
      subject: 'OST-0002',
      downloadId: 'ova',
      actorId: 'alex',
    });
    expect(tickets.redeem(ticket, { subject: 'OST-0002' })).toEqual({
      downloadId: 'ova',
      actorId: 'alex',
      use: 1,
    });
    // Chrome asks again when the user keeps a download it held back.
    expect(tickets.redeem(ticket, { subject: 'OST-0002' }).use).toBe(2);
    expect(tickets.redeem(ticket, { subject: 'OST-0002' }).use).toBe(3);
    expect(() => tickets.redeem(ticket, { subject: 'OST-0002' })).toThrow(/used too often/);
  });

  it('expire after five minutes', () => {
    const time = clock();
    const tickets = createDownloadTickets({ now: time.now });
    const { ticket, expiresAt } = tickets.issue({
      subject: 'OST-0002',
      downloadId: 'ova',
      actorId: 'a',
    });
    expect(expiresAt).toBe('2026-11-25T10:05:00.000Z');
    time.advance(5 * 60 * 1000);
    expect(() => tickets.redeem(ticket, { subject: 'OST-0002' })).toThrow(/expired/);
  });

  it('are refused for another template, when changed, or from another process', () => {
    const tickets = createDownloadTickets();
    const { ticket } = tickets.issue({ subject: 'OST-0002', downloadId: 'ova', actorId: 'a' });
    expect(() => tickets.redeem(ticket, { subject: 'OST-0003' })).toThrow(/another template/);
    const [payload, signature] = ticket.split('.');
    const forged = Buffer.from(
      JSON.stringify({ ...JSON.parse(Buffer.from(payload, 'base64url').toString()), d: 'vhdx' }),
    ).toString('base64url');
    expect(() => tickets.redeem(`${forged}.${signature}`, { subject: 'OST-0002' })).toThrow(
      /not valid/,
    );
    expect(() => createDownloadTickets().redeem(ticket, { subject: 'OST-0002' })).toThrow(
      /not valid/,
    );
    for (const bad of ['', 'x', 'a.b.c', `${'a'.repeat(2000)}.b`]) {
      expect(() => tickets.redeem(bad, { subject: 'OST-0002' })).toThrow(/not valid/);
    }
  });
});
