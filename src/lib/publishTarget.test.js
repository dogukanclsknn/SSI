import { describe, expect, it } from 'vitest';
import { buildPublishPolicyConfig, evaluatePublishPolicy } from './publishPolicy.js';
import { suggestPublishTarget } from './publishTarget.js';

const NOW = Date.parse('2026-11-17T09:00:00Z');
const request = (repository, tag) => ({ target: { repository, tag } });

describe('suggestPublishTarget', () => {
  it('names the approved repository after the image and keeps its source tag', () => {
    expect(
      suggestPublishTarget({ image: 'ssi-images/onboarded/nginx:alpine', now: NOW }),
    ).toEqual({
      repository: 'approved/nginx',
      tag: 'verified-20261117-alpine-r1',
    });
    expect(
      suggestPublishTarget({
        image: `registry.example.com/ssi-images/onboarded/library/redis:7.2-alpine@sha256:${'a'.repeat(64)}`,
        now: NOW,
      }),
    ).toEqual({ repository: 'approved/redis', tag: 'verified-20261117-7.2-alpine-r1' });
  });

  it("uses the team's publish boundary when multi-tenancy is on", () => {
    expect(
      suggestPublishTarget({
        image: 'ssi-images/onboarded/payments/api:1.4',
        repositoryPrefix: 'approved/payments/',
        now: NOW,
      }),
    ).toEqual({ repository: 'approved/payments/api', tag: 'verified-20261117-1.4-r1' });
  });

  it('suggests the next free revision, so it never repeats an immutable tag', () => {
    const requests = [
      request('approved/nginx', 'verified-20261117-alpine-r1'),
      request('approved/nginx', 'verified-20261117-alpine-r3'),
      request('approved/nginx', 'verified-20261116-alpine-r7'), // another day
      request('approved/ssi-remediation-test', 'verified-20261117-alpine-r9'), // another repository
      request('approved/nginx', 'verified-20261117-alpine-r2-hotfix'), // not a revision
    ];
    expect(
      suggestPublishTarget({ image: 'ssi-images/onboarded/nginx:alpine', requests, now: NOW })
        .tag,
    ).toBe('verified-20261117-alpine-r4');
  });

  it('keeps the base tag when a catalog image is patched and published again', () => {
    expect(
      suggestPublishTarget({
        image: 'ssi-images/approved/nginx:verified-20261116-alpine-r1',
        now: NOW,
      }),
    ).toEqual({ repository: 'approved/nginx', tag: 'verified-20261117-alpine-r1' });
    expect(
      suggestPublishTarget({
        image: 'ssi-images/approved/nginx:verified-20261116-r2',
        now: NOW,
      }).tag,
    ).toBe('verified-20261117-r1');
  });

  it('leaves out a latest, missing or unusable source tag and stays within the tag limit', () => {
    expect(suggestPublishTarget({ image: 'onboarded/nginx:latest', now: NOW }).tag).toBe(
      'verified-20261117-r1',
    );
    expect(suggestPublishTarget({ image: 'onboarded/nginx', now: NOW }).tag).toBe(
      'verified-20261117-r1',
    );
    expect(suggestPublishTarget({ image: 'onboarded/nginx:1.27_RC+build', now: NOW }).tag).toBe(
      'verified-20261117-1.27_rc-build-r1',
    );
    const long = suggestPublishTarget({
      image: `onboarded/nginx:${'x'.repeat(200)}`,
      now: NOW,
    }).tag;
    expect(long.length).toBeLessThanOrEqual(128);
    expect(long).toMatch(/^[\w][\w.-]{0,127}$/);
  });

  it('suggests a target the publish policy accepts as written', () => {
    const DIGEST = `sha256:${'a'.repeat(64)}`;
    const config = buildPublishPolicyConfig({
      PUBLISH_TARGET_REGISTRY: 'registry.example.com',
      PUBLISH_TARGET_PROJECT: 'ssi-images',
      PUBLISH_TARGET_REPOSITORY_PREFIX: 'approved',
    });
    const job = {
      id: 'RM-EXEC-0005',
      mode: 'execution',
      status: 'Verified',
      patchedImageDigest: DIGEST,
      patchedImageTag: `registry.example.com/ssi-images/onboarded/nginx:copa`,
      supplyChain: {},
    };
    for (const image of [
      'ssi-images/onboarded/nginx:alpine',
      'onboarded/nginx:1.27_RC+build',
      `onboarded/nginx:${'x'.repeat(200)}`,
    ]) {
      const target = suggestPublishTarget({ image, now: NOW });
      // A malformed target is refused before any check runs; this one reaches the policy.
      expect(() =>
        evaluatePublishPolicy({
          job,
          target: {
            registry: 'registry.example.com',
            project: 'ssi-images',
            ...target,
          },
          config,
          actorId: 'operator',
          requestId: 'PUB-0042',
        }),
      ).not.toThrow();
    }
  });

  it('suggests nothing without a usable image name', () => {
    expect(suggestPublishTarget({ image: '' })).toBeNull();
    expect(suggestPublishTarget({})).toBeNull();
    expect(suggestPublishTarget({ image: 'onboarded/___:1' })).toBeNull();
  });
});
