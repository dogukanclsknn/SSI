// SSI — The target a new publish request suggests (Publish screen, "New publish request").
//
// One approved repository per image, named like its quarantine repository, so the approved
// catalog says what it holds: onboarded/nginx → approved/nginx, and a team's
// onboarded/payments/api → approved/payments/api (the team's boundary prefix). The tag follows
// the catalog convention verified-<YYYYMMDD>-<source tag>-r<N>, with N one past the highest
// revision already requested for that repository and day, so the suggestion never repeats a tag
// (tags in the approved catalog are immutable). The person can still edit both fields; the
// publish policy decides what is allowed. Pure: no I/O.

// A repository path component as the publish policy accepts it (src/lib/publishPolicy.js):
// lower-case alphanumerics with single '.', '_' or '-' between them.
const COMPONENT = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const TAG_MAX_LENGTH = 128;
// "verified-20261116-alpine-r1" → "alpine": re-publishing a catalog image keeps its base tag.
const CATALOG_TAG = /^verified-\d{8}(?:-(.+))?-r\d+$/;

const text = (value) => (value == null ? '' : String(value).trim());

// Lower-cases and replaces what a registry would refuse; '' when nothing usable is left.
function slug(value, pattern = /[^a-z0-9._-]+/g) {
  return text(value)
    .toLowerCase()
    .replace(pattern, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^[._-]+|[._-]+$/g, '');
}

// The image name (last path segment) and tag of a reference such as
// "harbor.example/ssi-images/onboarded/nginx:alpine@sha256:…".
function imageNameAndTag(image) {
  const withoutDigest = text(image).split('@')[0];
  const lastSlash = withoutDigest.lastIndexOf('/');
  const lastColon = withoutDigest.lastIndexOf(':');
  const path = lastColon > lastSlash ? withoutDigest.slice(0, lastColon) : withoutDigest;
  const tag = lastColon > lastSlash ? withoutDigest.slice(lastColon + 1) : '';
  return { name: path.split('/').filter(Boolean).pop() || '', tag };
}

// The part of the source tag worth keeping in the catalog tag ('' for latest or none).
function sourceTagPart(tag) {
  const catalog = text(tag).match(CATALOG_TAG);
  const base = slug(catalog ? catalog[1] || '' : tag);
  return base === 'latest' ? '' : base;
}

function dayStamp(now) {
  const date = new Date(now);
  return (Number.isNaN(date.getTime()) ? new Date() : date)
    .toISOString()
    .slice(0, 10)
    .replaceAll('-', '');
}

// { repository, tag } for a verified job's image, or null when the image has no usable name.
// `repositoryPrefix` is the publish boundary (approved, or a team's approved/<team>);
// `requests` are the publish requests already known (any status).
export function suggestPublishTarget({
  image,
  repositoryPrefix = 'approved',
  requests = [],
  now = Date.now(),
} = {}) {
  const { name: rawName, tag: sourceTag } = imageNameAndTag(image);
  const name = slug(rawName);
  if (!name || !COMPONENT.test(name)) return null;

  const prefix = text(repositoryPrefix).replace(/^\/+|\/+$/g, '') || 'approved';
  const repository = `${prefix}/${name}`;

  const day = dayStamp(now);
  const revisionRoom = '-r999'.length;
  const head = `verified-${day}`;
  const tagPart = sourceTagPart(sourceTag).slice(
    0,
    TAG_MAX_LENGTH - head.length - 1 - revisionRoom,
  );
  const base = slug(tagPart ? `${head}-${tagPart}` : head);

  const revisionOf = new RegExp(`^${base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}-r(\\d+)$`);
  const highest = (Array.isArray(requests) ? requests : [])
    .filter((request) => text(request?.target?.repository) === repository)
    .map((request) => Number(text(request?.target?.tag).match(revisionOf)?.[1] || 0))
    .reduce((max, revision) => Math.max(max, revision), 0);

  return { repository, tag: `${base}-r${highest + 1}` };
}
