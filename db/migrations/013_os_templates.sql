-- OS template build requests (src/lib/osTemplate.js, docs/os-template-poc.md "Windows").
--
-- One row per request (OST-…): the source ISO and edition an operator asked for, the runs of
-- the "SSI - OS Template (Windows)" worker, its HMAC-signed result (the template manifest) and
-- the approver's decision, all in build_data. A status change and its audit event are written
-- in one transaction under the row lock (updateOsTemplateBuildWith).
-- No tenant column: an OS template is a platform-wide asset, not a team's record. Reads need
-- os-template:read (every role); the audit events carry no team (platform events).

CREATE SEQUENCE IF NOT EXISTS os_template_build_seq START WITH 1;

CREATE TABLE IF NOT EXISTS os_template_builds (
  id text PRIMARY KEY CHECK (id ~ '^OST-[0-9]{4,}$'),
  template_name text NOT NULL CHECK (template_name ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
  status text NOT NULL CHECK (status IN ('Requested', 'Built', 'Approved', 'Rejected')),
  build_data jsonb NOT NULL CHECK (jsonb_typeof(build_data) = 'object'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0)
);

CREATE INDEX IF NOT EXISTS os_template_builds_created_idx ON os_template_builds (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS os_template_builds_status_idx ON os_template_builds (status, created_at DESC);
