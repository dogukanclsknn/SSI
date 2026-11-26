CREATE SEQUENCE IF NOT EXISTS publish_request_seq START WITH 1;

CREATE TABLE IF NOT EXISTS publish_requests (
  id text PRIMARY KEY CHECK (id ~ '^PUB-[0-9]{4,}$'),
  remediation_job_id text NOT NULL REFERENCES remediation_jobs(id),
  source_digest text NOT NULL CHECK (source_digest ~ '^sha256:[a-f0-9]{64}$'),
  target_reference text NOT NULL,
  status text NOT NULL CHECK (status IN ('Blocked', 'ApprovalRequired', 'Approved', 'Published')),
  policy_version text NOT NULL,
  request_data jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  row_version bigint NOT NULL DEFAULT 1,
  UNIQUE (remediation_job_id, target_reference)
);

CREATE INDEX IF NOT EXISTS publish_requests_status_created_idx
  ON publish_requests (status, created_at DESC);

CREATE INDEX IF NOT EXISTS publish_requests_source_digest_idx
  ON publish_requests (source_digest);
