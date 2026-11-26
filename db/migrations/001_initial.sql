CREATE SEQUENCE IF NOT EXISTS remediation_dry_run_seq START WITH 1;
CREATE SEQUENCE IF NOT EXISTS remediation_execution_seq START WITH 1;

CREATE TABLE IF NOT EXISTS remediation_jobs (
  id text PRIMARY KEY CHECK (id ~ '^RM-(DRY|EXEC)-[0-9]{4,}$'),
  job_kind text NOT NULL CHECK (job_kind IN ('dry-run', 'execution')),
  parent_job_id text REFERENCES remediation_jobs(id) ON DELETE RESTRICT,
  source_digest text NOT NULL CHECK (source_digest ~ '^sha256:[a-f0-9]{64}$'),
  output_digest text CHECK (output_digest IS NULL OR output_digest ~ '^sha256:[a-f0-9]{64}$'),
  status text NOT NULL,
  lifecycle_state text NOT NULL,
  job_data jsonb NOT NULL CHECK (jsonb_typeof(job_data) = 'object'),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS remediation_jobs_output_digest_uq
  ON remediation_jobs (output_digest)
  WHERE output_digest IS NOT NULL;
CREATE INDEX IF NOT EXISTS remediation_jobs_created_at_idx ON remediation_jobs (created_at DESC);
CREATE INDEX IF NOT EXISTS remediation_jobs_source_digest_idx ON remediation_jobs (source_digest);
CREATE INDEX IF NOT EXISTS remediation_jobs_parent_idx ON remediation_jobs (parent_job_id);
CREATE INDEX IF NOT EXISTS remediation_jobs_data_gin_idx ON remediation_jobs USING gin (job_data);

CREATE TABLE IF NOT EXISTS remediation_evidence (
  evidence_digest text PRIMARY KEY CHECK (evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
  output_digest text NOT NULL UNIQUE CHECK (output_digest ~ '^sha256:[a-f0-9]{64}$'),
  dry_run_job_id text NOT NULL REFERENCES remediation_jobs(id) ON DELETE RESTRICT,
  execution_job_id text NOT NULL UNIQUE REFERENCES remediation_jobs(id) ON DELETE RESTRICT,
  contract_version text NOT NULL,
  evidence_data jsonb NOT NULL CHECK (jsonb_typeof(evidence_data) = 'object'),
  accepted_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS remediation_evidence_accepted_at_idx ON remediation_evidence (accepted_at DESC);
CREATE INDEX IF NOT EXISTS remediation_evidence_data_gin_idx ON remediation_evidence USING gin (evidence_data);

CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY,
  event_type text NOT NULL,
  action text NOT NULL,
  actor_id text NOT NULL,
  resource_type text NOT NULL,
  resource_id text,
  correlation_id uuid NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
  severity text NOT NULL CHECK (severity IN ('info', 'warning', 'error')),
  summary text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
  occurred_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_events_occurred_at_idx ON audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_resource_idx ON audit_events (resource_type, resource_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_correlation_idx ON audit_events (correlation_id);
CREATE INDEX IF NOT EXISTS audit_events_metadata_gin_idx ON audit_events USING gin (metadata);

CREATE OR REPLACE FUNCTION reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();

