-- Azure DevOps runs that SSI started for a record that is not a remediation job, onboarding
-- or publish request (those keep their runs in their own document, `pipelineRuns`).
--
-- Today: the image inspection of a scanned image (resource_type 'image', resource_id like a
-- scan reference: <project>/<repository>@sha256:<digest>). One row per Azure DevOps run.
-- No tenant column, like image_inspections: an image is only addressed after the caller's
-- team scope has shown its scan; the audit events carry the team.

CREATE TABLE IF NOT EXISTS pipeline_runs (
  resource_type text NOT NULL CHECK (resource_type IN ('image')),
  resource_id text NOT NULL CHECK (resource_id ~ '^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$'),
  run_id bigint NOT NULL CHECK (run_id > 0),
  run_data jsonb NOT NULL CHECK (jsonb_typeof(run_data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (resource_type, resource_id, run_id)
);

CREATE INDEX IF NOT EXISTS pipeline_runs_resource_idx ON pipeline_runs (resource_type, resource_id, created_at DESC);
