-- Image inspections (ssi.image-inspection/v1, src/lib/imageInspection.js).
--
-- The "SSI - Image Inspection" worker reports the OS package inventory, layers, size and
-- runtime configuration (environment variable names only) of one scanned image. Scan Results
-- compares two inspected images on top of their vulnerability scans.
--
-- One row per image, keyed like a scan reference: <project>/<repository>@sha256:<digest>.
-- A newer inspection replaces the row; an older one is refused by the application.
-- No tenant column: an inspection describes image content, and it is only read for images
-- whose scan the caller can already see (GET /scans scope). Its audit events carry the team.

CREATE TABLE IF NOT EXISTS image_inspections (
  reference text PRIMARY KEY CHECK (reference ~ '^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$'),
  digest text NOT NULL CHECK (digest ~ '^sha256:[a-f0-9]{64}$'),
  generated_at timestamptz NOT NULL,
  evidence_digest text NOT NULL CHECK (evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
  inspection_data jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS image_inspections_digest_idx ON image_inspections (digest);
