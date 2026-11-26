-- SSI risk acceptance (policy exceptions).
--
-- An approved, time-limited acceptance of one CVE in one repository (optionally narrowed to
-- a package or a digest). The publish gate deducts active exceptions from the Critical and
-- High thresholds. "Expired" is not stored: an Approved row whose expires_at has passed is
-- read as Expired. Same pattern as onboarding_requests: sequence, CHECK constraints, jsonb
-- body, optimistic locking and the audit event written in the same transaction.

CREATE SEQUENCE IF NOT EXISTS policy_exception_seq START WITH 1;

CREATE TABLE IF NOT EXISTS policy_exceptions (
  id text PRIMARY KEY CHECK (id ~ '^EXC-[0-9]{4,}$'),
  cve text NOT NULL CHECK (cve ~ '^(CVE-[0-9]{4}-[0-9]{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$'),
  repository text NOT NULL CHECK (repository ~ '^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)+$'),
  package text,
  digest text CHECK (digest IS NULL OR digest ~ '^sha256:[a-f0-9]{64}$'),
  reason_code text NOT NULL
    CHECK (reason_code IN ('not_affected', 'no_fix_available', 'compensating_control', 'accepted_risk')),
  justification text NOT NULL CHECK (char_length(justification) >= 20),
  status text NOT NULL CHECK (status IN ('Requested', 'Approved', 'Rejected', 'Revoked')),
  expires_at timestamptz NOT NULL,
  requested_by text NOT NULL,
  decided_by text,
  exception_data jsonb NOT NULL CHECK (jsonb_typeof(exception_data) = 'object'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  CHECK (decided_by IS NULL OR lower(decided_by) <> lower(requested_by))
);

CREATE INDEX IF NOT EXISTS policy_exceptions_status_expires_idx
  ON policy_exceptions (status, expires_at);
CREATE INDEX IF NOT EXISTS policy_exceptions_scope_idx
  ON policy_exceptions (cve, repository);
