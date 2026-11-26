-- Multi-tenancy, phase 1 (expand): teams ("tenants"), team memberships and a tenant on
-- every team-owned record. See src/lib/tenancy.js.
--
-- Everything that exists today belongs to the 'default' tenant, so behaviour does not change
-- while SSI_MULTI_TENANCY is off. The tenant_id columns keep DEFAULT 'default' during this
-- expand phase, so the previous release can still insert rows if it has to be rolled back;
-- the application always writes the tenant explicitly. A later contract migration drops
-- the defaults.
--
-- audit_events is append-only (001/007 reject UPDATE and TRUNCATE), so existing audit rows
-- are NOT backfilled: their tenant_id stays NULL and they read as platform-level history.

CREATE TABLE IF NOT EXISTS tenants (
  id text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$'),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
  status text NOT NULL CHECK (status IN ('active', 'disabled')),
  tenant_data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(tenant_data) = 'object'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0)
);

INSERT INTO tenants (id, display_name, status, tenant_data, created_at, updated_at)
VALUES ('default', 'Default', 'active', '{}'::jsonb, now(), now())
ON CONFLICT (id) DO NOTHING;

-- Team roles are the non-admin roles; platform administrators stay users.role = 'admin'.
CREATE TABLE IF NOT EXISTS tenant_memberships (
  tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  username text NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('viewer', 'operator', 'approver')),
  source text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'directory')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, username)
);

CREATE INDEX IF NOT EXISTS tenant_memberships_username_idx ON tenant_memberships (username);

-- Every existing non-admin user becomes a member of the default team with today's role.
INSERT INTO tenant_memberships (tenant_id, username, role, source, created_by, created_at, updated_at)
SELECT 'default', username, role, 'manual', 'migration-009', now(), now()
  FROM users
 WHERE role IN ('viewer', 'operator', 'approver')
ON CONFLICT (tenant_id, username) DO NOTHING;

-- Team-owned records.
ALTER TABLE remediation_jobs ADD COLUMN IF NOT EXISTS tenant_id text DEFAULT 'default';
UPDATE remediation_jobs SET tenant_id = 'default' WHERE tenant_id IS NULL;
ALTER TABLE remediation_jobs ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE publish_requests ADD COLUMN IF NOT EXISTS tenant_id text DEFAULT 'default';
UPDATE publish_requests SET tenant_id = 'default' WHERE tenant_id IS NULL;
ALTER TABLE publish_requests ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE onboarding_requests ADD COLUMN IF NOT EXISTS tenant_id text DEFAULT 'default';
UPDATE onboarding_requests SET tenant_id = 'default' WHERE tenant_id IS NULL;
ALTER TABLE onboarding_requests ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE policy_exceptions ADD COLUMN IF NOT EXISTS tenant_id text DEFAULT 'default';
UPDATE policy_exceptions SET tenant_id = 'default' WHERE tenant_id IS NULL;
ALTER TABLE policy_exceptions ALTER COLUMN tenant_id SET NOT NULL;

-- New audit rows carry the tenant of the record (NULL = platform event or legacy row).
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS tenant_id text;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'remediation_jobs_tenant_fk') THEN
    ALTER TABLE remediation_jobs ADD CONSTRAINT remediation_jobs_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'publish_requests_tenant_fk') THEN
    ALTER TABLE publish_requests ADD CONSTRAINT publish_requests_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'onboarding_requests_tenant_fk') THEN
    ALTER TABLE onboarding_requests ADD CONSTRAINT onboarding_requests_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'policy_exceptions_tenant_fk') THEN
    ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exceptions_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'audit_events_tenant_fk') THEN
    ALTER TABLE audit_events ADD CONSTRAINT audit_events_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS remediation_jobs_tenant_created_idx ON remediation_jobs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS publish_requests_tenant_created_idx ON publish_requests (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS onboarding_requests_tenant_created_idx ON onboarding_requests (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS policy_exceptions_tenant_idx ON policy_exceptions (tenant_id, status);
CREATE INDEX IF NOT EXISTS audit_events_tenant_occurred_idx ON audit_events (tenant_id, occurred_at DESC);
