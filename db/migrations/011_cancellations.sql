-- Cancelled: a request that can no longer happen is closed instead of staying open forever.
--
--   publish_requests     Blocked / ApprovalRequired / Approved → Cancelled, in the same
--                        transaction that withdraws its image (src/lib/publishLifecycle.js).
--                        A worker receipt that arrives later for a request that was already
--                        Approved is still recorded (Withdrawn, published after withdrawal).
--   onboarding_requests  Requested / Importing → Cancelled by a person, with a reason
--                        (src/lib/onboarding.js). A late import receipt is kept on record.
--
-- Existing rows are not changed. 004 created the onboarding status CHECK inline, so its
-- name is looked up instead of assumed; 008 named the publish one.

ALTER TABLE publish_requests DROP CONSTRAINT IF EXISTS publish_requests_status_check;
ALTER TABLE publish_requests
  ADD CONSTRAINT publish_requests_status_check
  CHECK (status IN ('Blocked', 'ApprovalRequired', 'Approved', 'Published', 'Rejected', 'Withdrawn', 'Cancelled'));

DO $$
DECLARE
  existing record;
BEGIN
  FOR existing IN
    SELECT conname
      FROM pg_constraint
     WHERE conrelid = 'onboarding_requests'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%status%'
  LOOP
    EXECUTE format('ALTER TABLE onboarding_requests DROP CONSTRAINT %I', existing.conname);
  END LOOP;
END $$;

ALTER TABLE onboarding_requests
  ADD CONSTRAINT onboarding_requests_status_check
  CHECK (status IN ('Requested', 'Importing', 'Imported', 'Failed', 'Cancelled'));

-- Open requests per quarantine target: the duplicate check on create reads this.
CREATE INDEX IF NOT EXISTS onboarding_requests_open_target_idx
  ON onboarding_requests (tenant_id, target_reference)
  WHERE status IN ('Requested', 'Importing');
