-- Publish lifecycle after the policy decision (src/lib/publishLifecycle.js):
--   ApprovalRequired → Rejected   an approver closes a request that waits for approval
--   Published        → Withdrawn  an approver withdraws a published image
--
-- 002 created the status CHECK inline, so PostgreSQL named it; the existing status
-- constraint is looked up instead of assuming its name. Existing rows are not changed.

DO $$
DECLARE
  existing record;
BEGIN
  FOR existing IN
    SELECT conname
      FROM pg_constraint
     WHERE conrelid = 'publish_requests'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%status%'
  LOOP
    EXECUTE format('ALTER TABLE publish_requests DROP CONSTRAINT %I', existing.conname);
  END LOOP;
END $$;

ALTER TABLE publish_requests
  ADD CONSTRAINT publish_requests_status_check
  CHECK (status IN ('Blocked', 'ApprovalRequired', 'Approved', 'Published', 'Rejected', 'Withdrawn'));

-- A withdrawal reads the published requests of one digest; publish_requests_source_digest_idx
-- (002) already serves that lookup.
