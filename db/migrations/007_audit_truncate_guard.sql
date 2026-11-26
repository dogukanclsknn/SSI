-- Close the last gap in the append-only audit trail.
--
-- 001 rejects UPDATE and DELETE on audit_events with a row-level trigger, but row
-- triggers do not fire for TRUNCATE, so the whole trail could still be wiped in one
-- statement. TRUNCATE only supports statement-level triggers; the same rejecting
-- function is reused.

DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
CREATE TRIGGER audit_events_no_truncate
BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_event_mutation();
