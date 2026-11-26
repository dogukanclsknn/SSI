-- SSI onboarding (karantina import) istekleri — kalıcılık.
--
-- Dış imajları yönetimli akışa alan onboarding istekleri artık kalıcı: SSI yeniden
-- başlasa/yeniden dağıtılsa da istek geçmişi ve durumları korunur (önceden memory'deydi).
-- publish_requests ile aynı desen: durum makinesi + jsonb gövde + append-only audit
-- aynı transaction'da yazılır.

CREATE SEQUENCE IF NOT EXISTS onboarding_request_seq START WITH 1;

CREATE TABLE IF NOT EXISTS onboarding_requests (
  id text PRIMARY KEY CHECK (id ~ '^ONB-[0-9]{4,}$'),
  source_reference text NOT NULL,
  target_reference text NOT NULL,
  status text NOT NULL CHECK (status IN ('Requested', 'Importing', 'Imported', 'Failed')),
  request_data jsonb NOT NULL CHECK (jsonb_typeof(request_data) = 'object'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0)
);

CREATE INDEX IF NOT EXISTS onboarding_requests_status_created_idx
  ON onboarding_requests (status, created_at DESC);
CREATE INDEX IF NOT EXISTS onboarding_requests_data_gin_idx
  ON onboarding_requests USING gin (request_data);
