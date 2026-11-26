-- Revoked SSI sessions (sign-out).
--
-- Session cookies are signed and stateless; signing out must still invalidate the
-- token server-side, otherwise a copied cookie stays valid until it expires. Each
-- token carries a random id (jti). Signing out records that id here until the token's
-- own expiry; rows past expires_at are useless and are pruned by the application.

CREATE TABLE IF NOT EXISTS session_revocations (
  jti text PRIMARY KEY CHECK (length(jti) BETWEEN 16 AND 128),
  subject text NOT NULL,
  revoked_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS session_revocations_expires_at_idx ON session_revocations (expires_at);
