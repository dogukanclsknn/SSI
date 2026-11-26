-- SSI kullanıcıları (rol yönetimi kalıcılığı).
--
-- LDAP yalnızca KİMLİK DOĞRULAR; kullanıcının ROLÜ ve DURUMU burada tutulur.
-- İlk LDAP girişinde satır varsayılan rolle (viewer) oluşur; lokal admin sonradan
-- rolü/durumu düzenler. Bu tablo, uygulama yeniden başlasa da rol atamalarının
-- kaybolmamasını sağlar (in-memory depo bunu yapamıyordu).
--
-- username daima normalize (küçük harf, trim) saklanır — CHECK bunu zorlar.

CREATE TABLE IF NOT EXISTS users (
  username text PRIMARY KEY CHECK (username = lower(username) AND length(username) > 0),
  display_name text NOT NULL,
  email text NOT NULL DEFAULT '',
  role text NOT NULL CHECK (role IN ('viewer', 'operator', 'approver', 'admin')),
  status text NOT NULL CHECK (status IN ('active', 'disabled')),
  login_type text NOT NULL CHECK (login_type IN ('ldap', 'local')),
  last_login_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS users_role_idx ON users (role);
CREATE INDEX IF NOT EXISTS users_status_idx ON users (status);
CREATE INDEX IF NOT EXISTS users_updated_at_idx ON users (updated_at DESC);
