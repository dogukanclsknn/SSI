// SSI kullanıcı deposu (rol yönetimi).
//
// LDAP yalnızca KİMLİK DOĞRULAR; kullanıcının ROLÜ burada tutulur. İlk LDAP
// girişinde kullanıcı varsayılan rolle (viewer) oluşturulur; lokal admin sonradan
// rolünü/durumunu düzenler.
//
// İki sürücü, TEK arayüz (Liskov): `memory` (PoC/demo, süreç ölünce kaybolur) ve
// `postgres` (kalıcı — yeniden başlatmada rol atamaları korunur). Postgres sürücüsü
// bir "write-through cache" kullanır: açılışta tüm kullanıcılar belleğe yüklenir
// (initialize) ve her YAZMADA hem veritabanı hem bellek aynası güncellenir. Böylece
// OKUMALAR (get/list) senkron kalır — kimlik çözümü (resolveIdentity) her istekte
// senkron çağırdığı için istek sıcak yolu async'e çevrilmeden kalıcılık kazanılır.
// SSI tek örnek (single-instance) çalıştığından bellek aynası her zaman tutarlıdır.

export const USER_ROLES = ['viewer', 'operator', 'approver', 'admin'];
export const DEFAULT_ROLE = 'viewer';
export const USER_STATUSES = ['active', 'disabled'];

export class UserStoreError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = 'UserStoreError';
    this.statusCode = statusCode;
  }
}

function normalizeUsername(username) {
  return String(username || '').trim().toLowerCase();
}

function assertRole(role) {
  if (!USER_ROLES.includes(role)) throw new UserStoreError(400, `Invalid role: ${role}`);
}

function assertStatus(status) {
  if (!USER_STATUSES.includes(status)) throw new UserStoreError(400, `Invalid status: ${status}`);
}

// --- Field validation -------------------------------------------------------------
// Admin-entered values are validated strictly. Values that arrive from the directory
// at sign-in (LDAP) are trusted for identity but still bounded and stripped of control
// characters before they are stored or rendered.
export const MAX_USERNAME_LENGTH = 128;
export const MAX_DISPLAY_NAME_LENGTH = 128;
export const MAX_EMAIL_LENGTH = 254;
const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._@-]*$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+$/;
const CONTROL_CHARACTER = /\p{Cc}/u;
const CONTROL_CHARACTERS = /\p{Cc}/gu;

function assertValidUsername(key) {
  if (!key) throw new UserStoreError(400, 'A username is required.');
  if (key.length > MAX_USERNAME_LENGTH || !USERNAME_PATTERN.test(key)) {
    throw new UserStoreError(
      400,
      `Usernames use letters, digits, ".", "_", "-" or "@" (up to ${MAX_USERNAME_LENGTH} characters).`,
    );
  }
}

function validDisplayName(value) {
  const text = String(value ?? '').trim();
  if (CONTROL_CHARACTER.test(text)) {
    throw new UserStoreError(400, 'The display name cannot contain control characters.');
  }
  if (text.length > MAX_DISPLAY_NAME_LENGTH) {
    throw new UserStoreError(400, `The display name can be up to ${MAX_DISPLAY_NAME_LENGTH} characters.`);
  }
  return text;
}

function validEmail(value) {
  const text = String(value ?? '').trim();
  if (text && (text.length > MAX_EMAIL_LENGTH || !EMAIL_PATTERN.test(text))) {
    throw new UserStoreError(400, 'Enter a valid email address.');
  }
  return text;
}

function directoryText(value, maxLength) {
  return String(value ?? '')
    .replace(CONTROL_CHARACTERS, '')
    .trim()
    .slice(0, maxLength);
}

function validateNewUser({ username, displayName, email, role }) {
  const key = normalizeUsername(username);
  assertValidUsername(key);
  assertRole(role);
  return { key, displayName: validDisplayName(displayName), email: validEmail(email), role };
}

function directoryLoginKey(username) {
  const key = directoryText(normalizeUsername(username), MAX_USERNAME_LENGTH);
  if (!key) throw new UserStoreError(400, 'A username is required.');
  return key;
}

// Kendini kilitleme koruması: bir yönetici bu ekrandan kendi hesabını silemez, pasife
// alamaz ve kendi rolünü değiştiremez (admin'den düşmek dahil). Böylece son aktif
// yöneticinin yanlışlıkla erişimini kaybetmesi engellenir. İhlalde 403 fırlatır.
export function assertNotSelfLockout({ actorId, targetUsername, method, changes = {} }) {
  const actor = normalizeUsername(actorId);
  if (!actor || actor !== normalizeUsername(targetUsername)) return;
  if (method === 'DELETE') {
    throw new UserStoreError(403, 'You cannot remove your own account.');
  }
  if (changes.status !== undefined && changes.status !== 'active') {
    throw new UserStoreError(403, 'You cannot disable your own account.');
  }
  if (changes.role !== undefined && changes.role !== 'admin') {
    throw new UserStoreError(403, 'You cannot change your own role.');
  }
}

// Dışa açılan kullanıcı görünümü (kopya — çağıran iç kaydı değiştiremez).
function view(record) {
  return { ...record };
}

// Veritabanı satırı (snake_case) → uygulama kaydı (camelCase).
function rowToRecord(row) {
  return {
    username: row.username,
    displayName: row.display_name,
    email: row.email,
    role: row.role,
    status: row.status,
    loginType: row.login_type,
    lastLoginAt: row.last_login_at ? new Date(row.last_login_at).toISOString() : null,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

// İlk LDAP girişinde oluşturulacak varsayılan kayıt.
function newLoginRecord({ key, displayName, email, loginType, timestamp }) {
  return {
    username: key,
    displayName: displayName || key,
    email: email || '',
    role: DEFAULT_ROLE,
    status: 'active',
    loginType,
    lastLoginAt: timestamp,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

// Admin'in önceden rol atadığı (şifresiz) kayıt.
function newCreatedRecord({ key, displayName, email, role, timestamp }) {
  return {
    username: key,
    displayName: displayName || key,
    email: email || '',
    role,
    status: 'active',
    loginType: 'ldap',
    lastLoginAt: null,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

// ---------------------------------------------------------------------------
// Bellek sürücüsü (PoC/demo). Yazmalar async imzalıdır ki iki sürücü aynı
// arayüzü paylaşsın; içeride senkron çalışır.
// ---------------------------------------------------------------------------
class MemoryUserStore {
  constructor({ now = () => new Date().toISOString() } = {}) {
    this.driver = 'memory';
    this.now = now;
    this.users = new Map(); // key: normalize(username)
  }

  async initialize() {}
  async close() {}

  list() {
    return [...this.users.values()].map(view).sort((a, b) => a.username.localeCompare(b.username));
  }

  get(username) {
    const record = this.users.get(normalizeUsername(username));
    return record ? view(record) : null;
  }

  async upsertOnLogin({ username, displayName: rawDisplayName = '', email: rawEmail = '', loginType = 'ldap' }) {
    const key = directoryLoginKey(username);
    const displayName = directoryText(rawDisplayName, MAX_DISPLAY_NAME_LENGTH);
    const email = directoryText(rawEmail, MAX_EMAIL_LENGTH);
    const timestamp = this.now();
    const existing = this.users.get(key);
    if (existing) {
      if (displayName) existing.displayName = displayName;
      if (email) existing.email = email;
      existing.lastLoginAt = timestamp;
      existing.updatedAt = timestamp;
      return view(existing);
    }
    const record = newLoginRecord({ key, displayName, email, loginType, timestamp });
    this.users.set(key, record);
    return view(record);
  }

  async create({ username, displayName = '', email = '', role = DEFAULT_ROLE }) {
    const input = validateNewUser({ username, displayName, email, role });
    const { key } = input;
    if (this.users.has(key)) throw new UserStoreError(409, 'This user already exists.');
    const record = newCreatedRecord({ ...input, timestamp: this.now() });
    this.users.set(key, record);
    return view(record);
  }

  async update(username, changes = {}) {
    const record = this.users.get(normalizeUsername(username));
    if (!record) throw new UserStoreError(404, 'User not found.');
    applyChanges(record, changes);
    record.updatedAt = this.now();
    return view(record);
  }

  async remove(username) {
    const key = normalizeUsername(username);
    if (!this.users.has(key)) throw new UserStoreError(404, 'User not found.');
    this.users.delete(key);
  }
}

// role/status/displayName/email değişikliklerini doğrulayıp uygular (ortak).
function applyChanges(record, changes) {
  if (changes.role !== undefined) {
    assertRole(changes.role);
    record.role = changes.role;
  }
  if (changes.status !== undefined) {
    assertStatus(changes.status);
    record.status = changes.status;
  }
  if (changes.displayName !== undefined) record.displayName = validDisplayName(changes.displayName) || record.username;
  if (changes.email !== undefined) record.email = validEmail(changes.email);
}

// ---------------------------------------------------------------------------
// Postgres sürücüsü (kalıcı). Write-through cache: okumalar bellek aynasından
// (senkron), yazmalar önce veritabanına sonra aynaya.
// ---------------------------------------------------------------------------
class PostgresUserStore {
  constructor(pool, { now = () => new Date().toISOString() } = {}) {
    this.driver = 'postgres';
    this.pool = pool;
    this.now = now;
    this.mirror = new Map(); // key: normalize(username) → record
  }

  // Açılışta tabloyu belleğe yükle. Tablo yoksa migrasyon uyarısı ver.
  async initialize() {
    let result;
    try {
      result = await this.pool.query(
        `SELECT username, display_name, email, role, status, login_type,
                last_login_at, created_at, updated_at
           FROM users`,
      );
    } catch (error) {
      throw new Error(`PostgreSQL persistence is not initialized. Run npm run db:migrate first. ${error.message}`, {
        cause: error,
      });
    }
    this.mirror.clear();
    for (const row of result.rows) {
      const record = rowToRecord(row);
      this.mirror.set(record.username, record);
    }
  }

  // Paylaşılan havuzu remediationStore.close() kapatır; burada kapatmayız.
  async close() {}

  list() {
    return [...this.mirror.values()].map(view).sort((a, b) => a.username.localeCompare(b.username));
  }

  get(username) {
    const record = this.mirror.get(normalizeUsername(username));
    return record ? view(record) : null;
  }

  async upsertOnLogin({ username, displayName: rawDisplayName = '', email: rawEmail = '', loginType = 'ldap' }) {
    const key = directoryLoginKey(username);
    const displayName = directoryText(rawDisplayName, MAX_DISPLAY_NAME_LENGTH);
    const email = directoryText(rawEmail, MAX_EMAIL_LENGTH);
    const timestamp = this.now();
    const existing = this.mirror.get(key);

    if (existing) {
      const record = {
        ...existing,
        displayName: displayName || existing.displayName,
        email: email || existing.email,
        lastLoginAt: timestamp,
        updatedAt: timestamp,
      };
      await this.pool.query(
        `UPDATE users
            SET display_name = $2, email = $3, last_login_at = $4::timestamptz, updated_at = $5::timestamptz
          WHERE username = $1`,
        [key, record.displayName, record.email, record.lastLoginAt, record.updatedAt],
      );
      this.mirror.set(key, record);
      return view(record);
    }

    const record = newLoginRecord({ key, displayName, email, loginType, timestamp });
    await this.pool.query(
      `INSERT INTO users
        (username, display_name, email, role, status, login_type, last_login_at, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz, $9::timestamptz)`,
      [
        record.username,
        record.displayName,
        record.email,
        record.role,
        record.status,
        record.loginType,
        record.lastLoginAt,
        record.createdAt,
        record.updatedAt,
      ],
    );
    this.mirror.set(key, record);
    return view(record);
  }

  async create({ username, displayName = '', email = '', role = DEFAULT_ROLE }) {
    const input = validateNewUser({ username, displayName, email, role });
    const { key } = input;
    if (this.mirror.has(key)) throw new UserStoreError(409, 'This user already exists.');
    const record = newCreatedRecord({ ...input, timestamp: this.now() });
    try {
      await this.pool.query(
        `INSERT INTO users
          (username, display_name, email, role, status, login_type, last_login_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, NULL, $7::timestamptz, $8::timestamptz)`,
        [
          record.username,
          record.displayName,
          record.email,
          record.role,
          record.status,
          record.loginType,
          record.createdAt,
          record.updatedAt,
        ],
      );
    } catch (error) {
      if (error.code === '23505') throw new UserStoreError(409, 'This user already exists.');
      throw error;
    }
    this.mirror.set(key, record);
    return view(record);
  }

  async update(username, changes = {}) {
    const key = normalizeUsername(username);
    const existing = this.mirror.get(key);
    if (!existing) throw new UserStoreError(404, 'User not found.');
    const record = { ...existing };
    applyChanges(record, changes);
    record.updatedAt = this.now();
    const result = await this.pool.query(
      `UPDATE users
          SET display_name = $2, email = $3, role = $4, status = $5, updated_at = $6::timestamptz
        WHERE username = $1`,
      [key, record.displayName, record.email, record.role, record.status, record.updatedAt],
    );
    if (result.rowCount === 0) {
      // Ayna ile veritabanı çeliştiyse (dış müdahale) aynayı düşür.
      this.mirror.delete(key);
      throw new UserStoreError(404, 'User not found.');
    }
    this.mirror.set(key, record);
    return view(record);
  }

  async remove(username) {
    const key = normalizeUsername(username);
    if (!this.mirror.has(key)) throw new UserStoreError(404, 'User not found.');
    const result = await this.pool.query('DELETE FROM users WHERE username = $1', [key]);
    this.mirror.delete(key);
    if (result.rowCount === 0) throw new UserStoreError(404, 'User not found.');
  }
}

// Fabrika. Postgres sürücüsü paylaşılan bir havuz (pool) bekler; havuzu server.js
// oluşturur ve remediationStore ile paylaşır (tek havuz).
export function createUserStore({ driver = process.env.PERSISTENCE_DRIVER, pool = null, now } = {}) {
  const selected = String(driver || 'memory').trim().toLowerCase();
  if (selected === 'memory') return new MemoryUserStore({ now });
  if (selected !== 'postgres') {
    throw new Error('PERSISTENCE_DRIVER must be memory or postgres');
  }
  if (!pool) throw new Error('createUserStore requires a pool when PERSISTENCE_DRIVER=postgres');
  return new PostgresUserStore(pool, { now });
}

export { MemoryUserStore, PostgresUserStore };
