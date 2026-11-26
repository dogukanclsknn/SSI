import { Client, InvalidCredentialsError, escapeFilter } from 'ldapts';

// LDAP / Active Directory kimlik doğrulama (search-then-bind).
//
// Akış: (1) servis hesabıyla bağlan, (2) kullanıcıyı sAMAccountName ile bul,
// (3) kullanıcının DN'iyle yeniden bind ederek şifreyi doğrula, (4) memberOf
// gruplarını döndür. Şifreler yalnızca bind anında kullanılır; saklanmaz/loglanmaz.
//
// Config (server.js env'den okur):
//   { url, baseDN, bindDN, bindPassword, userFilter, tlsRejectUnauthorized, caCert,
//     timeout, connectTimeout }

export class LdapAuthError extends Error {
  constructor(message = 'Authentication failed.', { statusCode = 401 } = {}) {
    super(message);
    this.name = 'LdapAuthError';
    this.statusCode = statusCode;
  }
}

// Bir LDAP attribute'unu (memberOf / sAMAccountName) her zaman string dizisine çevir.
// ldapts değerleri string | string[] | Buffer | Buffer[] olabilir.
export function toStringArray(value) {
  if (value == null) return [];
  const list = Array.isArray(value) ? value : [value];
  return list.map((item) => (Buffer.isBuffer(item) ? item.toString('utf8') : String(item))).filter(Boolean);
}

// Kullanıcı arama filtresini, güvenilmeyen kullanıcı adını LDAP-escape ederek kur.
// userFilter bir şablondur: "(sAMAccountName={username})".
export function buildUserFilter(userFilter, username) {
  const safeUsername = escapeFilter`${username}`; // ( ) * \ NUL vb. kaçışlanır — LDAP injection'ı önler.
  return userFilter.replace('{username}', safeUsername);
}

export function isLdapConfigured(config) {
  return Boolean(config && config.url && config.baseDN && config.bindDN && config.userFilter);
}

// "CN=SSI-Approvers,OU=Groups,DC=corp,DC=..." -> "SSI-Approvers"
export function groupCommonName(dn) {
  const firstRdn = String(dn || '').split(',')[0] || '';
  const match = firstRdn.match(/^\s*CN=(.*)$/i);
  return (match ? match[1] : firstRdn).trim();
}

// memberOf DN listesinden grup→rol haritasıyla rolleri türetir. Harita anahtarı
// grubun CN'i (ör. "ssi-approvers") YA DA tam DN olabilir; karşılaştırma
// büyük/küçük harf duyarsızdır. Böylece Casey grup adı da tam DN de verebilir.
export function rolesForGroups(groups, groupRoleMap = {}) {
  const roles = new Set();
  for (const dn of groups) {
    const byFullDn = groupRoleMap[String(dn).toLowerCase()] || [];
    const byCommonName = groupRoleMap[groupCommonName(dn).toLowerCase()] || [];
    for (const role of byFullDn) roles.add(role);
    for (const role of byCommonName) roles.add(role);
  }
  return [...roles];
}

// Varsayılan client üretici — testlerde enjekte edilir (DI).
function defaultCreateClient(config) {
  const tlsOptions = { rejectUnauthorized: config.tlsRejectUnauthorized !== false };
  if (config.caCert) tlsOptions.ca = config.caCert;
  return new Client({
    url: config.url,
    timeout: config.timeout ?? 8000,
    connectTimeout: config.connectTimeout ?? 8000,
    tlsOptions,
  });
}

// Kullanıcıyı LDAP/AD'ye karşı doğrular. Başarılıysa { subject, dn, groups } döner;
// aksi halde LdapAuthError fırlatır. Hata mesajları jeneriktir (hangi adımın
// başarısız olduğunu sızdırmaz).
export async function authenticateUser(username, password, config, { createClient = defaultCreateClient } = {}) {
  const trimmedUsername = String(username || '').trim();

  // Boş kimlik bilgilerini baştan reddet. Geçerli bir DN + BOŞ şifre ile bind,
  // AD'de "unauthenticated bind" olarak başarılı sayılabilir — kritik bypass.
  if (!trimmedUsername || !password) {
    throw new LdapAuthError();
  }
  if (!isLdapConfigured(config)) {
    throw new LdapAuthError('LDAP is not configured.', { statusCode: 500 });
  }

  const client = createClient(config);
  try {
    // 1) Dizini aramak için servis hesabıyla bağlan.
    try {
      await client.bind(config.bindDN, config.bindPassword);
    } catch {
      throw new LdapAuthError('The directory server could not be reached.', { statusCode: 502 });
    }

    // 2) Kullanıcıyı bul (kullanıcı adı güvenle escape edilir).
    const filter = buildUserFilter(config.userFilter, trimmedUsername);
    const { searchEntries } = await client.search(config.baseDN, {
      scope: 'sub',
      filter,
      attributes: ['dn', 'sAMAccountName', 'memberOf', 'displayName', 'mail'],
      sizeLimit: 2,
    });
    // 0 = bulunamadı, >1 = belirsiz eşleşme. İkisi de jenerik başarısızlık.
    if (searchEntries.length !== 1) {
      throw new LdapAuthError();
    }
    const entry = searchEntries[0];

    // 3) Kullanıcının DN'iyle yeniden bind ederek şifreyi doğrula.
    try {
      await client.bind(entry.dn, password);
    } catch (error) {
      if (error instanceof InvalidCredentialsError) throw new LdapAuthError();
      throw new LdapAuthError();
    }

    const subject = toStringArray(entry.sAMAccountName)[0] || trimmedUsername;
    const groups = toStringArray(entry.memberOf);
    const displayName = toStringArray(entry.displayName)[0] || subject;
    const email = toStringArray(entry.mail)[0] || '';
    return { subject, displayName, email, dn: entry.dn, groups };
  } finally {
    // Bağlantıyı her durumda kapat; unbind hatalarını yoksay.
    try {
      await client.unbind();
    } catch {
      /* yoksay */
    }
  }
}
