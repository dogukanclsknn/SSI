// HTTP response başlıklarının tek noktadan sanitizasyonu.
//
// Node'un http modülü, bir başlık değerinde CR/LF veya ISO-8859-1 dışı bayt görürse
// response yazılırken ERR_INVALID_CHAR, geçersiz bir başlık adı görürse
// ERR_INVALID_HTTP_TOKEN fırlatır. Her iki durumda sunucu state'i başarıyla
// değiştirmiş, ancak cevabı yazamamış olur (mutate-then-fail): çağıran taraf bunu
// geçici bir transport hatası sanıp retry eder ve aynı mutasyon tekrar denenir.
//
// Bu yüzden dinamik başlıklar (X-SSI-Data-Error gibi ham hata metinleri) asla
// doğrudan yazılmaz; önce tek satırlık, printable-ASCII ve sınırlı uzunlukta hale
// getirilir. Tam hata metni audit ve log kayıtlarında korunur.
//
// Kapsam: yalnızca response başlıkları. Harbor'a giden istek başlıkları kod içinde
// sabit tanımlıdır; onları bu modülden geçirmek yön hatasıdır ve istek başlıklarının
// sessizce düşmesine yol açar.

export const MAX_HEADER_VALUE_LENGTH = 200;

const TRUNCATION_MARKER = '...';

// RFC 7230 token kümesi: Node'un writeHead'de kabul ettiği başlık adları.
const VALID_HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;

// DİKKAT: Bu ifade bilinçli olarak "izin verilenler" (printable ASCII) biçiminde
// yazılmıştır. Aynı sonuç [\x00-\x1F] gibi bir kontrol karakteri kara listesiyle de
// alınabilir, ancak o biçim ESLint'in no-control-regex kuralını ihlal eder ve lint
// adımını kırar. Kara listeye çevirmeyin.
const NON_PRINTABLE_ASCII = /[^ -~]+/g;

// Tek bir başlık değerini RFC 7230 uyumlu, güvenle yazılabilir bir stringe indirger.
export function sanitizeHeaderValue(value, { maxLength = MAX_HEADER_VALUE_LENGTH } = {}) {
  if (value === undefined || value === null) {
    return '';
  }

  const safe = String(value).replace(NON_PRINTABLE_ASCII, ' ').replace(/ {2,}/g, ' ').trim();

  if (safe.length <= maxLength) {
    return safe;
  }

  return maxLength > TRUNCATION_MARKER.length
    ? `${safe.slice(0, maxLength - TRUNCATION_MARKER.length)}${TRUNCATION_MARKER}`
    : safe.slice(0, maxLength);
}

// Başlık adının Node tarafından yazılabilir bir token olup olmadığını bildirir.
export function isValidHeaderName(name) {
  return typeof name === 'string' && VALID_HEADER_NAME.test(name);
}

// Bir başlık sözlüğünü writeHead'e verilebilir hâle getirir: geçersiz adlar ve
// sanitizasyondan sonra boş kalan değerler yazılmaz. Boş bir başlık göndermek yerine
// hiç göndermemek tercih edilir; istemci tarafı yokluğu zaten boş kabul eder
// (`src/lib/api.js`: `headers.get('x-ssi-data-error') || ''`).
export function sanitizeHeaders(headers = {}, options = {}) {
  if (headers === null || typeof headers !== 'object') {
    return {};
  }

  const sanitized = {};

  for (const [name, value] of Object.entries(headers)) {
    if (!isValidHeaderName(name)) {
      continue;
    }

    const safe = sanitizeHeaderValue(value, options);

    if (safe) {
      sanitized[name] = safe;
    }
  }

  return sanitized;
}
