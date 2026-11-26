# SSI — API Sözleşmesi (Faz 4 Uygulanan PoC Sözleşmesi)

> Backend yaklaşımı: **REST API + JSON**. Teknoloji esnek; FastAPI güçlü adaylardan
> biri olsa da zorunlu değil. Bu doküman, mevcut React arayüzünün tükettiği
> verilerin gerçek API'den nasıl geleceğini tanımlar.
> Makine-okur tam spec: [`openapi.yaml`](openapi.yaml) (Swagger UI ile açılabilir,
> backend/istemci kodu üretiminde referans alınabilir).

## Tasarım kararları
- **Base URL:** `/api/v1`
- **Repo yaklaşımı:** Backend aynı repo içinde ilerleyebilir. Önerilen yerleşim:
  `backend/` (API + worker/adapter), mevcut `src/` frontend olarak kalır.
- **İlk entegrasyon hedefi:** Inventory. Önce `GET /images`,
  `GET /images/{id}` ve `GET /images/{id}/sbom` gerçek API'ye bağlanır; daha sonra
  Scan → Remediation → Publish akışına geçilir.
- **Async job modeli:** Uzun süren işlemler (ingest, scan, remediation, rebuild, publish)
  hemen sonuç döndürmez. `POST` bir **Job** başlatır → `202 Accepted` + `jobId`.
  Client `GET /jobs/{jobId}` ile durumu sorar (`queued → running → succeeded/failed`).
  İş bitince `resultUrl` ilgili sonuç kaynağını gösterir.
- **Auth:** Şimdilik `Authorization: Bearer <token>` **placeholder**. Gerçek
  LDAP/AD + RBAC **Faz 5**'te. (Tüm endpoint'ler `401` döndürebilir.)
- **Veri modeli:** `src/data/platformData.js`'teki simüle şemayla **birebir** — yani
  mock ekranlar sözleşmenin canlı referansı. Gerçek entegrasyonda sadece bu veri
  kaynağı gerçek backend'e bağlanır; ekranlar değişmez.
- **Scanner kararı:** İlk aşamada **Trivy JSON** baz alınır. Harbor integration
  aktifken backend, artifact'in resmi vulnerability addition endpointinden aldığı
  scanner reportunu normalize ederek `Finding` şemasına çevirir. Harbor'da
  artifact/scan yoksa veri kaynağı durumu açıkça belirtilir; gerçek bağlantı
  varken fixture veri gerçekmiş gibi gösterilmez.
- **Remediation kapsamı:** İlk fazda **OS package remediation** (apt/apk/yum/dnf
  seviyesi). Application dependency remediation (npm, pip, Maven, Go vb.) sonraki
  fazlarda ayrı capability olarak ele alınır.
- **Remediation engine:** **Copacetic (copa)** ana aday. Alternatifler ayrıca
  değerlendirilecek. Beklenen output: patched image tag/digest, fixed CVE listesi,
  remaining CVE listesi, before/after severity özeti, status ve log/error bilgisi.
- **Dry Run güvenlik sınırı (uygulandı):** `POST /images/{scanReportId}/remediation`
  yalnızca `dryRun: true` kabul eder. Bu çağrı image pull, Copa patch, registry push
  veya re-scan yapmaz; sadece uygun bulgulardan denetlenebilir bir remediation planı
  üretir. Uygunluk için `class=os-pkgs`, paket adı ve fixed version şarttır.
  Harbor reportunda package class belirsizse bulgu otomatik patch'e alınmaz.
- **Gerçek motor sınırı:** Copa, web uygulaması container'ında çalıştırılmayacak;
  firewall ve registry doğrulaması tamamlandıktan sonra ayrı worker/agent içinde
  çalışacak. Bu sayede web/API katmanına Docker socket veya registry yazma yetkisi
  verilmez.
- **Lifecycle ve worker handoff (uygulandı):** Dry Run planı `planned` durumunda
  kalır. Hedef execution lifecycle'i `queued → running → patched → rescanning →
  verified` (ve terminal `failed` / `blocked`) şeklinde açık geçiş kurallarıyla
  tanımlanmıştır. `GET /remediation/{id}/execution-readiness` salt-okunur olarak
  worker önkoşullarını döner. Canonical report ile planı doğrulanmış bir Dry Run için
  `GET /remediation/{id}/worker-handoff` salt-okunur, digest-pinned ve credential-free
  bir manifest üretir. Bu endpoint dispatch endpointi değildir; gerçek execution bu
  aşamada bilinçli olarak yoktur.
- **Canonical worker input:** Harbor'ın normalize vulnerability response'u UI için
  kullanılabilir; fakat Copa worker'ı kendi ortamında immutable image digest üzerinden
  OS-only ham Trivy JSON üretir. Bu, package class belirsizliğini azaltır ve worker
  input'unu denetlenebilir hale getirir. Ayrıntı:
  [`remediation-worker-contract.md`](remediation-worker-contract.md).
- **Canonical report intake (uygulandı):** `POST /remediation/{id}/canonical-report`,
  ayrı worker'ın ürettiği ham Trivy JSON'u en fazla 2 MiB boyutta kabul eder. Raporun
  `SchemaVersion: 2`, `ArtifactType: container_image`, sadece `os-pkgs` sonucu ve Dry
  Run job'ının immutable source digest'i ile birebir eşleşmesi zorunludur. Başarılı
  intake, Dry Run planını yeniden hesaplar; image pull, Copa patch, registry push veya
  re-scan başlatmaz. `contentDigest`, pipeline artifact'inin UTF-8 ham dosya içeriğinden
  hesaplanır; JSON parse/stringify dönüşümü yapılmadan evidence ile aynı byte kimliği
  korunur. Raw report kalıcı olarak web uygulamasında tutulmaz. Job ve receipt metadata'sı
  seçili store sürücüsünde (`memory` veya `postgres`) saklanır.
- **Verification evidence intake (uygulandı):** Açık onaylı Copa worker'ın ürettiği
  `remediation-result.json`, ilgili canonical Dry Run job'ına bağlanır. Normal operasyonel
  yol `POST /remediation/{id}/worker-evidence`; worker ham JSON body'yi job kimliği,
  UTC epoch timestamp, worker kimliği ve SHA-256 content digest ile birlikte HMAC-SHA256
  imzalar. API imzayı sabit zamanlı karşılaştırma ile doğrular, varsayılan beş dakikalık
  replay penceresini uygular ve kısa/eksik server secret'ında fail-closed `503` döner.
  `POST /remediation/{id}/verification-evidence` ise PoC/debug için manuel geri dönüş
  yolu olarak korunur. Her iki yol da contract sürümü, immutable source digest, canonical
  report content digest, output tag/digest, Copacetic sürümü, Trivy re-scan sonucu ve
  fixed/remaining muhasebesini aynı doğrulayıcıyla kontrol eder. Aynı output digest için
  aynı evidence idempotent olarak mevcut kaydı döndürür; farklı içerik `409` ile reddedilir.
  Başarılı intake ayrı bir `RM-EXEC-*` kaydı üretir; Dry Run geçmişi değiştirilmez.
- **Scope-aware doğrulama (uygulandı):** Canonical OS package sonucu ile Harbor full-image
  sonucu birbirine karıştırılmaz. Mevcut PoC için canonical sonuç `64 → 0 (Verified)`,
  full-image sonuç `77 → 13`; kalan 13 application dependency bulgusu ilk faz kapsamı
  dışındadır. Verification başarılı olsa bile merkezi publish otomatik açılmaz;
  `publishGate` kalan Critical/High bulgular nedeniyle `Blocked` kalır.
- **Persistence ve transaction sınırı (uygulandı, aktivasyon opsiyonel):** Remediation
  job, verification evidence ve audit olayları ortak bir store sözleşmesi kullanır.
  Varsayılan `memory` PoC sürücüsüne ek olarak migration kontrollü PostgreSQL sürücüsü
  vardır. Evidence kabulü; execution job, evidence ve audit kaydını tek transaction'da
  yazar. Output digest üzerinde idempotency/çakışma kontrolü uygulanır. PostgreSQL
  seçildiğinde migration eksikse API fail-fast başlatılmaz.
- **Yapılandırılmış audit (uygulandı):** Mutasyonlar actor, correlation ID, action,
  resource, outcome, severity ve redacted metadata ile kaydedilir. PostgreSQL'deki audit
  tablosu append-only trigger'larla UPDATE/DELETE (satır) ve TRUNCATE (ifade, migration 007) işlemlerini reddeder. Caller actor header'ı
  yalnızca güvenilir proxy/RBAC katmanı açıkça etkinleştirirse kabul edilir.
- **Error responses & HTTP hardening (implemented):** Every response carries
  `X-Correlation-ID`. Domain and validation errors keep their caller-facing message;
  any unexpected error returns `500 {message, correlationId}` with a generic message and
  is logged in full under that ID (no SQL, host or stack details reach the client). All
  responses send `Content-Security-Policy` (self-only for the UI; no script at all for
  generated HTML reports), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP/CORP, and HSTS when the
  deployment is HTTPS (`SSI_SESSION_COOKIE_SECURE=true`).
- **Reports entegrasyonu (uygulandı):** Verified/planned/blocked remediation geçmişi,
  before/after özetleri ve son sekiz ISO hafta trendi store'dan üretilir. Reports ve Audit
  ekranları gerçek API'yi kullanır; API erişilemezse veri kaynağı açıkça fixture olarak
  işaretlenir.
- **Registry:** Harbor URL `registry.example.com`. Robot account + secret
  bilgisi sağlandı; secret dosyaları repoya commit edilmez, deployment secret/env
  olarak yönetilir.

## Endpoint özeti

### Inventory
| Metot | Yol | Açıklama |
|---|---|---|
| GET | `/images` | Envanteri listele (filtre: q, type, source, status) |
| GET | `/images/{id}` | İmaj detayı |
| GET | `/images/{id}/sbom` | SBOM bileşenleri |

### Pipeline (akış)
| Metot | Yol | Açıklama |
|---|---|---|
| POST | `/ingest` | Registry'den imaj al + tara (async) |
| GET | `/ingest` | Ingest kuyruğu |
| GET | `/scans` | Scan Results için normalize raporlar; Harbor aktifse artifact vulnerability result okur |
| GET | `/images/{id}/scan` | Son tarama raporu (CVSS + EPSS bulguları) |
| POST | `/images/{id}/scan` | Yeni tarama (async) |
| POST | `/images/{scanReportId}/remediation` | **Mevcut:** `dryRun: true` ile OS package remediation planı oluşturur; dış sistemde işlem yapmaz (`201`) |
| GET | `/remediation` · `/remediation/{id}` | Dry Run planları ve ileride gerçek remediation sonuçları |
| POST | `/remediation/{id}/canonical-report` | **Mevcut:** immutable digest'e bağlı OS-only ham Trivy JSON'u doğrular ve Dry Run planını yeniden hesaplar (`200`); execution başlatmaz |
| POST | `/remediation/{id}/supply-chain-evidence` | Manual upload of the signing worker's receipt (`remediation:manage`); stored and audited as `channel=manual` |
| POST | `/remediation/{id}/worker-supply-chain-evidence` | Signing worker delivery, HMAC-SHA256 with purpose `ssi-supply-chain-evidence-v1` (`SSI_SUPPLY_CHAIN_EVIDENCE_HMAC_SECRET`); stored as `channel=worker` |
| POST | `/remediation/{id}/worker-evidence` | **Mevcut/önerilen operasyonel yol:** worker'ın HMAC-SHA256 imzalı execution evidence'ını replay penceresi içinde doğrular; ayrı `Verified` execution kaydı oluşturur (`201`, idempotent tekrar `200`) |
| POST | `/remediation/{id}/verification-evidence` | **Mevcut manuel geri dönüş yolu:** evidence JSON'unu immutable digest ve canonical input ile doğrular; otomatik worker teslimatı kullanılamadığında PoC/debug amaçlıdır |
| GET | `/remediation/{id}/execution-readiness` | **Mevcut:** izole worker'a geçmeden önce lifecycle/önkoşul görünürlüğü sağlar; dispatch yapmaz |
| GET | `/remediation/{id}/worker-handoff` | **Mevcut:** canonical plan için credential-free, prepare-only worker manifesti döner (`200`); pull/patch/push/re-scan veya dispatch yapmaz |
| POST | `/images/{id}/publish` | Harbor'a robot account ile yayın (async) — policy geçmezse `409` |
| GET | `/publish` | Yayın kuyruğu/geçmişi |

### Onboarding (karantina import)
| Metot | Yol | Açıklama |
|---|---|---|
| POST | `/onboarding` | **Mevcut (Faz 5):** dış imaj için onboarding isteği oluşturur (`{ sourceReference }`); karantina (`onboarded/`) hedefi türetilir. SSI pull/registry yazma yapmaz (`201`). Aynı ekip + aynı karantina hedefi için açık (`Requested`/`Importing`) bir istek varsa `409` (mesaj açık isteğin ID'sini verir) |
| GET | `/onboarding` | İstek kuyruğu (durum + kaynak takibi) |
| GET | `/onboarding/{id}/worker-handoff` | Credential-free handoff manifesti (izole import worker tüketir); `X-SSI-Onboard-Handoff-Token` ister, ilk çekişte `Importing`'e geçer. `Cancelled` istek için `409` |
| POST | `/onboarding/{id}/cancel` | Açık (`Requested`/`Importing`) isteği kapatır → `Cancelled` (`{ reason }`, 10–1000 karakter, tek satır). `onboarding:create` + güvenilir kimlik ister; yalnızca ekibin kendi istekleri (başka ekip `404`). Kapanmış istek `409`. Audit: `onboarding.request.cancelled`, reddedilen deneme `onboarding.cancel.rejected` |
| POST | `/onboarding/{id}/import-receipt` | İzole worker'ın import sonucu → `Imported`/`Failed`; HMAC imzası ister (`SSI_ONBOARD_RECEIPT_HMAC_SECRET`, `X-SSI-Evidence-*` header'ları; geçiş döneminde `ONBOARD_RECEIPT_TOKEN` tanımlıysa imzasız token da kabul edilir). Aynı receipt tekrar gelirse değişiklik yapılmaz, `200` + `X-SSI-Receipt-Replay: true`. İptal edilmiş isteğe gelen receipt `importAfterCancellation` olarak kaydedilir, durum `Cancelled` kalır (audit uyarısı `onboarding.receipt.after-cancellation`); ikinci, farklı bir receipt `409` |

Ayrıntı: [`onboarding-worker-contract.md`](onboarding-worker-contract.md).

### Yönetim & Raporlama
| Metot | Yol | Açıklama |
|---|---|---|
| GET | `/health` | Public readiness probe: `{status, timestamp}` — `200 ok` / `503 degraded`; failure details are logged, never returned |
| GET | `/session` | **Mevcut (Faz 5):** mevcut kullanıcının subject + roller + etkin izinler + enforcement durumu (UI rol-duyarlılığı için). RBAC muaf. |
| GET | `/policy/rules` | Enforcement kuralları |
| POST | `/policy/evaluate` | İmajı politikaya göre değerlendir (pass/findings) |
| GET · POST | `/exceptions` | İstisna kuyruğu / yeni talep |
| GET | `/reports/remediation` | Remediation özeti, geçmişi ve haftalık before/after trendi |
| GET | `/reports/remediation/{jobId}/document` | **Mevcut (Faz 5):** tek bir remediation job için yazdırmaya/PDF'e uygun, kendi kendine yeten HTML rapor dokümanı döner (imaj, önem bazlı öncesi/sonrası, kapatılan CVE listesi, tam imaj karşılaştırması, publish durumu). `?download=true` dosya olarak indirir; iş bulunamazsa `404` |
| GET | `/reports/export?type=inventory\|remediation&format=csv` | CSV dışa aktar |
| GET | `/audit-events?limit=100&before=…` | Yapılandırılmış denetim zaman çizelgesi, en yeni önce (`limit: 1..250`). Sunucu tarafı filtreler: `category`, `failures`, `actor`, `resourceType`, `resourceId`, `correlationId`, `q`, `from`, `to`. Sonraki sayfa: cevabın `X-SSI-Next-Cursor` değeri `before` olarak verilir (keyset; araya giren kayıt sayfayı kaydırmaz). Geçersiz filtre/cursor `400` |
| GET | `/audit-events/summary` | Filtreye uyan olay sayısı, toplam ve kategori başına |
| GET | `/audit-events/export?from=…&to=…` | Filtreye uyan tüm olayların CSV'si (`audit:read`). Dönem zorunlu, en fazla 50.000 satır (fazlası gönderilmeden `422`). RFC 4180, UTF-8 BOM, formül enjeksiyonuna karşı korumalı. Her dışa aktarma ve reddi audit'e yazılır (`audit.exported`, `audit.export.rejected`) |
| GET | `/jobs/{jobId}` | Async iş durumu |
| GET | `/integrations/azure-devops` | **Yeni (otomasyon Faz 1):** Azure DevOps bağlantı durumu (token hariç) + her worker pipeline için salt-okuma sağlık kontrolü. Yalnızca `system:admin`. Bkz. `docs/azure-devops-integration.md` |
| GET · POST | `/remediation/{jobId}/pipeline-runs` | **Yeni (otomasyon Faz 2):** işin worker pipeline aksiyonları + canlı run durumu / pipeline başlat (`{action, canonicalBuildId?}`, `remediation:manage`). Parametreleri SSI üretir. Bkz. `docs/azure-devops-integration.md` |
| POST | `/remediation/{jobId}/worker-canonical-report` | **Yeni (otomasyon Faz 3):** canonical scan worker'ının `canonical-trivy.json` teslimi, HMAC imzalı (`SSI_CANONICAL_REPORT_HMAC_SECRET`, amaç `ssi-canonical-report-v1`). RBAC muaf (makine-arası); yalnızca Dry Run; aynı rapor tekrarında değişiklik yok |
| GET · POST | `/onboarding/{id}/pipeline-runs` · `/publish-requests/{id}/pipeline-runs` · `/scans/pipeline-runs` | **Yeni (otomasyon Faz 4a):** Onboard Import (`onboarding:create`), Controlled Publish ve Supply-Chain Sign (`publish:approve`), Image Inspection (`remediation:manage`) pipeline'larını başlatma ve canlı run durumu. Parametreleri SSI üretir |

## Dry Run akışı (mevcut)
```
POST /api/v1/images/registry.example.com%2Fpayment-api%3A1.2.3/remediation
{ "scanReportId": "registry.example.com/payment-api:1.2.3", "dryRun": true }
   → 201 {
       "id": "RM-DRY-0001",
       "mode": "dry-run",
       "status": "Planned",
       "plannedFixes": [ ... ],
       "patchedImageDigest": "",
       "verificationStatus": "Pending"
     }

GET /api/v1/remediation/RM-DRY-0001
   → 200 { "mode": "dry-run", "before": {...}, "after": null, "fixed": [] }

GET /api/v1/remediation/RM-DRY-0001/execution-readiness
   → 200 { "lifecycleState": "planned", "dispatchAllowed": false, "requirements": [...] }

POST /api/v1/remediation/RM-DRY-0001/canonical-report
Content-Type: application/json
{ "SchemaVersion": 2, "ArtifactName": "...@sha256:<same-source-digest>", "Results": [ { "Class": "os-pkgs", ... } ] }
   → 200 { "status": "Planned", "canonicalReport": { "scope": "os-packages-only", ... } }

GET /api/v1/remediation/RM-DRY-0001/worker-handoff
   → 200 {
       "kind": "RemediationHandoffManifest",
       "spec": { "executionMode": "prepare-only", "source": { "immutableReference": "...@sha256:..." } },
       "safeguards": { "webContainerDispatch": false, "registryCredentialsEmbedded": false }
      }

POST /api/v1/remediation/RM-DRY-0001/verification-evidence
Content-Type: application/json
{ "contractVersion": "ssi.copa-remediation-poc/v1alpha1", "mode": "approved-poc-execution", ... }
   → 201 {
       "id": "RM-EXEC-0001",
       "parentJobId": "RM-DRY-0001",
       "mode": "execution",
       "status": "Verified",
       "before": { "critical": 19, "high": 19, "medium": 25, "low": 1 },
       "after": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
       "fixed": [ ... 64 kayıt ... ],
       "fullImageComparison": {
         "source": { "findings": 77 },
         "output": { "findings": 13 },
         "remainingOutsideCanonicalOsScope": 13
       },
       "publishGate": { "allowed": false, "status": "Blocked" }
     }
```

## Hedef async akış (izole Copa worker sonrası)
```
POST /api/v1/images/{scanReportId}/remediation
{ "dryRun": false }
   → 202 { "id": "job_ab12", "type": "remediation", "status": "queued" }

GET /api/v1/jobs/job_ab12
   → 200 { "status": "running", ... }
   → 200 { "status": "succeeded", "resultUrl": "/remediation/RM-2047" }

GET /api/v1/remediation/RM-2047
   → 200 { before: {...}, after: {...}, fixed: [...], remaining: [...] }
```

## Temel şemalar (özet)
- **Image** — envanter kaydı (cve sayaçları, maxCvss, source, sbom/signature/provenance, tags…)
- **Finding** — cve, package, installed→fixed, severity, **cvss**, opsiyonel **epss**, status, Trivy target/class/type, title/url. EPSS Trivy default çıktısında gelmez; sonraki fazda CVE ID üzerinden enrich edilir.
- **RemediationJob** — `mode`, `scope`, planlanan/fixed/remaining/excluded bulgular,
  before/after severity, engine, tag/digest, verification state ve audit log. Dry Run
  kaydında `after`, patched digest ve `fixed[]` bilinçli olarak boş kalır. Kabul edilen
  verification evidence ayrı bir `execution` kaydı oluşturur ve parent Dry Run kimliğini,
  evidence digest'ini, full-image karşılaştırmasını ve publish gate sonucunu taşır.
- **RemediationExecutionReadiness** — worker'a dispatch edilmeden önce uygun OS paket
  planı, immutable digest, canonical Trivy JSON, credential-free handoff ve izole worker'ın
  SSI'dan başlatılabilirliğini gösteren salt-okunur kontrat. `workerConfigured`, Azure DevOps
  Copa pipeline'ı ayarlıysa `true`; `dispatchAllowed` tüm koşullar sağlanınca `true` olur.
  Re-scan ve registry sınırları listede değildir: worker her zaman uygular, iş yalnızca
  doğrulanmış kanıtla ilerler.
- **CanonicalTrivyReceipt** — canonical report'un report/content digest'i, source
  digest'i, Trivy sürümü, üretim zamanı, OS package sınıfı ve bulgu sayısı. Raw JSON
  web/API job kaydına saklanmaz.
- **RemediationReport** — store'daki job'lardan hesaplanan toplam/verified/planned/blocked
  sayıları, remediated CVE toplamı, publish-blocked sayısı, remediation history ve son
  sekiz ISO haftalık Critical/High/Medium trendi.
- **AuditEvent** — UUID event/correlation kimliği, actor, action, resource, outcome,
  severity, özet, redacted metadata ve UTC timestamp içeren append-only olay kaydı.
- **RemediationHandoffManifest** — canonical report metadata'sı ve planlanan OS
  package güncellemelerini taşıyan, worker tarafından doğrulanacak content digest'i
  içeren prepare-only manifest. Raw report, robot secret, Docker config ve dispatch
  yetkisi içermez.
- **RemediationVerificationEvidence** — approved PoC execution'ın immutable source/output
  digestleri, canonical input content digest'i, Copacetic metadata'sı, Trivy before/after
  özeti ve fixed/remaining listesi. Secret veya Docker credential içermez.
- **WorkerEvidenceAuthentication** — exact request body SHA-256 digest'i, job kimliği,
  worker kimliği ve epoch timestamp'i `ssi-remediation-evidence-v1` domain separator'ı
  altında HMAC-SHA256 ile bağlayan transport sözleşmesi. Secret request body veya audit
  metadata'sına yazılmaz; replay süresi varsayılan 300 saniyedir.
- **FullImageComparison** — canonical OS-only sonucu değiştirmeden Harbor'daki kaynak ve
  patched digestlerin tam tarama sayılarını ve scope dışında kalan bulgu sayısını gösterir.
- **PublishGate** — remediation doğrulamasından bağımsız merkezi publish kararını taşır;
  verification başarılı olsa dahi policy koşulları sağlanmadan `allowed: false` kalır.
- **PublishItem** — registry/repo/digest, signature (Cosign), policyPass, status
- **Job** — id, type, status, resultUrl (async takip)
- Ayrıntı: `openapi.yaml` `components/schemas`.

## Sonraki adımlar (Faz 4)
1. **Tamamlandı:** Inventory Harbor repository/artifact verisini gerçek API'den okuyor.
2. **Tamamlandı:** Harbor/Trivy scan sonucu `Finding` modeline normalize edilip Scan
   Results ekranına bağlandı; EPSS opsiyonel tutuluyor.
3. **Tamamlandı:** Canonical OS-only Trivy input, Dry Run planı, worker handoff/preflight,
   gerçek Copa patch, test-tag push ve immutable output re-scan PoC'si doğrulandı.
4. **Tamamlandı:** Copa evidence API/UI intake'i; OS-only `64 → 0` ile full-image
   `77 → 13` sonucu ve bloklu publish gate ayrı gösteriliyor.
5. **Tamamlandı:** Verified execution kaydı gerçek Reports/Audit API ve ekranlarına
   taşındı; yapılandırılmış audit ve PostgreSQL destekli persistence katmanı eklendi.
6. **Tamamlandı:** Başarılı Copa pipeline evidence'ının imzalı, replay-korumalı ve
   idempotent worker callback'i ile SSI API'ye otomatik teslim sözleşmesi eklendi.
7. **Operasyonel aktivasyon:** Harici PostgreSQL sağlanması, migration'ın ayrı yetkili
   bağlantıyla uygulanması, yedekleme/retention ve canlı `PERSISTENCE_DRIVER=postgres`
   geçişinin kontrollü doğrulanması.
8. **Sıradaki:** Policy kabul kriteri ve kontrollü publish/promote approval akışını bağlamak.
9. **Faz 5:** Bearer placeholder → LDAP/AD + RBAC; signing, gerçek SBOM/provenance ve
   application dependency remediation capability'si.

## Açık noktalar (diğer ekiplerle netleşecek)
- Kalan 13 application dependency bulgusunun sonraki capability kapsamı ve önceliği.
- Kalan Critical/High bulgular için kontrollü publish/promote kabul kriteri ve approval sahibi.
- Production öncesi ayrı least-privilege remediation worker ve kalıcı secret delivery
  standardı.
- PostgreSQL servis sahibi, HA/yedekleme/retention hedefleri ve migration credential
  yönetim standardı.
- Copacetic'e alternatif remediation yaklaşımlarının kısa teknik değerlendirmesi.
