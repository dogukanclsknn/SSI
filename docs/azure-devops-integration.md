# Azure DevOps entegrasyonu (otomasyon Faz 1–4)

SSI'nın worker pipeline'larını (onboard-import, canonical-trivy-scan, copa-remediation-poc,
candidate-test, image-inspection, controlled-publish, supply-chain-sign) Azure DevOps Pipelines
REST API 7.1 üzerinden kendisinin başlatabilmesi için bağlantı katmanı.

- **Faz 1:** bağlantı ve admin sağlık kontrolü.
- **Faz 2:** Remediation ekranında **Run in Azure DevOps** düğmeleri — canonical scan, Copa (önce girdi
  kontrolü, sonra patch) ve candidate test. SSI pipeline'ı yalnızca bir kişi düğmeye bastığında başlatır;
  kendiliğinden hiçbir şey çalıştırmaz.
- **Faz 3:** canonical scan raporu SSI'a imzalı olarak kendisi gelir (elle indir-yükle kalkar); verified
  sonucu olan bir Dry Run'da Copa yeniden çalıştırılamaz; run satırında "Open in Azure DevOps" linki.

Ayarlar boşsa SSI bugünkü gibi elle çalışır ve düğmeler görünmez.

## Ne yapar, ne yapmaz

| SSI yapar                                                                  | SSI yapmaz                                                                |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Yalnızca `SSI_ADO_PIPELINE_*` ile verilen definition ID'lerine çağrı       | Başka pipeline, repo, release, variable group, agent pool'a dokunmak      |
| Yalnızca `SSI_ADO_ORG_URL` + `SSI_ADO_PROJECT`                             | `dev.azure.com` / `*.visualstudio.com` dışında bir adrese token göndermek |
| Yalnızca `SSI_ADO_PIPELINE_REF` dalında run (varsayılan `refs/heads/main`) | Başka daldan run, YAML override                                           |
| `GET pipeline`, `POST runs`, `GET run`                                     | Silme, iptal, onay (approval) — insan kapıları ADO'da kalır               |
| Pipeline parametrelerini job kaydından kendisi üretir                      | Kullanıcıdan serbest metin parametre almak (yalnızca Build ID sayısı)     |
| Token'ı yalnızca `Authorization` başlığında taşır                          | Token'ı URL'ye, loga, hata mesajına, API cevabına yazmak                  |

Token geniş yetkili olsa bile SSI bu çağrıların dışına çıkmaz. Yine de token'ın kendisi ADO'da geniş
yetkilidir; bu yüzden **süresi kısa tutulur ve devirden sonra döndürülür** (aşağıda).

## Ayarlar (`/data/SSI/.env`)

| Değişken                              | Örnek                            | Not                                        |
| ------------------------------------- | -------------------------------- | ------------------------------------------ |
| `SSI_ADO_ORG_URL`                     | `https://example-org.visualstudio.com` | https, kimlik bilgisi/query yok            |
| `SSI_ADO_PROJECT`                     | `SecureImages`                         |                                            |
| `SSI_ADO_PAT`                         | —                                | **SECRET.** Yalnızca gizli girişle yazılır |
| `SSI_ADO_PIPELINE_REF`                | `refs/heads/main`                | Boşsa `refs/heads/main`                    |
| `SSI_ADO_PIPELINE_ONBOARD_IMPORT`     | `412`                            | Pipeline URL'sindeki `definitionId=`       |
| `SSI_ADO_PIPELINE_CANONICAL_SCAN`     |                                  |                                            |
| `SSI_ADO_PIPELINE_COPA_REMEDIATION`   |                                  |                                            |
| `SSI_ADO_PIPELINE_CANDIDATE_TEST`     |                                  |                                            |
| `SSI_ADO_PIPELINE_IMAGE_INSPECTION`   |                                  |                                            |
| `SSI_ADO_PIPELINE_CONTROLLED_PUBLISH` |                                  |                                            |
| `SSI_ADO_PIPELINE_SUPPLY_CHAIN_SIGN`  |                                  |                                            |
| `SSI_ADO_PIPELINE_OS_TEMPLATE_WINDOWS`|                                  | SSI - OS Template (Windows), havuz `SSI-Windows` |
| `SSI_ADO_PIPELINE_OS_TEMPLATE_UBUNTU` |                                  | SSI - OS Template (Ubuntu), havuz `LinuxPool` |

En az bir pipeline ID'si gerekir; boş bırakılan rol "Not configured" görünür ve SSI onu çağırmaz.
Biçimi bozuk bir değer varsa entegrasyon **tamamen kapalı** kalır ve açılış logunda yalnızca değişken
adı yazar (değer asla).

## Kurulum

1. **PAT oluştur** — Azure DevOps → sağ üst kullanıcı menüsü → _Personal access tokens_ → _New Token_.
   Organization: `example-org`. Süre: en fazla 30–90 gün. Kapsam: ekip kararı (en az _Build: Read & execute_).
   Token yalnızca bir kez gösterilir; kopyalayıp doğrudan 3. adımdaki gizli girişe yapıştırın.
2. **Definition ID'leri bul** — her pipeline'ı ADO'da açın; adres çubuğundaki `definitionId=<sayı>`.
3. **`.env`'ye yaz** (sunucuda, `/data/SSI`):
   ```bash
   # Token ekrana ve shell geçmişine düşmez
   read -rsp 'ADO PAT: ' P; echo; printf 'SSI_ADO_PAT=%s\n' "$P" >> /data/SSI/.env; unset P
   ```
   Diğer (gizli olmayan) değişkenler normal editörle eklenir.
4. **Yeniden deploy** — push sonrası sunucuda `cd /data/SSI && docker compose up -d --build ssi`
   (yeni kod imaja ancak `--build` ile girer). Açılış logu:
   `Azure DevOps: https://example-org.visualstudio.com/SecureImages, N pipeline(s) on refs/heads/main.`
   Ayar hatalıysa: `Azure DevOps integration is off: <yalnızca değişken adları>`
5. **Doğrula** — admin kullanıcıyla tarayıcıda `http://10.0.0.10:5021/api/v1/integrations/azure-devops`.
   Her rol için `ok: true` ve pipeline adı görünmeli.

## Remediation ekranından çalıştırma (Faz 2)

Sağ sütundaki **Azure DevOps** kartı. Yetki: `remediation:manage` (operator). Her başlatma audit'e
`remediation.pipeline-run.started` olarak yazılır: kim, hangi pipeline, ADO run no, gönderilen parametreler.

| Düğme                | İş                                                      | Pipeline                                                    | Koşul                                                                                           |
| -------------------- | ------------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Canonical Trivy scan | Dry Run (planlı ya da Harbor taraması yüzünden Blocked) | SSI - Canonical Trivy Scan                                  | Görüntü `HARBOR_PROJECTS`'in ilk projesinde, tam sha256 digest                                  |
| Copa input check     | Planlı Dry Run                                          | SSI - Copa Patch + Re-scan PoC (`executeRemediation=false`) | Canonical JSON yüklenmiş; SSI'ın başlattığı başarılı canonical scan ya da elle girilen Build ID |
| Copa patch + re-scan | Planlı Dry Run                                          | aynı (`executeRemediation=true`), **onay adımıyla**         | Aynı canonical girdiyle başarılı bir input check                                                |
| Candidate test       | Verified RM-EXEC                                        | SSI - Candidate Test                                        | Geri çekilmemiş imaj                                                                            |

- Aynı iş için aynı pipeline'ın çalışan bir run'ı varken ikinci run başlamaz (409). Kontrol, run başlatma
  ve kayıt job satırı kilitliyken tek adımda yapılır.
- Copa çıktı etiketi: `copa-poc-<YYYYMMDD>-<kaynak tag>-<job id>-r<N>`, çıktı reposu kaynakla aynı.
- Run durumu ekran açıkken 15 sn'de bir ADO'dan okunur. Run bitince iş listesi yenilenir; canonical
  rapor, Copa ve candidate test kanıtı SSI'a kendisi gelir.
- Bir Dry Run'dan verified bir RM-EXEC çıktıysa (geri çekilmemiş) o Dry Run'da Copa input check ve patch
  kapanır. Aynı imajı yeniden yamamak için yeni bir Dry Run açılır.
- ADO cevap vermezse run'ın son bilinen durumu gösterilir ve yeni run başlatılmaz.

## Onboard, Publish, Sign ve Image Inspection düğmeleri (Faz 4a)

| Ekran                         | Düğme                                            | Pipeline                                          | Koşul                                             | Yetki                |
| ----------------------------- | ------------------------------------------------ | ------------------------------------------------- | ------------------------------------------------- | -------------------- |
| Onboard → satırda **Import…** | Import check                                     | SSI - Onboard Import (`executeImport=false`)      | Requested / Importing istek                       | `onboarding:create`  |
|                               | Import into quarantine (**onaylı**)              | aynı (`executeImport=true`)                       | Aynı istekte başarılı import check                | `onboarding:create`  |
| Publish → seçili talep        | Publish check                                    | SSI - Controlled Publish (`executePublish=false`) | **Approved** talep                                | `publish:approve`    |
|                               | Publish to approved/ (**onaylı**)                | aynı (`executePublish=true`)                      | Aynı talepte başarılı publish check               | `publish:approve`    |
|                               | Sign + SBOM + provenance (**onaylı**)            | SSI - Supply-Chain Sign (`postToSsi=true`)        | **Published** talep, hedef proje = worker projesi | `publish:approve`    |
| Scan Results → karşılaştırma  | Image inspection (taban ve karşılaştırılan imaj) | SSI - Image Inspection (`deliverToSsi=true`)      | Takımın görebildiği tarama                        | `remediation:manage` |

- Onboard, Publish ve Sign pipeline'ları SSI adresini parametre olarak alır. `.env`'de
  `SSI_ADO_WORKER_API_BASE_URL` (Copa/candidate pipeline'larındaki `SSI_API_BASE_URL` ile aynı) olmalı;
  adres `http://` ise SSI `allowInsecurePocApi=true` gönderir. Tanımlı değilse bu üç düğme gerekçesiyle kapalı kalır.
  Bu değer pipeline'ların izin verdiği adreslerden biri olmalıdır (aşağıdaki "Worker sınırları"); değilse
  Azure DevOps run'ı başlatmaz ve SSI hatayı gösterir.
- Registry'ye yazan adımlar (import, publish, sign) sayfa içinde ikinci bir onay ister.
- Onboarding ve publish run'ları kendi kayıtlarında (`pipelineRuns`), image inspection run'ları yeni
  `pipeline_runs` tablosunda (migration 012) tutulur. Başlatma kayıt kilitliyken yapılır; publish için
  iş ve talep satırı diğer publish kararlarıyla aynı sırada kilitlenir.
- Audit: `onboarding.pipeline-run.started`, `publish.pipeline-run.started`, `scan.pipeline-run.started`
  (reddedilenler `.rejected`).
- Bir inspection run'ı bitince karşılaştırma kendiliğinden yeniden okunur.

## OS Templates (Windows ISO, Ubuntu 24.04)

Bir OS template build talebinin (`OST-…`) işletim sistemi talepte yazar (`os`; yoksa Windows) ve
yalnızca o işletim sisteminin worker'ı başlatılabilir:

| `os` | Eylem | Worker | Parametreler (hepsi talepten) |
|---|---|---|---|
| `windows` (varsayılan) | `os-template-build` | **SSI - OS Template (Windows)**, `azure-pipelines-os-template-windows.yml`, havuz `SSI-Windows` | `isoFile`, `isoSha256`, `imageIndex`, `product`, `templateName` |
| `ubuntu-24.04` | `os-template-build-ubuntu` | **SSI - OS Template (Ubuntu)**, `azure-pipelines-os-template-ubuntu.yml`, havuz `LinuxPool` | `baseImageUrl`, `baseImageSha256`, `templateName`, `diskSizeGb`, `aptMirror` (boşsa `none`) |

İkisine de `osTemplateBuildId`, `deliverToSsi=true`, `ssiApiBaseUrl`, `allowInsecurePocApi` gider.
Sonuç `POST /os-templates/{id}/worker` ile HMAC imzalı döner (`ssi-os-template-evidence-v1`,
`SSI_OS_TEMPLATE_EVIDENCE_HMAC_SECRET`; sunucu `.env` + her iki pipeline'da aynı adlı secret değişkeni).

| Eylem | Kim | Koşul |
|---|---|---|
| Talep (`POST /os-templates`) | `os-template:build` (operator) | Kaynağın SHA-256'sı zorunlu; Ubuntu'da yalnızca `https://cloud-images.ubuntu.com/…` |
| Build başlat (`POST /os-templates/{id}/pipeline-runs`, **onaylı**) | `os-template:build` | Talep **Requested**, eylem talebin işletim sistemine ait, aynı pipeline'da açık run yok |
| Sonuç (worker), Windows | HMAC | Talebin ISO'su, index'i ve adı; **0 açık CVE** (MSRC); kapı geçti |
| Sonuç (worker), Ubuntu | HMAC | Talebin cloud image URL'si, SHA-256'sı ve adı; Trivy imajı **Ubuntu 24.04** olarak tanımış; **düzeltmesi olan CVE yok**; kapı uygulanmış ve geçmiş; Trivy DB'si build'den en çok 7 gün eski; QCOW2 + OVA + VHDX (her biri bir kez, adı ve SHA-256'sıyla); dosyalar o ADO run'ının `os-template-ubuntu-images` artefaktında |
| Onay / red (`/approve`, `/reject`) | `os-template:approve` (approver) | Onay yalnızca **Built**; talep eden karar veremez (dört göz); red gerekçeli |

OS template'leri platform genelidir (takım kapsamı yok); her rol okur.

**İndirme ve saklama (Ubuntu):** SSI, Built/Approved bir template'in dosyalarını o run'ın
artefaktlarından akıtır (`GET …/_apis/build/builds/{runId}/artifacts?artifactName=…`, `Accept:
application/zip`; ADO zip'i `Content-Length` olmadan gönderir, eksik başlık "boyut bilinmiyor" sayılır;
22 baytlık boş arşiv hiç verilmez) ve onaylanan
template'in run'ına retention lease koyar (`POST …/_apis/build/retention/leases`). İkisi de mevcut PAT
kapsamıyla çalışır (artefakt okumak için **Build: Read**, lease için **Build: Read & execute**).
İndirme bağlantısı 5 dakikalıktır ve en fazla 3 kez kullanılabilir; ayrıntı `docs/os-template-poc.md` ("SSI'dan
indirme"). Büyük dosyalar (VHDX ~3 GB) önündeki reverse proxy üzerinden akar; SSI
`X-Accel-Buffering: no` gönderir. Proxy'de yanıt süresi ya da boyut sınırı varsa indirme yarıda
kesilir.

## Image Journey (Faz 4b)

Sol menüde **Image Journey**: bir remediation planının (RM-DRY) dokuz adımı tek ekranda.

1. Onboard
2. Canonical scan
3. Copa input check
4. Patch + re-scan
5. Candidate test
6. Consumer acceptance
7. Publish approval
8. Publish
9. Sign + SBOM

- **Adım durumları** mevcut kayıtlardan okunur (`src/lib/imageJourney.js`): canonical rapor, run'lar, RM-EXEC, candidate test, tüketici kararı, publish talebi ve imza kanıtı. Ekran yeni bir karar vermez; diğer ekranların reddedeceği hiçbir şeyi atlatmaz.
- **Her zaman tek bir "Next" adım vardır.**
  - Worker adımında, o kaydın kendi ekranındaki Azure DevOps paneli aynen gösterilir. Yetki, onay sorusu ve çift run engeli aynıdır.
  - İnsan kapısında (tüketici kabulü, publish onayı) kimin karar verdiği ve 4 göz kuralı yazar. Kararın verildiği ekran kayıt seçili açılır.
- **Geri çekilen sonuç:** Geri çekilen bir sonuç "verified" sayılmaz. Yolculuk "Patch" adımına döner ve bunu açıkça yazar.
- **Workflow Actions kartı:** Remediation ekranındaki Workflow Actions kartı, otomasyon açıkken elle yolu katlanabilir **Manual fallback** altında gösterir.
- **Scan Results karşılaştırması:** Her imaj kartı "inspected …" ya da "not inspected yet" yazar. Elle çalıştırma talimatı yalnızca otomasyon kapalıyken görünür.

## Canonical raporun otomatik teslimi (Faz 3)

SSI canonical scan'i `remediationJobId=<Dry Run>` ve `deliverToSsi=true` ile başlatır. Pipeline,
yayımladığı `canonical-trivy.json`'un **aynı byte'larını** HMAC imzalı olarak
`POST /api/v1/remediation/{jobId}/worker-canonical-report` adresine gönderir
(`scripts/canonical-report.mjs`, imza amacı `ssi-canonical-report-v1`). SSI raporu doğrular, Dry Run'ı
yeniden planlar ve `canonicalReport.intake.channel = worker` olarak kaydeder. Aynı rapor tekrar gelirse
hiçbir şey değişmez (`X-SSI-Evidence-Replay: true`). Copa'nın doğruladığı content digest bu byte'lardan
hesaplanır.

**Bir kerelik kurulum (sır, iki yerde aynı değer):**

1. Sunucuda `.env`'ye `SSI_CANONICAL_REPORT_HMAC_SECRET` (en az 32 rastgele byte, diğer worker
   sırlarından ayrı), gizli girişle.
2. ADO → **SSI - Canonical Trivy Scan** (4417) → Edit → Variables:
   - `SSI_CANONICAL_REPORT_HMAC_SECRET` — aynı değer, **Keep this value secret** işaretli
   - `SSI_API_BASE_URL` — Copa pipeline'ındaki değerle aynı (ör. `http://10.0.0.10:5021/api/v1`)
   - `SSI_API_ALLOW_HTTP` — Copa pipeline'ındaki değerle aynı
3. `docker compose up -d --build ssi`.

Sır veya adres yoksa pipeline yeşil-uyarılı biter (SucceededWithIssues) ve rapor yalnızca artifact'te
kalır; o zaman Dry Run sayfasından elle yüklenir (audit'te `manual`). SSI raporu reddederse run kırmızı
biter.

## Worker sınırları (pipeline'larda sabit, run sırasında değiştirilemez)

Worker pipeline'ları ADO'da elle de kuyruğa alınabilir. Bu yüzden yazma yetkili robotların ve imza
anahtarının nereye kullanılacağı SSI'ın gönderdiği parametrelere bırakılmaz; YAML'da sabittir.
YAML'ın `variables:` bloğundaki değerler run sırasında (UI ya da REST API) değiştirilemez;
`values:` listesi olan bir parametre de yalnızca listedeki değeri alır.

| Pipeline                                              | Sabit sınır                                                                                                                                                                   | Aşılırsa                                      |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| Onboard Import, Controlled Publish, Supply-Chain Sign | `ssiApiBaseUrl` yalnızca `http://10.0.0.10:5021/api/v1` veya `http://ssi.example.com/api/v1`                                                                     | ADO run'ı başlatmaz                           |
| Onboard Import                                        | Hedef `registry.example.com` / `ssi-images` / `onboarded/...` (`SSI_ONBOARD_TARGET_*`)                                                                           | Handoff reddedilir, robot şifresi kullanılmaz |
| Controlled Publish                                    | Hedef `registry.example.com` / `ssi-images` / `approved/...`, kaynak aynı registry'de (`SSI_PUBLISH_TARGET_*`)                                                   | Handoff reddedilir, robot şifresi kullanılmaz |
| Supply-Chain Sign                                     | Yalnızca `approved/...` altındaki bir digest imzalanır                                                                                                                        | İmza adımı başlamaz                           |
| Supply-Chain Sign                                     | syft ve cosign sürüm + yayımlanan SHA-256 ile sabit; sırrı olmayan ayrı bir adımda indirilir                                                                                  | Uyuşmayan dosya silinir, run durur            |
| Copa Patch + Re-scan                                  | Çıktı `approved/` altına yazılamaz. `approved/<ad>` bir imaj yamalanırsa SSI adayı `onboarded/<ad>` altına yönlendirir; aday test, kabul ve onaylı publish ile kataloğa döner | Run durur, registry'ye yazılmaz               |
| Harbor Test Push (yardımcı)                           | Hedef yalnızca `ssi-test-...` repoları                                                                                                                                        | Run durur                                     |

## Sonuç bildirimleri (receipt) imzası

Onboard Import ve Controlled Publish işini bitirince SSI'a bir receipt gönderir. Receipt, diğer worker
kanallarıyla aynı şekilde HMAC-SHA256 ile imzalanır (`src/lib/workerReceiptAuth.js`): imza kanalın
amacını (`ssi-publish-receipt-v1` / `ssi-onboard-receipt-v1`), zaman damgasını, talep numarasını,
worker kimliğini ve gövdenin SHA-256'sını kapsar. SSI şunları reddeder (`401`):

- gövdesi imzadan sonra değişmiş receipt,
- başka bir talep ya da kanal için atılmış imza,
- yaş sınırını (`SSI_REMEDIATION_EVIDENCE_MAX_AGE_SECONDS`, varsayılan 300 sn) aşmış imza,
- gövdesindeki `workerId` imzalayan worker'dan farklı olan receipt.

| Kanal              | Sunucu (`.env`) ve ADO secret variable | Geçiş dönemi token'ı        |
| ------------------ | -------------------------------------- | --------------------------- |
| Controlled Publish | `SSI_PUBLISH_RECEIPT_HMAC_SECRET`      | `SSI_PUBLISH_RECEIPT_TOKEN` |
| Onboard Import     | `SSI_ONBOARD_RECEIPT_HMAC_SECRET`      | `ONBOARD_RECEIPT_TOKEN`     |

**Geçiş:** Token `.env`'de tanımlı kaldıkça imzasız, token'lı receipt de kabul edilir; her biri sunucu
loguna yazılır ve audit kaydına `authentication: legacy-token` düşer (imzalılar `hmac`). İki pipeline da
imzalı gönderdikten sonra token'lar `.env`'den ve ADO'dan silinir; kod değişikliği gerekmez. O andan
sonra imzasız receipt `401` alır ve açılış logunda receipt uyarısı görünmez. İmzalı bir receipt hiçbir
zaman token'a düşürülmez: imza varsa yalnızca imza karar verir.

Secret değerleri en az 32 rastgele bayt olmalı, diğer worker secret'larından ayrı üretilmeli ve yalnızca
sunucu `.env`'inde ve ilgili pipeline'ın ADO secret variable'ında bulunmalıdır.

**SSI adresi ya da Harbor hedefi değişirse:** ilgili YAML'daki liste/değişken bir commit ile güncellenir
(kod incelemesinden geçen değişiklik), sonra `.env`'deki `SSI_ADO_WORKER_API_BASE_URL` aynı değere getirilir.

**Araç yükseltme (sign):** `SYFT_VERSION`/`COSIGN_VERSION` ile birlikte `*_LINUX_AMD64_SHA256` değeri de
güncellenir; değer aracın sürüm sayfasındaki checksum dosyasından alınır (`syft_<sürüm>_checksums.txt`,
`cosign_checksums.txt`).

**ADO tarafında önerilen ayarlar (proje yöneticisi):**

- Worker pipeline'larında _Queue builds_ yetkisi yalnızca SSI otomasyon kimliğinde ve yöneticilerde olsun.
- _Project settings → Pipelines → Settings → Limit variables that can be set at queue time_ açık olsun.
- Bu iki ayar, YAML'daki sınırlara ek bir katmandır; sınırlar onlarsız da geçerlidir.

## Sağlık kontrolü cevabı

`GET /api/v1/integrations/azure-devops` (yalnızca `system:admin`) — her yapılandırılmış pipeline için
salt-okuma `GET pipeline` çağrısı yapar:

| `error`                                   | Anlamı                         | Ne yapılır                                     |
| ----------------------------------------- | ------------------------------ | ---------------------------------------------- |
| `Not configured`                          | O rolün ID'si yok              | Gerekirse ID ekle                              |
| `…did not accept the token…`              | Süresi dolmuş/iptal/yanlış org | Yeni PAT, `.env`, redeploy                     |
| `…no permission for this pipeline…`       | Kapsam yetmiyor                | PAT kapsamını kontrol et                       |
| `…was not found…`                         | Yanlış ID veya proje           | `definitionId`'yi kontrol et                   |
| `…could not be reached / did not answer…` | Ağ / proxy                     | Sunucudan `example-org.visualstudio.com:443` erişimi |

## Token döndürme (devir sonrası zorunlu)

1. ADO'da yeni token oluştur (tercihen servis hesabında, en az yetkiyle).
2. Sunucuda `.env` içindeki `SSI_ADO_PAT` satırını gizli girişle yeniden yaz.
3. Redeploy, 5. adımdaki doğrulama.
4. ADO'da eski token → _Revoke_.

Token'ı Teams, e-posta, doküman veya sohbet üzerinden paylaşmayın.
