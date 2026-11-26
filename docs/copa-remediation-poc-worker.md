# Copa Patch + Re-scan PoC Worker

## Amac

`azure-pipelines-copa-remediation-poc.yml`, SSI web uygulamasindan ayri calisan,
manuel baslatilan bir **Copa patch + re-scan PoC worker** tanimidir. Jordan Reed'in
ilk faz kapsamiyla uyumludur: yalnizca Trivy'nin kanitladigi `os-pkgs` bulgulari
icin patch onerir; npm, pip, Maven ve Go dependency remediation'i bu asamada
kapsam disindadir.

Pipeline, web/API container'inin Docker socket'ine veya Harbor yazma secret'ina
erismesini saglamaz. Registry credential'i yalnizca calisan worker'in gecici
Docker config dosyasina yazilir, artifact olarak yayinlanmaz ve job sonunda
silinir.

## Neden Copa BuildKit Frontend?

Mevcut read-only preflight, onceden kurulmus `copa` CLI binary'sini kontrol eder.
Bu PoC pipeline'i ise Copacetic'in resmi BuildKit frontend yaklasimini kullanir;
bu nedenle worker'a ayri bir Copa binary kurmadan Docker Buildx ile calisabilir.
Frontend OCI referansi `v0.14.2` icin digest ile pinlenmistir. Bu tercih hem
worker'i daha tekrarlanabilir yapar hem de runtime'da rastgele binary indirmez.

Resmi referanslar:

- [Copacetic BuildKit frontend](https://project-copacetic.github.io/copacetic/website/buildkit-frontend)
- [Copacetic quick start](https://project-copacetic.github.io/copacetic/website/quick-start)
- [Docker BuildKit registry CA configuration](https://docs.docker.com/build/buildkit/configure/)

## Guvenlik sinirlari

- Pipeline `trigger: none` ve `pr: none` ile yalnizca manuel calisir.
- `executeRemediation` varsayilan olarak `false`tur. Bu mod sadece canonical
  inputu denetler ve `prepared-remediation-input.json` ile
  `remediation-result.json` kanitlarini yayinlar.
- Patch, Harbor'a push ve verification re-scan yalnizca operator run ekraninda
  **`executeRemediation=true`** secildiginde calisir.
- Kaynak image mutable tag ile degil `repository@sha256:...` digest'iyle okunur.
- Canonical Trivy JSON, Azure artifact'inden indirilir; byte seviyesindeki SHA-256
  digest'i ve source digest baglantisi dogrulanmadan Copa'ya verilmez.
- Sadece `SchemaVersion: 2`, yalnizca `Results[].Class = os-pkgs` ve fixed
  version'i olan bulgular kabul edilir.
- Cikti tag'i zorunlu olarak `copa-poc-*` ile baslar. Source tag degistirilmez ve
  onayli/kurumsal publish akisi baslatilmaz.
- Worker, Harbor CA'sini BuildKit'in gecici `buildkitd.toml` yapilandirmasina
  verir. `--insecure`, `curl -k` ve HTTP fallback kullanilmaz.
- Pushed PoC output tekrar Trivy ile **immutable digest** uzerinden taranir.
  Verification; en az bir bulgunun kapanmasini, toplam bulgunun azalmasini ve
  Critical + High sayisinin artmamasini zorunlu kilar.

## Image configuration integrity gate

Copa yalnizca paket katmani ekler; yamali image kaynakla ayni sekilde baslamali ve
calismalidir. Copa BuildKit frontend ciktisi kaynagin runtime config'ini
(Entrypoint, Cmd, ExposedPorts, StopSignal, ...) kaybedebilir ve CVE re-scan bunu
gormez (html-hello-world smoke testi, run 20261102.6). Bu yuzden Harbor'a kopyadan
once su kapi calisir (`scripts/image-config-integrity.mjs`,
`src/lib/imageConfigIntegrity.js`):

1. Copa ciktisinin ve ayni platformdaki kaynak image'in manifest ve config blob'lari
   regctl ile indirilir; her byte kendi digest'iyle dogrulanir.
2. Runtime config karsilastirilir. Ayniysa cikti degismez (`preserved`).
3. Farkliysa yalnizca config degistirilir: Copa ciktisinin rootfs/history/platform
   bilgisi kalir, `config` bolumu kaynaktan gelir; katmanlar ayni kalir. Yeni config ve
   manifest gecici registry'ye yazilir (`restored`).
4. Son image bagimsiz olarak tekrar indirilip dogrulanir; config, platform, katmanlar
   ve digest planla birebir uyusmazsa run basarisiz olur.
5. Sonuc `evidence/config-integrity.json` ve `remediation-result.json` icindeki
   `configIntegrity` alanidir (`ssi.image-config-integrity/v1`). SSI bu kanit olmadan
   execution evidence kabul etmez; publish policy v1.2 `image-config-preserved`
   kontroluyle kaniti output digest'e baglar.

Birden fazla platform image'i iceren Copa ciktisi desteklenmez ve run fail-closed durur.
Config geri yuklendiginde BuildKit'in kendi attestation manifest'i ciktida yer almaz;
SSI'in Cosign imza/SBOM/provenance kanitlari bundan etkilenmez.

## Calistirma sirasi

1. `SSI - Canonical Trivy Scan` pipeline'ini source `repository@digest` icin
   basariyla calistir.
2. Azure DevOps URL'sinden bu run'in teknik **Build ID** degerini al
   (`buildId=...`). Gorunen run numarasi ile Build ID ayni sey degildir.
3. `canonical-trivy-os-report` artifact'ini indir ve `canonical-trivy.json`
   dosyasinin SHA-256 degerini kaydet.
4. Yeni pipeline'i once `executeRemediation=false` ile calistir. `canonicalBuildId`,
   source digest ve canonical content digest degerlerinin dogrulandigini evidence
   artifact'inden kontrol et.
5. Teknik/governance onayi sonrasinda ayni immutable source icin yeni bir
   `copa-poc-YYYYMMDD-rN` output tag'iyle `executeRemediation=true` calistir.
6. `copa-remediation-poc-evidence` artifact'indeki `remediation-result.json`
   dosyasinda source/output digestleri, fixed/remaining listesi ve before/after
   severity dagilimini kontrol et.
7. Sonuc basarili olsa bile bunu onayli Harbor publish'i olarak kabul etme.
   Publish policy, imzalama ve onayli registry promotion sonraki ayri gate'dir.

## Otomatik evidence teslimi

Gercek patch ve verification basarili oldugunda pipeline, `remediation-result.json`
dosyasini yalnizca Azure artifact'i olarak birakmaz; SSI API'deki ilgili Dry Run job'ina
otomatik olarak teslim eder. Manuel UI yuklemesi PoC/debug geri donus yolu olarak kalir.

Gerekli Azure pipeline variable'lari:

- `SSI_API_BASE_URL`: Ornek `https://ssi.example.internal/api/v1`. PoC ortaminda HTTP
  zorunluysa ayrica `SSI_API_ALLOW_HTTP=true` acikca tanimlanir; production hedefi HTTPS'tir.
- `SSI_REMEDIATION_EVIDENCE_HMAC_SECRET`: En az 32 byte, secret olarak isaretlenmis,
  server runtime'indaki ayni adli degerle birebir ayni anahtar.

Run parametresi `remediationJobId`, canonical inputun kabul edildigi `RM-DRY-*` job'ini
gosterir. Pipeline exact JSON body icin SHA-256 hesaplar; timestamp, job kimligi ve agent
kimligiyle HMAC-SHA256 imzasi uretir. Secret URL'ye, komut satirina, artifact'e veya loga
yazilmaz. API `201` ile yeni execution ya da idempotent retry icin `200` donmezse pipeline
sinirli retry sonrasinda basarisiz olur. Basarili teslimatta secret icermeyen
`api-evidence-receipt.json` evidence artifact'ine eklenir.

## Gerekli worker kosullari

- Harbor'a HTTPS/TCP 443 erisimi ve kurumsal CA trust'i.
- Docker ve Docker Buildx.
- `HARBOR_ROBOT_USERNAME` ve secret variable olarak `HARBOR_ROBOT_SECRET`.
- `SSI_API_BASE_URL` ve secret variable olarak en az 32 byte
  `SSI_REMEDIATION_EVIDENCE_HMAC_SECRET`.
- Test repository icin pull/push izni. Ilk denemede yalnizca
  `ssi-images/ssi-remediation-test` ve `copa-poc-*` tag'leri kullanilacak.

## Basarisizlik davranisi

Canonical artifact, content digest, digest binding, OS-only scope, CA trust veya
verification gate gecmezse pipeline basarisiz olur ve onayli publish yapmaz.
Olasi bir PoC output tag'i olussa bile verification basarisizsa bunu guvenli image
olarak kullanmak veya promotion'a almak yasaktir; evidence artifact'i inceleme icin
kalir.

Worker callback'te imza, content digest, replay penceresi veya SSI API teslimati
basarisizsa run yesil tamamlanmaz. Ayni body'nin tekrar teslimi idempotenttir; ayni output
digest icin farkli evidence server tarafinda `409` ile fail-closed reddedilir.
