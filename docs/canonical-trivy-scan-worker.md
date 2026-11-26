# Canonical Trivy OS-only Scan Worker

**Durum:** Faz 4 PoC scan worker'i gercek Harbor artifact'iyle basariyla dogrulandi.
Pipeline manuel calisir; image patch, Harbor push, SSI deploy veya remediation dispatch
yapmaz.

## Neden Ayri Bir Scan Worker?

Harbor'in artifact vulnerability endpointi CVE, paket, kurulu surum ve fix surumunu
doner; ancak unified response her bulgunun `os-pkgs` veya `lang-pkgs` sinifini guvenilir
sekilde tasimaz. Faz 1 remediation kapsami sadece OS package oldugu icin bu sinif bilgisi
olmayan bir bulgunun Copa'ya gonderilmesi guvenli degildir.

`azure-pipelines-canonical-trivy-scan.yml`, source artifacti immutable digest ile okur ve
Trivy'nin ham JSON formatini `--pkg-types os --ignore-unfixed` ile olusturur. Bu format
`Results[].Class = os-pkgs` bilgisini korur; pipeline, karisik veya eksik raporu artifact
olarak yayinlamadan once reddeder.

## Guvenlik Sinirlari

- Pipeline `trigger: none` ile sadece manuel calisir.
- Tag kabul edilmez; tam `sha256:<64-hex>` digest zorunludur.
- Scanner container'ina Docker socket mount edilmez.
- Source image remote registry'den salt-okunur taranir; Copa, BuildKit, image patch veya
  Harbor push komutu yoktur.
- Harbor robot credential'i Azure DevOps secret variable olarak runtime'da kullanilir;
  gecici Docker-compatible config dosyasina yazilir, loglanmaz, artifact olarak yayinlanmaz
  ve job sonunda silinir. Trivy'nin `registry login` komutu kurum ici CA zincirini kendi
  login dogrulama yolunda kullanamadigi icin bu worker o komutu calistirmaz.
- Trivy container'i resmi `v0.70.0` manifest digest'ine pinlenmistir. Tag yerine digest
  kullanimi, calisan scanner binary'sinin tekrar edilebilir olmasini saglar.
- Kurum ici Harbor CA'si runner trust store'a henuz alinmadigi icin `--insecure`, Trivy'nin
  Harbor image read adiminda kullanilir. Kalici kurumsal hedef, CA bundle'ini runner'a
  dagitip bu bayragi kaldirmaktir.

## Azure DevOps Kurulumu

1. **Pipelines > New pipeline** ile ayni SSI reposunu secin.
2. Mevcut YAML'i secip `azure-pipelines-canonical-trivy-scan.yml` dosyasini kullanin.
3. Agent pool olarak `LinuxPool` kullanin.
4. Pipeline variables alanina mevcut Harbor test pipeline'indaki secret variable'lari ekleyin:
   - `HARBOR_ROBOT_USERNAME` (secret)
   - `HARBOR_ROBOT_SECRET` (secret)
5. Pipeline'i manuel calistirirken source repository ve Harbor artifact ekranindan kopyalanan
   tam source digest bilgisini girin.

Ornek input:

```text
sourceRepository = ssi-remediation-test
sourceDigest     = sha256:<Harbor artifact ekranindan kopyalanan tam digest>
```

## Beklenen Cikti ve Kontrol

Basarili run sonunda Azure DevOps build artifact alaninda
`canonical-trivy-os-report/canonical-trivy.json` bulunur. JSON asagidakileri tasimalidir:

- `SchemaVersion: 2`
- source artifactin immutable digest'i
- yalnizca `Results[].Class: "os-pkgs"`
- paket adi, kurulu surum, fixed version, severity ve CVSS alanlari

Bu artifact, ilerleyen asamada izole remediation worker'in Copa input'u olacak; web/API
container'i bu raporu kendisi uretmeyecek ve Harbor yazma credential'i tasimayacak.

## Sonraki Adim

Canonical report'un controlled intake akisi uygulandi: SSI, raporu sadece source digest'i
eslesen ve `os-pkgs` scope'unu kanitlayan bir JSON olarak kabul edip Dry Run planini yeniden
hesaplar. Raw JSON web job kaydinda tutulmaz; bu PoC'de job durumu server bellegindedir.

Siradaki teknik sinir, canonical input'u okuyacak ayri ve en az yetkili Copa worker'dir.
Actual execution icin ayrica onayli worker identity, output repository policy, patch edilen
imajin re-scan ile before/after dogrulamasi ve publish gate gerekir. Bu worker pipeline'i
image patch veya Harbor push yapana kadar SSI web/API container'ina Docker socket ya da Harbor
yazma secret'i verilmeyecektir.

## Resmi Referanslar

- [Trivy image scanning](https://trivy.dev/docs/latest/guide/scanner/vulnerability/)
- [Trivy private registry authentication](https://trivy.dev/docs/latest/advanced/private-registries/self/)
- [Trivy registry TLS troubleshooting](https://trivy.dev/latest/docs/references/troubleshooting/)
- [Copacetic quick start](https://project-copacetic.github.io/copacetic/website/v0.10.x/quick-start)
