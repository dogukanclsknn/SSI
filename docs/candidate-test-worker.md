# Pre-release Candidate Test Worker

## Amac

Faz 5 sunumundaki geri bildirim: "Imaji once bir yerde kullanip sonra herkese acmak daha
saglikli." 2026-11-02'de bu gercekten yasandi: Copa yamali nginx:alpine imaji tum CVE
kontrollerinden gecti, ama tuketici projede (html-hello-world) baslangic komutu olmadigi
icin hic acilmadi. Zafiyet taramasi bunu goremez.

Bu yuzden publish'ten once iki adim zorunludur (publish policy v1.3):

1. **Otomatik aday testi** (`azure-pipelines-candidate-test.yml`): kaynak imaj ile yamali
   aday imaj ajanda yan yana calistirilir.
2. **Tuketici onayi**: imaji kullanacak ekip onu kendi test projesinde dener ve SSI'da
   "Tested — OK" ya da "Issue found" isaretler.

## Otomatik test neyi kontrol eder

| Kontrol | Gecme kosulu |
| --- | --- |
| `image-config` | Calisma yapilandirmasi (Entrypoint, Cmd, Env, ExposedPorts, StopSignal, Healthcheck, User, WorkingDir, Volumes, Labels...) kaynakla birebir ayni |
| `startup` | Varsayilan komutla ayni davranis: ikisi de calisiyor, ya da ikisi de ayni cikis koduyla bitiyor; aday OOM ile oldurulmemis |
| `healthcheck` | HEALTHCHECK tanimliysa ayni sonuc (healthy/unhealthy); tanimli degilse not-applicable |
| `package-inventory` | OS paket degisiklik raporu; **paket silinmisse basarisiz** |

Paket raporu Trivy'nin paket listesinden uretilir (`--scanners license --pkg-types os`,
zafiyet veritabani indirilmez). SSI her degisikligi remediation planiyla karsilastirir ve
plan disindaki degisiklikleri (yeni bagimlilik, ana surum atlamasi) "Unplanned" olarak
isaretler. "Fixlerden onemli bir sey degisti mi?" sorusunun cevabi bu rapordur.

## Imaj bilgileri (imageFacts)

Sonuc ayrica iki imajin karsilastirma bilgisini tasir ("What changed" paneli, katmanlar ve
yapilandirma sekmeleri). Yeni bir pipeline adimi yoktur; bilgiler zaten alinan
`docker image inspect` ciktisindan uretilir.

| Alan | Kaynak | Not |
| --- | --- | --- |
| `diffIds` | `RootFS.Layers` | Sikistirilmamis katman icerik digest'leri; iki imaj ayni temelde karsilastirilir |
| `sizeBytes` | `Size` | Docker'in bildirdigi imaj boyutu; yoksa `null` |
| `config` | `Config` (calisma alanlari) | `Env` **yalnizca degisken adlari**; degerler ajandan hic cikmaz |

- Bu alanlar bilgi amaclidir: eksik katman listesi testi basarisiz yapmaz.
- SSI `Env` icinde `=` iceren (deger tasiyan) bir kaydi hangi kanaldan gelirse gelsin 422 ile
  reddeder; manuel yukleme ile de deger saklanamaz.
- SSI raporlanan yapilandirmayi `image-config` karariyla karsilastirir: yapilandirmalar
  farkliysa (Env adlari dahil) kontrol `pass` olamaz.
- Alan istege baglidir (`ssi.candidate-test/v1` sozlesmesi degismedi). Eski worker sonuclari
  kabul edilmeye devam eder; o job'larda katman sekmesi "unavailable" gorunur. Bilgiyi
  gormek icin pipeline'i ayni job icin yeniden calistirmak yeterlidir.

## Izolasyon ve guvenlik

- Test konteynerleri **agsiz** (`--network none`), CPU/bellek/process sinirli,
  `no-new-privileges` ile calisir. Privileged, port yayini, `docker exec` ve Docker
  socket mount'u yoktur.
- Parametreler kati desenlerle dogrulanir: yalnizca `HARBOR_HOST/HARBOR_PROJECT` altindaki
  `repository@sha256:<64 hex>` referanslari; tag kabul edilmez.
- Cekilen imajin `RepoDigests` degeri istenen digest'e baglanir.
- Harbor kimlik bilgisi yalnizca bu run'in gecici klasorundeki Docker config'ine yazilir,
  `--password-stdin` ile verilir, run sonunda logout yapilir ve klasor silinir.
- Sonuc HMAC-SHA256 ile imzalanir; ilk satir `ssi-candidate-test-evidence-v1` oldugu icin
  baska bir worker'in imzasi burada gecmez (domain separation).
- SSI worker'in kararina guvenmez: `passed` ve paket kontrolunu raporlanan veriden yeniden
  hesaplar, aday digest'i job'in verified output digest'ine, kaynak digest'i job'in source
  digest'ine baglar.
- Ayni sonuc tekrar gelirse idempotent'tir; **eski bir sonuc yenisinin yerine gecemez**
  (eski bir "passed" sonradan gelen bir "failed"i ortemez).
- Basarisiz test de SSI'a teslim edilir: SSI adayin basarisiz oldugunu bilmelidir.
- SSI'a ulasilamazsa run "Succeeded with issues" olur; sessizce yesil bitmez.

## Calistirma

1. RM-EXEC sayfasinda **Pre-release testing** panelindeki uc parametreyi kopyala:
   `remediationJobId`, `sourceReference`, `candidateReference`.
2. Azure DevOps'ta **SSI - Candidate Test** pipeline'ini bu degerlerle calistir.
3. Sonuc otomatik olarak SSI'a gelir. Gelmezse `candidate-test-evidence` artifact'indeki
   `candidate-test-result.json` dosyasini panelden **Upload test result** ile yukle.
4. Imaji kullanacak ekip adayi kendi test projesinde digest ile ceker, dener ve panelden
   **Mark tested — OK** ya da **Report issue** ile kaydeder.
5. Ardindan Publish ekraninda talep olusturulur. Talebi acan kisi adayi onaylayan kisi
   olamaz (dort goz kurali). "Issue found" kaydi her durumda publish'i durdurur ve onay
   aninda yeniden kontrol edilir.

## Gerekli Azure pipeline degiskenleri

- `HARBOR_ROBOT_USERNAME`, `HARBOR_ROBOT_SECRET` (secret): **yalnizca pull** yetkili robot.
- `SSI_API_BASE_URL`, `SSI_API_ALLOW_HTTP` (yalnizca dahili PoC HTTP icin `true`).
- `SSI_CANDIDATE_TEST_EVIDENCE_HMAC_SECRET` (secret, en az 32 byte): SSI sunucusundaki ayni
  adli degerle birebir ayni; diger worker sirlarindan ayri.

## Sunucu ayarlari

- `SSI_CANDIDATE_TEST_EVIDENCE_HMAC_SECRET`: worker teslimi icin (tanimli degilse yalnizca
  manuel yukleme calisir).
- `SSI_PUBLISH_REQUIRE_CONSUMER_ACCEPTANCE` (varsayilan `true`): `false` yapilirsa tuketici
  onayi zorunlu olmaz, ama "Issue found" yine publish'i durdurur. Otomatik test her zaman
  zorunludur.
