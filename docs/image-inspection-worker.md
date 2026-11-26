# Image Inspection Worker

## Amac

Scan Results ekranindaki "Compare with another image" paneli iki taranmis imaji zafiyet
bazinda karsilastirir. Paket, katman ve yapilandirma farki ise Harbor taramasinda yoktur:
Harbor yalnizca zafiyetli paketleri listeler. **SSI - Image Inspection** pipeline'i bir imajin
icine bakar ve bu bilgileri imzali olarak SSI'a bildirir. Bir imaj **bir kez** incelenir;
sonra baska herhangi bir incelenmis imajla karsilastirilabilir.

Karsilastirma ekraninda gelen sekmeler:

| Sekme | Icerik |
| --- | --- |
| OS packages | Degisen / eklenen / silinen paketler, ana surum atlamalari |
| Layers and size | Ortak taban katmanlari, eklenen / silinen katmanlar, boyut farki |
| Image configuration | Cmd, Entrypoint, portlar, ortam degiskeni ADLARI... alan alan |

Iki imajin isletim sistemi farkliysa (or. alpine ile debian) ekran bunu acikca soyler.

Iki imaj da incelenmisse zafiyet sekmesi de daha dogru olur: sadece karsilastirilan imajda gorulen
bir bulgu, paketi iki imajin OS paket listesinde de **ayni surumdeyse** kirmizi uyari vermez. Bunun
yerine "yeni tarama verisinden geliyor, base imaji Harbor'da yeniden tarayin" bilgi notu cikar.
OS paket listesinde olmayan paketler (or. imaja gomulu bir program) farkli olabilecegi icin
her zaman uyari verir.

## Ne toplar (`ssi.image-inspection/v1`)

| Alan | Kaynak |
| --- | --- |
| `packages` | Trivy paket listesi (`--scanners license --pkg-types os`, zafiyet veritabani indirilmez) |
| `os` | Trivy `Metadata.OS` (or. `alpine 3.22.2`) |
| `facts.diffIds`, `facts.sizeBytes` | `docker image inspect` (`RootFS.Layers`, `Size`) |
| `facts.config` | `docker image inspect` calisma alanlari; `Env` **yalnizca degisken adlari** |

## Guvenlik

- Imajdan **hicbir konteyner baslatilmaz**. Imaj yalnizca **pull** yetkili robotla digest ile
  cekilir, incelenir ve silinir. Tek `docker run`, Trivy paket listeleyicisidir.
- Parametre kati desenle dogrulanir: yalnizca `HARBOR_HOST/HARBOR_PROJECT` altindaki
  `repository@sha256:<64 hex>`; tag kabul edilmez. Hatali degerde mesaj hangi degerin
  neden reddedildigini yazar ve nedeni `failure.txt` olarak artifact'e koyar.
- Ortam degiskeni degerleri ajandan cikmaz. SSI, deger iceren (`AD=deger`) her kaydi 422 ile
  reddeder.
- Sonuc HMAC-SHA256 ile imajin digest'ine bagli olarak imzalanir. Ilk satir
  `ssi-image-inspection-evidence-v1` oldugu icin baska bir worker'in imzasi burada gecmez.
- SSI ayrica kontrol eder:
  - imaj SSI'in Harbor'inda ve okudugu projede olmali,
  - Harbor o imaji taramis olmali (taranmamis imaj ve Cosign artifact'i 409),
  - digest, istegin digest'i olmali.
- Ayni sonuc tekrar gelirse idempotent'tir. Eski bir sonuc yenisinin yerine gecemez (409).
- Kabul edilen ve reddedilen her sonuc audit'e yazilir. Audit'te yalnizca sayilar ve
  digest'ler bulunur.
- Inceleme kaydi, yalnizca o imajin taramasini gorebilen kullaniciya gosterilir (ekip
  ayrimi `GET /scans` ile ayni).
- SSI'a ulasilamazsa run "Succeeded with issues" olur; pipeline'i ayni imaj icin yeniden
  calistirmak yeterlidir.

## Calistirma

1. SSI'da Scan Results → bir imaj sec → altta **Compare with another image** → ikinci imaji sec.
2. Panelde "Compare packages, layers and configuration too" kutusu, incelenmemis imajlarin
   `imageReference` degerini kopya butonuyla gosterir.
3. Azure DevOps'ta **SSI - Image Inspection** pipeline'ini bu degerle calistir
   (her incelenmemis imaj icin bir kez).
4. Run bitince paneli yenile: OS packages, Layers and size ve Image configuration sekmeleri dolar.

## Gerekli Azure pipeline degiskenleri

- `HARBOR_ROBOT_USERNAME`, `HARBOR_ROBOT_SECRET` (secret): **yalnizca pull** yetkili robot
  (aday test ile ayni robot kullanilabilir).
- `SSI_API_BASE_URL`, `SSI_API_ALLOW_HTTP` (yalnizca dahili PoC HTTP icin `true`).
- `SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET` (secret, en az 32 byte): SSI sunucusundaki ayni
  adli degerle birebir ayni; diger worker sirlarindan ayri.

## Sunucu ayarlari

- `SSI_IMAGE_INSPECTION_EVIDENCE_HMAC_SECRET`: tanimli degilse inceleme sonuclari 503 ile
  reddedilir ve karsilastirma yalnizca zafiyet bazinda kalir.
- Kabul edilen registry adlari: `ONBOARD_TARGET_REGISTRY`, `PUBLISH_TARGET_REGISTRY` ve
  `HARBOR_URL`'nin host'u. Projeler: `HARBOR_PROJECTS`.
- Veriler `image_inspections` tablosunda tutulur (migration `010`). Deploy sirasinda
  `ssi-migrate` otomatik uygular.
