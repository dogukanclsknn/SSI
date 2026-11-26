# SSI — Harbor Scan Results Entegrasyonu

> Faz 4 scanner entegrasyon dilimi. Amaç: Harbor'ın push sonrası ürettiği Trivy
> vulnerability sonucunu SSI'nin normalize `ScanReport` / `Finding` modeline
> güvenli biçimde bağlamak.

## Resmi Harbor akışı

Harbor'da push sonrası otomatik scan etkin olduğunda artifact üzerindeki
`scan_overview` alanı taramanın durumunu gösterir. Scan başarılıysa ayrıntılı
vulnerability raporu Harbor v2 API'den okunur:

```text
GET /api/v2.0/projects/{project}/repositories/{repository}/artifacts/{digest}/additions/vulnerabilities
X-Accept-Vulnerabilities: application/vnd.security.vulnerability.report; version=1.1
```

Endpoint, Harbor'ın resmi vulnerability scanning dokümantasyonunda tanımlıdır.
Artifact digest'i referans olarak kullanılır; bu, mutable tag yerine aynı imajı
kararlı biçimde hedeflemeyi sağlar.

**Teknik referans:** [Harbor Vulnerability Scanning dokümantasyonu](https://goharbor.io/docs/main/administration/vulnerability-scanning/)

## SSI tarafındaki davranış

`GET /api/v1/scans` artık Harbor environment bilgileri tanımlıysa aşağıdaki
akışı uygular:

1. Harbor project içindeki repository ve artifact'leri listeler.
2. Her artifact'in `scan_overview` durumunu okur.
3. `Success` durumundaki artifact için vulnerability addition endpointini çağırır.
4. Harbor scanner reportunu UI'nin kullandığı normalize `ScanReport` modeline dönüştürür.
5. Sadece ilk faz kapsamındaki OS package bulgularını remediation için uygun
   `Finding` alanlarıyla sunar: CVE, package, installed/fixed version, severity,
   CVSS, link ve fix availability.

## Veri kaynağı durumları

| `X-SSI-Data-Source` | Anlamı | UI davranışı |
|---|---|---|
| `harbor` | Tüm okunabilir Harbor scan sonuçları alındı | `Harbor API` rozeti ve gerçek findings |
| `harbor-partial` | Bazı artifact scanleri tamamlanmadı veya okunamadı | Mevcut gerçek sonuçlar + uyarı rozeti |
| `harbor-empty` | Project'te artifact yok | Fixture gösterilmez; kontrollü boş durum |
| `harbor-scan-pending` | Artifact var, Trivy sonucu hazır değil | Fixture gösterilmez; scan bekleniyor ekranı |
| `harbor-scan-error` | Harbor scan raporu okunamadı | Fixture gösterilmez; hata ayrıntısı rozette |
| `trivy-fixture` | Harbor env tanımlı değil | Mevcut Trivy fixture davranışı |

Bu ayrım kritik: gerçek Harbor bağlantısı aktifken UI'ın fixture verisini gerçek
veri gibi göstermesini önler.

## Canlı doğrulama sırası

1. Network talebi sonrası Azure DevOps build agent'ından Harbor'a test image push edilir.
2. Harbor `auto_scan: true` politikası Trivy taramasını otomatik başlatır.
3. Artifact `scan_overview.scan_status` değeri `Success` olduğunda `/api/v1/scans`
   gerçek reportu döndürür.
4. Inventory `Harbor API`, Scan Results `Harbor API` rozetleri ve CVE bulguları
   birlikte doğrulanır.
5. Aynı normalize sonuç, sonraki aşamada Copacetic remediation job input'u olur.

Yerel entegrasyon testi; artifact listeleme, `scan_overview` ile başarı durumunun
tespiti, resmi MIME header'ının gönderilmesi ve örnek CVE'nin normalize edilmesini
başarıyla doğrular. Canlı Harbor doğrulaması ise gerçek test image ve auto-scan
sonucu oluştuğunda yapılacaktır.

## Güvenlik sınırları

- Robot account secret sadece deployment `.env`/secret ortamında kalır; repo ve
  frontend bundle içine girmez.
- Server tarafı Harbor'a Basic auth ile bağlanır; credential istemciye dönmez.
- `HARBOR_TLS_VERIFY=false` yalnızca kurum içi CA'nın runtime trust store'da
  olmadığı PoC koşulunda kullanılır. Kalıcı ortamda kurum CA'sı ile doğrulama
  açık tutulmalıdır.
