# Onboarding (Quarantine Import) Worker Contract

**Durum:** Faz 5 · Adım 2b. SSI orkestrasyon tarafı (istek + credential-free
worker-handoff + receipt intake) ve izole import pipeline (`azure-pipelines-onboard-import.yml`)
uygulandı. Gerçek çalıştırma için operasyonel aktivasyon (Sam + Azure) gerekir.

## Amaç ve güvenlik sınırı

Dış (güvenilmeyen) bir imajı SSI'nin yönetimli akışına almak için. SSI web/API
container'ının **Docker socket'i ve registry yazma yetkisi yoktur**; bu yüzden imajı
SSI **kendisi çekip Harbor'a yazmaz**. Pull → copy → scan işini ayrı, dar yetkili bir
**izole worker** (Azure pipeline) yapar. SSI yalnızca isteği kaydeder, denetler ve
sonucu (receipt) kabul eder — tıpkı remediation ve controlled publish akışlarındaki gibi.

**Karantina duruşu:** Onboarding edilen imajlar Harbor'da ayrı bir **karantina prefix'ine**
(varsayılan `onboarded/`) iner; `approved/` ile yan yana **durmaz**. İmaj ancak normal
scan + remediation + publish akışından geçince `approved/`'a terfi eder.

## Durum akışı

```
Requested → Importing → Imported
                     └→ Failed
```

`Requested`: SSI isteği kaydetti. `Importing`: worker handoff'u çekti (işi aldı).
`Imported`: worker karantinaya kopyaladı ve receipt döndü. `Failed`: worker hata bildirdi.

## SSI API yüzeyi

| Metot | Yol | Açıklama |
|---|---|---|
| POST | `/api/v1/onboarding` | Onboarding isteği oluşturur. Body: `{ "sourceReference": "registry/ns/image:tag" }`. Kaynak ref doğrulanır, karantina hedefi türetilir. `201` + istek. |
| GET | `/api/v1/onboarding` | İstek kuyruğu (durum + kaynak takibi). |
| GET | `/api/v1/onboarding/{id}/worker-handoff` | Credential-free handoff manifesti. `X-SSI-Onboard-Handoff-Token` ister; ilk çekişte istek `Importing`'e geçer. |
| POST | `/api/v1/onboarding/{id}/import-receipt` | Worker sonucu bildirir. `X-SSI-Onboard-Receipt-Token` ister; isteği `Imported`/`Failed` yapar. |

Handoff ve receipt kimlik bilgileri **bilinçli olarak ayrıdır** (publish akışıyla aynı desen).

## Worker Handoff (credential-free)

`GET .../worker-handoff` çıktısı. Harbor robot secret, Docker config veya herhangi bir
kimlik bilgisi **içermez**:

```json
{
  "contractVersion": "ssi.onboard-handoff/v1",
  "requestId": "ONB-0001",
  "source": { "reference": "docker.io/library/nginx:1.27", "registry": "docker.io", "pinnedByDigest": false },
  "target": {
    "registry": "registry.example.com",
    "project": "ssi-images",
    "repository": "onboarded/nginx",
    "tag": "1.27",
    "tagReference": "registry.example.com/ssi-images/onboarded/nginx:1.27"
  },
  "scanner": { "tool": "trivy", "scope": "full-image" },
  "constraints": {
    "credentialMaterialIncluded": false,
    "overwriteExistingTag": false,
    "quarantine": true,
    "rescanAfterImport": true
  }
}
```

## Import Receipt

Worker'ın `POST .../import-receipt` gövdesi:

```json
{
  "contractVersion": "ssi.onboard-receipt/v1",
  "requestId": "ONB-0001",
  "status": "imported",
  "importedDigest": "sha256:<karantinaya inen immutable digest>",
  "targetReference": "registry.example.com/ssi-images/onboarded/nginx:1.27",
  "scanSummary": { "critical": 1, "high": 4, "medium": 9, "low": 3, "unknown": 0 },
  "workerId": "LinuxAgent1@build-agent-01",
  "importedAt": "2026-09-03T09:00:00.000Z"
}
```

Hata halinde `{ "status": "failed", "error": "<neden>" }` gönderilir; istek `Failed` olur.

## İzole import worker'ın uyguladığı akış

`azure-pipelines-onboard-import.yml` (manuel, fail-closed, `pool: LinuxPool`):

1. `worker-handoff`'u handoff token ile çeker; sözleşme, hedef ve fail-closed
   kısıtları Node ile doğrular; kimlik-benzeri içerik reddedilir.
2. `executeImport=true` değilse **prepare-only** durur (hiçbir pull/yazma yok).
3. Harbor CA ile TLS doğrular; dar yetkili onboarding robotu ile hedef registry'e login olur.
4. Dış kaynağı **immutable digest'e pinler** (`regctl image digest`); gerekiyorsa opsiyonel
   kaynak-registry kimliğiyle (özel kaynaklar için) login olur, public kaynaklar anonim.
5. Hedef karantina tag'i farklı bir manifest ile varsa **asla üzerine yazmaz** (fail-closed);
   aynıysa yazmayı atlar (retry-safe). Yoksa `regctl image copy` ile karantinaya kopyalar.
6. Hedef digest'in kaynağı koruduğunu doğrular; best-effort Trivy taraması (pinli imaj) ile
   severity özeti üretir (Harbor auto-scan zaten devrede, Trivy aksarsa özet atlanır).
7. İmzalı olmayan ama receipt-token ile korunan `import-receipt`'i SSI'ya gönderir; hata
   halinde `failed` receipt gönderip `Failed` durumunu yansıtır.

TLS bypass (`--insecure`, `curl -k`) veya HTTP fallback yoktur; secret komut satırına,
URL'ye, loga veya artifact'e yazılmaz. Evidence `onboarding-import-evidence` artifact'i
olarak yayınlanır (handoff, receipt, tanı dosyaları — secret'sız).

## Operasyonel aktivasyon (Sam + Azure — 2b-1'i bloklamaz)

- **Harbor:** hedef projede `onboarded/` prefix'ine **yazma yetkili** dar kapsamlı robot hesabı.
  Bu robot yalnızca karantina prefix'ine yazabilmeli; `approved/`'a **yazamamalı**.
- **SSI API env:** `ONBOARD_TARGET_REGISTRY`, `ONBOARD_TARGET_PROJECT`,
  `ONBOARD_TARGET_REPOSITORY_PREFIX` (varsayılan `onboarded`), `ONBOARD_HANDOFF_TOKEN`,
  `ONBOARD_RECEIPT_TOKEN` (ikisi de ≥ rastgele üretilmiş, secret olarak yönetilir).
- **Azure DevOps:** `azure-pipelines-onboard-import.yml` pipeline olarak kaydedilir; secret
  variable'lar: `ONBOARD_HANDOFF_TOKEN`, `ONBOARD_RECEIPT_TOKEN`, `ONBOARD_ROBOT_USERNAME`,
  `ONBOARD_ROBOT_SECRET` ve opsiyonel `SOURCE_ROBOT_USERNAME`/`SOURCE_ROBOT_SECRET`
  (özel kaynak registry'leri için).
- **Kalıcılık:** İstekler ilk sürümde SSI belleğinde tutulur (uygulamanın PoC modeliyle
  tutarlı); PostgreSQL'e taşıma remediation store deseniyle fast-follow.

## Resmi teknik referanslar
- [regclient/regctl](https://github.com/regclient/regclient)
- [Trivy image scanning](https://trivy.dev/docs/latest/scanner/vulnerability/)
- [Harbor robot accounts](https://goharbor.io/docs/latest/administration/robot-accounts/)
