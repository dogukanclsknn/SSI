# Yayın sonrası geri çekme (Withdraw) ve talep reddi (Reject)

Policy `ssi.publish-policy/v1.4`. Kod: `src/lib/publishLifecycle.js`, API:
`POST /api/v1/publish-requests/{id}/withdraw` ve `/reject` (bkz. `docs/openapi.yaml`).

## Ne zaman kullanılır

| Durum | İşlem | Sonuç |
|---|---|---|
| Onay bekleyen bir talep artık gerekmiyor (ör. eski imaj, yanlış tag) | **Reject** | Talep `Rejected` olur; kuyruğu terk eder. Geri alınamaz. |
| Yayınlanmış imajda sorun bulundu (işlevsel hata, güvenlik, uyum) | **Withdraw** | İmaj (digest) `Withdrawn` olur; bir daha yayınlanamaz. Geri alınamaz. |

- Kim yapar: `publish:approve` yetkisi olan kişi (approver veya admin). Tek kişi yeterlidir;
  gerekçe (10–1000 karakter, tek satır) ve geri çekmede kategori zorunludur.
- Onaylanmış (`Approved`) ama henüz yayınlanmamış talep reddedilemez: worker o anda
  registry'ye yazıyor olabilir. Bu taleplerin worker handoff'u, imaj geri çekildiyse
  zaten reddedilir (`image-not-withdrawn`).

## Geri çekme neyi değiştirir

- **Digest bazında çalışır:** aynı digest'le yayınlanmış bütün talepler birlikte `Withdrawn`
  olur. İmajı üreten RM-EXEC işine `publishWithdrawal` kaydı yazılır (ilk kayıt kalıcıdır).
  Hepsi tek bir veritabanı işleminde yazılır.
- **Açık talepler kapanır:** aynı digest'in açık talepleri (`Blocked`, `ApprovalRequired`,
  `Approved`) aynı işlemde `Cancelled` olur. Talepte `cancellation` kaydı tutulur: neden
  (`image-withdrawn`), önceki durum, geri çeken kişi, gerekçe ve zaman. Böylece kuyrukta
  "onaylanmış ama hiç yayınlanamayacak" talep kalmaz. `Cancelled` geri alınamaz.
- **Engeller:**
  - Bu digest için yeni yayın talebi `Blocked` olur.
  - İptal edilen talepler onaylanamaz, worker'a verilmez.
  - Yeni aday testi sonucu ya da tüketici kararı kabul edilmez.
- **Geç gelen yayın:** handoff'u önceden almış bir worker geri çekmeden sonra yayını
  tamamlarsa, SSI bu yazmayı kaydeder ama talebi doğrudan `Withdrawn` olarak saklar
  (`publishedAfterWithdrawal: true`, audit'te uyarı). Bu, `Approved` iken iptal edilen
  talep için de geçerlidir (`cancellation` kaydı korunur). Onaydan önce iptal edilmiş bir
  talep için gelen receipt reddedilir (`409`): o talebin hiç handoff'u olmamıştır.
- **Ekranlar:**
  - Publish, Remediation ve Inventory'de kırmızı "Withdrawn — do not use" uyarısı görünür.
  - Publish kuyruğunda iptal edilen talepler "Cancelled" filtresinde, gerekçe ve önceki durumla görünür.
  - Dashboard'daki "Approved Catalog", "Approved Images" sayısı ve App Builder base listesi geri çekilen imajı göstermez.
  - Production Gate geri çekilen imajı imzalı saymaz ve "withdrawn image still in approved/" diye belirtir.
  - Raporlarda durum "Withdrawn" olarak görünür.
- **Audit kayıtları:**
  - `publish.withdrawn`: talep başına.
  - `remediation.output.withdrawn`: iş için.
  - `publish.request.cancelled`: geri çekme yüzünden kapanan her açık talep için (uyarı).
  - `publish.request.rejected`: red için.
  - Başarısız denemeler `publish.withdrawal.failed` / `publish.rejection.failed` olarak düşer.

## SSI'ın yapmadıkları (elle yapılacak adımlar)

1. **Harbor'dan kaldırmaz.** SSI'ın Harbor hesabı yalnızca okur. İmaj `approved/` altında
   çekilebilir kalır. Kaldırma geri alınamaz, bu yüzden ayrı ve onaylı bir adımdır.
   Kontrollü bir "Controlled Withdraw" pipeline'ı yazılana kadar bu işlem, Harbor yöneticisinin
   onayıyla elle yapılır.
2. **Tüketicilere haber vermez.** İmajı kullanan ekipleri (ör. html-hello-world) sen
   bilgilendirirsin: hangi tag/digest, neden, yerine ne kullanılacak.
3. **Yeni imaj üretmez.** Düzeltme için kaynak imaj yeniden remediate edilir (yeni digest),
   sonra test aşaması ve yayın akışı baştan işler.

## Deploy ve geri dönüş notları

- Migration `008_publish_lifecycle.sql`, `ssi-migrate` ile otomatik uygulanır. Var olan
  satırlar değişmez; yalnızca durum kısıtı `Rejected` ve `Withdrawn` değerlerini de kabul
  eder. `011_cancellations.sql` durum kısıtına `Cancelled` ekler (yayın ve onboarding
  talepleri); var olan satırlar değişmez. Migration'dan önce geri çekilmiş digest'lerin açık
  talepleri kendiliğinden kapanmaz; prod'daki 2026-11-11 kontrolünde böyle talep yoktu.
- `SSI_PUBLISH_POLICY_VERSION` `.env`'de eski bir değere sabitlenmişse, karar etiketleri o
  değerle yazılır ve açılışta uyarı loglanır. Değişkeni kaldırmak ya da `v1.4` yapmak yeterli.
- **Kodu geri almak (rollback) güvenli değildir** `Withdrawn` kaydı oluştuktan sonra: eski
  kod `image-not-withdrawn` kontrolünü bilmediği için geri çekilen digest için bekleyen
  talepler yeniden onaylanabilir hale gelir. Geri dönüş gerekirse önce bu talepler reddedilmelidir.
- Reddedilen ya da bloklanan bir talep, aynı iş + aynı tag kombinasyonunu kullanmaya devam eder
  (`UNIQUE (remediation_job_id, target_reference)`); yeni talep için yeni tag seçilir.
