# Çok kiracılı yapı (multi-tenancy) — Faz 1 + Faz 2

**Kod:**
- `src/lib/tenancy.js`: kurallar, kapsam, takım bağlamı.
- `src/lib/tenantInventory.js`: Harbor imajlarının takıma eşlenmesi.
- `src/server/tenantStore.js`: takımlar ve üyelikler.
- `src/server/remediationStore.js`: kiracı kapsamı.
- `src/TeamManagement.jsx`: konsoldaki takım ekranları.
- Migration `009_tenancy.sql`.

**API:** `/api/v1/tenants…` ve `X-SSI-Tenant` header'ı (bkz. `docs/openapi.yaml`, etiket *Teams*).

## Kavramlar

| Kavram | Anlamı |
|---|---|
| Takım (tenant) | SSI'ı kullanan bir ekip. Kimliği küçük harf, rakam ve `-` (2–40 karakter), ör. `payments`. |
| `default` takımı | Migration 009'dan önceki bütün kayıtlar burada. Bugünkü Harbor klasörlerini kullanır, devre dışı bırakılamaz. |
| Takım rolü | `viewer`, `operator`, `approver`. Bayrak açıkken kullanıcının o takımdaki rolü, global rolünün yerine geçer. |
| Platform yöneticisi | `users.role = admin` ve lokal admin. Bütün takımlarda çalışır, üyelik gerekmez. |
| Takıma ait kayıtlar | Remediation işleri, yayın talepleri, onboarding talepleri, risk kabulleri ve bunların audit kayıtları. |
| Takımın Harbor klasörleri | Onboard klasörü (karantina) ve approved klasörü (yayın sınırı). |

## Bayrak

| Değişken | Varsayılan | Etki |
|---|---|---|
| `SSI_MULTI_TENANCY` | `false` | **`false`:** davranış eskisiyle aynı. Her şey `default` takımında, global rol geçerli, `X-SSI-Tenant` yok sayılır, konsolda takım kontrolü görünmez. **`true`:** aşağıdaki kurallar geçerli. |

- `SSI_MULTI_TENANCY=true`, `SSI_RBAC_ENFORCED=true` olmadan açılmaz.
- Faz 1'deki `SSI_MULTI_TENANCY_PREVIEW` artık kullanılmıyor. Harbor envanteri takıma göre ayrıldığı için bu kilide gerek kalmadı; tanımlı kalırsa yok sayılır.

## Harbor: imaj hangi takımın

Tasarımdaki Seçenek A uygulanır: ortak projede her takımın kendi klasörü olur.

| Takım | Onboard klasörü | Approved klasörü |
|---|---|---|
| `default` | `ssi-images/onboarded/` | `ssi-images/approved/` |
| Diğer takım (ör. `payments`) | `ssi-images/onboarded/payments/` | `ssi-images/approved/payments/` |

- **Sahiplik kuralı:** Klasörler iç içedir; imaj, **en uzun eşleşen** klasörün takımına aittir. Örneğin `onboarded/payments/redis` payments'ındır, default'un değil. Hiçbir takımın klasörüne uymayan imaj `default`'ta kalır.
- **Klasörü değiştirmek:** Takım kaydındaki Harbor hedefiyle değiştirilir (`registry`, `project`, `onboardPrefix`, `approvedPrefix`). Boş alan platform değerini alır. Takımın kendi projesi varsa (Seçenek B) klasör adları düz `onboarded/` ve `approved/` olur. Seçenek B'de ekip projesinin `HARBOR_PROJECTS`'e de eklenmesi gerekir, yoksa envanter o projeyi okumaz.
- **Çakışma:** İki takım aynı klasörü kullanamaz; takım oluşturma ve güncelleme 409 ile reddedilir.
- **Pipeline değişikliği gerekmiyor:** Worker'lar hedefi zaten iş emrinden (handoff) okuyor. Bayrak açıkken iş emirlerine `tenantId` de eklenir.

## Bayrak açıkken kurallar

- **Okuma ve yazma takım içinde kalır.**
  - Store'un her çağrısı bir kapsam ister; kapsamsız çağrı hata verir (fail-closed).
  - Başka takımın kaydı "bulunamadı" (404) döner. Bir kayıt başka takıma taşınamaz.
- **Envanter ve scan'ler:**
  - Takım kendi onboarded imajlarını ve scan'lerini görür. CVE Queue ve Dashboard bu filtreden geçer.
  - Yayınlanmış (approved) imajlar **ortak katalogdur**: herkes görür, "Published by" alanı yayınlayan takımı gösterir.
  - Geri çekilen bir imaj ("Withdrawn — do not use") her takımda geri çekilmiş görünür.
- **Remediation:** Bir takım yalnızca kendi imajının scan'inden dry run başlatabilir.
- **Onboarding:** İmaj, takımın onboard klasörüne iner.
- **Yayın sınırı:** Policy'deki "Approved registry boundary" kontrolü takımın approved klasörüyle karşılaştırır. Başka bir takımın klasörüne yayın talebi `Blocked` olur.
- **Takım seçimi:**
  - Tek aktif takımı olan kullanıcı header göndermeden çalışır.
  - Birden fazla takımı olan kullanıcı `X-SSI-Tenant` gönderir. Göndermezse API 400 döner; konsol ilk takımı kendisi seçer.
  - Hiç aktif takımı olmayan kullanıcı 403 alır.
  - Bilinmeyen takım ile üyesi olunmayan takım aynı 403 mesajını verir; takım adları sızmaz.
  - Rapor dokümanı düz bir link olarak açıldığı için takımı `?tenant=` ile de alır.
- **Yeni kayıt:**
  - Dry run, onboarding ve risk kabulü seçili takıma yazılır. Platform yöneticisi de bir takım seçmek zorundadır.
  - Yayın talebi işin takımına, doğrulanmış iş (RM-EXEC) dry run'ın takımına yazılır.
- **Risk kabulleri takıma özeldir:** Bir takımın kabulü başka takımın imajına uygulanmaz ve onu engellemez.
- **Worker callback'leri** (token/HMAC ile gelen kanıt, receipt, handoff) adını verdikleri kaydın takımında çalışır.
- **Audit:**
  - Her kayıt kendi takımıyla etiketlenir; takım üyeleri yalnızca kendi takımınınkileri görür.
  - Platform olayları ve 009 öncesi audit satırları (`tenantId: null`) yalnızca platform yöneticisine görünür.
  - Reddedilen takım seçimi `tenancy.access.denied` olarak kaydedilir.

## Konsol (yalnızca bayrak açıkken)

- **Üst barda takım seçici:** Birden fazla takımı olan kullanıcıya ve platform yöneticisine görünür; yöneticide ayrıca "All teams" seçeneği vardır. Takım değişince konsol yeniden yüklenir. Seçim tarayıcı sekmesi başına tutulur, yani iki sekmede iki ayrı takımla çalışılabilir.
- **Teams ekranı (platform yöneticisi):**
  - Takım oluşturma ve yeniden adlandırma.
  - Harbor hedefi; kullanılan klasörler gösterilir.
  - Üye ekleme, rol değiştirme, çıkarma.
  - Takımı devre dışı bırakma (onay için takım id'si yazılır).
- **Users ekranı:** Seçili kullanıcının takımları ve takım rolleri burada görülür ve yönetilir.
- **Inventory:** Görselde takım ya da "Published by" alanı.
- **Publish formu:** Önerilen hedef, takımın approved klasörüyle başlar.

## Takım yönetimi API'si (yalnızca platform yöneticisi)

| İşlem | Çağrı | Audit kaydı |
|---|---|---|
| Takımları listele (kullanılan klasörlerle) | `GET /tenants` | — |
| Takım oluştur | `POST /tenants` `{ id, displayName, harbor? }` | `tenant.created` |
| Takımı değiştir | `PATCH /tenants/{id}` `{ displayName?, status?, harbor?, rowVersion? }` | `tenant.updated` / `tenant.disabled` / `tenant.enabled` |
| Üyeleri listele | `GET /tenants/{id}/members` | — |
| Üye ekle veya rolünü değiştir | `PUT /tenants/{id}/members/{username}` `{ role }` | `tenant.membership.added` / `.updated` |
| Üyeyi çıkar | `DELETE /tenants/{id}/members/{username}` | `tenant.membership.removed` |

- Üye olacak kullanıcı önce **Users**'ta bulunmalıdır. Platform yöneticisine üyelik verilmez (400).
- Devre dışı takımın üyeleri o takıma erişemez; takımın kayıtları silinmez.
- `rowVersion` gönderilirse, başkası takımı arada değiştirdiyse güncelleme 409 ile reddedilir.
- **Bir klasörü değiştirmek**, takımın hangi mevcut imajları gördüğünü ve nereye onboard/yayın yaptığını değiştirir. Konsol bu konuda uyarır.

## Deploy, açılış ve geri dönüş

1. **Migration 009** `ssi-migrate` ile otomatik uygulanır (Faz 1). Faz 2'de yeni migration yok. Deploy'dan önce DB yedeği alınır.
2. **Bayrak kapalıyken davranış değişmez.** Bu, testlerle ve gerçek PostgreSQL üzerinde uçtan uca doğrulandı. Konsolda yeni bir şey görünmez.
3. **Geri dönüş güvenlidir.** Sütunlardaki `DEFAULT 'default'` sayesinde eski kod `tenant_id` vermeden yazabilir.
4. **Bayrağı açmadan önce:**
   - Takımları oluştur ve klasörlerini kontrol et (Teams ekranı yalnızca bayrak açıkken görünür; önceden hazırlık API ile yapılır).
   - Aktif kullanıcıları en az bir takıma ekle. Migration'dan sonra eklenen kullanıcıların üyeliği yoktur; SSI açılışta bunları `no team membership and cannot act` uyarısıyla listeler.
   - Harbor'da takım klasörlerine yazma yetkisinin olduğunu doğrula. Seçenek A'da ortak robot hesabı yeterlidir.
   - `SSI_MULTI_TENANCY=true` ver. Açılış logunda `SSI_MULTI_TENANCY=true: N team(s)` satırını gör.
5. **Bayrağı kapatmak** her zaman mümkündür: herkes yeniden tek takımdaymış gibi görür, veri silinmez.

## Testler

- **Birim testleri:** `npm test`. Kapsam, izolasyon, imaj–takım eşlemesi ve klasör çakışmaları.
- **Uçtan uca test:**
  ```
  DATABASE_URL=postgres://user@host:5432/empty_db DATABASE_SSL_MODE=disable npm run test:e2e:tenancy
  ```
  - **Ne gerekir:** Boş ve atılabilir bir PostgreSQL veritabanı. Test, içinde SSI kullanıcısı olan bir veritabanında çalışmayı reddeder.
  - **Ne yapar:** Gerçek sunucuyu sahte bir Harbor'la çalıştırır.
    - Bayrak kapalıyken eski davranışı doğrular.
    - Bayrak açıkken ikinci takımın bir üyesini, birinci takımın kaydını okuyan veya değiştiren **her route'a** dener ve hepsinde 404 bekler.
    - Kontrol olarak aynı isteği kaydın kendi takımı yapar ve 404 almadığını doğrular. Böylece her 404'ün takım sınırından geldiği kanıtlanır.
  - **Yeni bir route eklenirse** bu listeye de eklenmelidir.

## Bilinen sınırlar (sonraki adımlar)

- **AD grupları:** Gruptan otomatik üyelik (`source: directory`), AD grup adı netleşince.
- **Seçenek B:** Takım başına Harbor projesi ve robot hesabı. Kod hazır, ama altyapı (proje, robot, ADO variable group) senior ile kurulmalı.
- **Production Gate:** Kenar çubuğundaki gösterge platformun approved alanını sayar. Seçenek B'deki ayrı projeler henüz sayılmaz.
- **Approver listesi:** `SSI_PUBLISH_APPROVERS` listesindeki bir kullanıcı, kendi takımında publish handoff önizlemesini okuyabilir (salt okuma). Onay yetkisi her zaman takım rolüne bağlıdır.
