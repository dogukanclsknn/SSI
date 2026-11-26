# Onaylı imajlar için sabit latest adresi

Onboard kuyruğu artık 15 saniyede bir güncellenir. İlerleme çubuğu Azure DevOps
timeline'ındaki tamamlanan görevler ve worker'ın bildirdiği aşamalardan hesaplanır;
bayt/indirme yüzdesi veya süre tahmini değildir. Ön kontrol %0–25, aktarım/tarama
%25–95 aralığındadır; yalnızca SSI import receipt'i kabul ettiğinde %100 olur.
Ön kontrolün bitmesi aktarımın otomatik başladığı anlamına gelmez: satır açıkça
"Check passed — ready to start import" gösterir. Telemetri alınamıyorsa yüzde
uydurulmaz; hata, iptal ve receipt bekleme durumları ayrı gösterilir.

Controlled Publish worker, test ve policy/onay akışından geçmiş imajı önce değişmez
sürümlü etikete yayınlar. Manifest digest'ini doğruladıktan sonra aynı repository'nin
`latest` etiketini bu digest'e taşır ve tekrar doğrular. Bu davranış bütün onaylı
repository'ler için geçerlidir; onboard veya Copa aday çıktısına latest verilmez.

Örnek tüketim adresi:

```text
registry.example.com/ssi-images/approved/nginx:latest
```

Tüketen pipeline bu adresi sabit tutabilir. Her build'de etiketi yeniden çözmeli/çekmeli;
yerel Docker cache'ine güvenmemelidir (`docker pull` veya build sırasında `--pull`).
Tekrarlanabilir dağıtımlar için çözülmüş digest ayrıca kaydedilebilir.

Publish detayında kaynak imaj/sürüm referansı, değişmez yayın etiketi ve yayın anında
latest'e atanan digest gösterilir. Eski bir talepteki latest bilgisi o yayın anının
kaydıdır; etiket daha sonraki yayınlarla değişebilir. Kaynak etiketi gerçek paket
sürümünün kanıtı değildir; kurulu sürüm tarama/paket raporundan doğrulanmalıdır.

## Devreye alma

- API ve arayüz ile `azure-pipelines-controlled-publish.yml` birlikte güncellenmelidir.
- Harbor tag immutability kuralı sürümlü etiketleri korumalı, `latest` etiketini hariç
  tutmalıdır. Aksi durumda worker alias adımında durur; sürümlü yayın yerinde kalır.
- Worker'ın mevcut approved/ yazma hesabı latest'i güncelleyebilmelidir. Onboard veya
  remediation worker hesaplarının yetkisini genişletmek gerekmez.
- Aynı repository için yayınları sırayla çalıştırın; eşzamanlı registry yazmaları için
  Harbor atomik karşılaştırmalı tag güncellemesi sağlamaz. Son tamamlanan alias yazması kazanır.
- Sürümlü yayın başarılı fakat alias/receipt başarısızsa aynı talep yeniden çalıştırılabilir.
  Aynı digest'li sürümlü yayın tekrar yazılmaz; latest doğrulaması ve receipt yeniden denenir.
- Eski worker receipt'leri alias bilgisi olmadan kabul edilir; eski yayınlara latest
  eklenmiş varsayılmaz. Yeni yayınlar bu worker ile tamamlandığında alias kaydı oluşur.
- Withdraw mevcut tasarımdaki gibi Harbor'a yazmaz: geri çekilen digest latest'teyse
  Harbor yöneticisi etiketi kaldırmalı veya başka onaylı digest'e taşımalıdır.

## Sürüm yükseltme ve Nginx örneği

Yeniden tarama aynı digest'i güncel zafiyet verisiyle inceler; imajı yükseltmez.
Copa OS paketlerini mevcut dağıtım depolarının sunduğu düzeltmelere yükseltir;
uygulamanın upstream sürümüne geçişi garanti etmez.

Nginx 1.31.9 hedefi için `docker.io/library/nginx:1.31.9` kaynak imajını yeni
onboarding isteğiyle alın, tarama/paket raporundaki nginx sürümünü doğrulayın,
gerekiyorsa Copa çalıştırın, yeniden tarayın, aday testi/tüketici onayı ve Publish
akışını tamamlayın. Mainline 1.31.9 güvenlik duyurusu:
https://nginx.org/en/security_advisories.html

Import düğmesi için `onboarding:create` (Operator veya Admin) gerekir. Viewer
salt okuma rolüdür. Admin Users ekranından kullanıcının rolünü değiştirebilir;
butonu açmak için RBAC'ı kapatmayın.
