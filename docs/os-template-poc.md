# OS template PoC (Image Journey 11–12: export ve dağıtıma hazırlık)

Durum: PoC · Windows ve Ubuntu offline build ADO'da (2026-11-24) · Kod: `poc/os-template/`

## Amaç

Docker imajlarında yaptığımızın aynısını işletim sistemi için göstermek:

1. **Kur:** Ubuntu 24.04 VM'i resmî bulut imajından açılır.
2. **Tara:** Trivy işletim sistemi paketlerindeki açıkları bulur.
3. **Düzelt:** Güncellemeler yüklenir; yeni çekirdek geldiyse makine yeniden başlatılır.
4. **Tekrar tara:** Önce/sonra raporu çıkar; düzeltilebilir açık kaldıysa build durur.
5. **Mühürle:** Makineye özel her şey silinir (build kullanıcısı, SSH anahtarları, makine kimliği, cloud-init durumu, loglar) ve makine kapatılır. Disk artık bir **template**'tir.
6. **Export:** VMware için **OVA**, Proxmox/KVM için **QCOW2** üretilir.
7. **İmzala ve kaydet:** Her dosyanın SHA-256'sı alınır, Cosign ile imzalanır ve doğrulanır. Template manifesti (katalog kaydının taslağı) yazılır.

## Karar: build vCenter'da yapılır (2026-11-20)

İlk sürümde build VM'i ADO ajanında QEMU/KVM ile açılıyordu. Bu yol kaldırıldı:

- **Neden:** Her run'da taban imaj ajana yeniden indirilecekti ve ajanda KVM (nested virtualization) gerekiyordu.
- **Yeni yol:** Packer'ın vSphere eklentisi build VM'ini doğrudan vCenter'da açar. Taban imaj (Ubuntu bulut OVA'sı) bir kez vCenter Content Library'ye konur ve her run oradan klonlanır. Ajanda KVM gerekmez.
- Bitince VM vCenter'da **template**'e çevrilir ve aynı VM OVF olarak export edilir. Export'tan OVA ve QCOW2 üretilir, imzalanır.

## Hazır olan parçalar (vCenter yolunda aynen kullanılır)

| Parça | Ne yapar |
|---|---|
| `guest/wait-cloud-init.sh` | cloud-init bitene kadar bekler |
| `guest/scan.sh` | Trivy ile işletim sistemi paketlerini çevrimdışı tarar (tarayıcı ve veritabanı build makinesinden yüklenir), paket listesini yazar |
| `guest/patch.sh` | `apt full-upgrade`, VMware ve QEMU ajanları; isteğe bağlı iç paket aynası (`APT_MIRROR`) |
| `guest/seal.sh` | Makineye özel her şeyi siler, template'i mühürler |
| `cloud-init/*.pkrtpl` | Build süresince geçici kullanıcı ve SSH anahtarı (mühürlemede silinir) |
| `host/template-report.mjs` | Önce/sonra raporu, kapı (düzeltmesi olan açık kalmaz), template manifesti |
| `host/export.sh` | Template diskinden QCOW2 ve OVA, `SHA256SUMS` |
| `host/sign.sh` | Cosign ile imza ve her imzanın doğrulanması |
| `ovf/ubuntu-2404.ovf.tpl` | VMware OVF tanımı; içe alırken SSH anahtarı ve hostname sorar |
| `guest/removal-impact.py` | Her kurulu paket için kaldırma etkisi (simülasyon) |
| `guest/minimize.sh` | Profili uygular; korunan paket ya da apt reddi varsa durur |
| `host/template-profile.mjs` | Profil doğrulama, seçim listesi (`catalog`), önizleme (`preview`), build listesi (`plan`) |
| `profiles/` | Korunan paket kuralları ve `baseline` profili |
| `linux/build-ubuntu-template.sh` | Ubuntu cloud image'ını VM açmadan günceller: sabitle → tara → güncelle → tekrar tara → kapı → mühürle → QCOW2/OVA/VHDX → manifest |
| `guest/prune-kernels.sh` | Offline build'de yalnızca en yeni çekirdeği bırakır |
| `windows/Build-WindowsTemplate.ps1` | Windows ISO'sunu offline günceller: tara → KB göm → tekrar tara → kapı → bootable ISO → manifest |
| `windows/Find-WindowsVulnerabilities.ps1` | Bir Windows imaj build'inde açık CVE'leri listeler (MSRC) |
| `windows/SsiWindowsTemplate.psm1` | Ortak fonksiyonlar (MSRC karşılaştırması, .msu doğrulama, DISM çıktısı) |

## Template profili (gereksiz paketlerin kaldırılması)

Amaç: template'te ihtiyaç olmayan paketleri, kurallı ve kanıtlı biçimde kaldırmak. Kaldırılan her
paket hem saldırı yüzeyini hem de açık sayısını düşürür.

**Seçim listeden yapılır, yazılmaz.** Liste, template'te gerçekten kurulu olan paketlerdir
(`removal-impact.jsonl`, build VM'inde yazılır). Serbest metin kabul edilmez; paket adı Debian
kuralına uymayan hiçbir şey apt'ye ulaşmaz.

| Kavram | Açıklama |
|---|---|
| Profil | Adı olan, tekrar kullanılabilen kaldırma listesi (`profiles/*.json`, `ssi.os-template-profile/v1`). `baseline` her template'e uygulanır; kurum sertleştirme standardı (ör. CIS) gelene kadar boştur. |
| Korunan paketler | Hiç seçilemez, bir kaldırmanın parçası da olamaz: `profiles/protected-packages.txt` (çekirdek, önyükleme, systemd, apt/dpkg, SSH, sudo, cloud-init, ağ, VMware/QEMU ajanları, python3) + her **Essential** ve **required** paket + apt'nin kaldırmayı reddettiği paketler. |
| Etki haritası | Her paket için kaldırılırsa yanında gidecek paketler (`apt-get --autoremove purge` simülasyonu, hiçbir şey değişmez). |

**Ekran tasarımı (SSI, sonraki adım):**

1. Aranabilir paket listesi: sürüm, açık sayısı (kritik/yüksek), "yanında gidecekler", kapanacak CVE sayısı.
2. Korunan paketler gri ve seçilemez; nedeni yanında yazar ("korunan paket", "essential", "openssh-server'ı da götürür").
3. Seçim yaptıkça canlı önizleme: toplam kaldırılacak paket, kapanacak benzersiz CVE, engel varsa nedeni.
4. **Profili kaydet** → dört göz onayı → audit kaydı. Onaylı profil adıyla build'e verilir.

Kurallar ekran ve build için tek yerde: `src/lib/templateProfile.js`.

**Build sırası:** patch → (gerekirse) reboot → `removal-impact.py` → `minimize.sh` (profil) →
ikinci tarama → kapı → seal. `minimize.sh` build VM'inde kuralları **yeniden** kontrol eder ve asıl
karar odur: önce apt simülasyonu, plan dosyası; korunan bir paket plana girerse ya da apt reddederse
build durur (çıkış 3), hiçbir şey kaldırılmaz. Kaldırma sonrası her paketin gittiği doğrulanır.

**Kanıt:** `minimize-plan.tsv` (istenen / bağımlılık), `minimize-removed.tsv`, `minimize-skipped.txt`
(listede olup kurulu olmayanlar). Rapor "Template profile X: N package(s) removed" satırını ve tabloyu,
manifest `scan.profile` alanını taşır.

**Sonra:** Template vCenter'da bir test VM'i olarak açılır (boot, SSH, cloud-init); geçmezse
yayınlanmaz.

## Sıradaki iş (vCenter bilgileri gelince)

1. Packer vSphere şablonu (Content Library'den klon, build kullanıcısı cloud-init ile, sonda template'e çevirme ve OVF export).
2. ADO pipeline'ı: araçlar sürüm ve SHA-256 ile sabit; vCenter hesabı yalnızca ADO secret variable'ından; kanıtlar her durumda artefakt olarak yayınlanır.
3. Export betiğinin kaynağı OVF export'undan gelen VMDK olur (`qemu-img` VMDK'yı okuyabiliyor).

## Güvenlik kararları

- **vCenter hesabı:** Kişisel ya da admin hesabı değil, ayrı bir servis hesabı. Yetkisi tek bir klasör, kaynak havuzu, datastore ve port group ile sınırlı. Bilgileri sadece ADO secret variable'ında durur.
- **Taban imaj sabit:** Content Library'deki imajın kaynağı ve SHA-256'sı kayıt altında.
- **VM CVE verisini internetten çekmez:** Trivy ikili dosyası ve veritabanı build makinesinden yüklenir (`--skip-db-update --offline-scan`).
- **Build kimliği geçici:** Her run'da yeni bir SSH anahtar çifti; build kullanıcısı, anahtarı ve sudo kuralı mühürlemede silinir.
- **İmza:** Anahtar yalnızca ADO secret variable'ından gelir (sign pipeline'ıyla aynı adlar ve biçim). Anahtar yoksa dosyalar imzasız kalır ve bu açıkça raporlanır.
- **Kapı:** Güncellemeden sonra düzeltmesi olan bir açık kalırsa build durur.

## Hedef platforma alma

- **VMware vSphere:** Template build sonunda zaten vCenter'da olur. Başka bir vCenter için: *Deploy OVF Template* ile `.ova`.
- **Proxmox VE:** `.qcow2` düğüme kopyalanır, `qm disk import` ile diske alınır, `qm template`.
- Her iki tarafta önce `sha256sum -c` ve `cosign verify-blob`.

## Windows (offline servis, 2026-11-23)

Windows template'i VM açmadan, Microsoft'un resmî ISO'su üzerinde **offline** üretilir (DISM).
Elle yapılan ilk çalıştırma: Windows Server 2025 Ocak ISO'su 3.388 açık CVE (210 Critical) →
Kasım kümülatif güncellemesi gömüldü → **0**. Ayrıntılar proje raporunda
(`faz-raporlari/2026-11-23-windows-iso-zafiyet-poc.md`).

**Zafiyet tespiti:** Trivy Windows'u taramaz. İmajın build'i (Version + ServicePack Build, ör.
`10.0.26100.32230`) Microsoft Security Update Guide verisiyle (MSRC CVRF API v3.0) karşılaştırılır:
ürünün (ör. "Windows Server 2025") vendor fix'i imajdan **daha yeni** bir build'de olan her CVE
imajda açıktır. Kümülatif güncellemeler önceki ayları içerdiği için en yeni build'li güncelleme
hepsini kapatır.

**Akış** (`windows/Build-WindowsTemplate.ps1`, yönetici olarak):

1. Ön kontrol: yönetici, Windows ADK Deployment Tools (imajla aynı ya da daha yeni DISM, oscdimg), boş alan.
2. Kaynak ISO'nun SHA-256'sı (isteğe bağlı sabitleme), salt okunur takma.
3. İmaj bilgisi ve **önce** taraması → kapatacak KB.
4. `.msu` dosyaları katalog adındaki SHA-1 ile doğrulanır; MSRC'nin istediği KB yoksa build durur.
5. Tek index'i dışa aktar → mount → `Add-Package` → build'i imajın kendi kayıt defterinden oku
   (`CurrentBuild.UBR`) → paket listesi → `StartComponentCleanup /ResetBase` → commit.
6. **Sonra** taraması; açık kalırsa build durur (kapı, `-MaxOpenAfter 0`).
7. BIOS + UEFI bootable ISO (oscdimg), `SHA256SUMS`, `template-manifest.json`
   (`ssi.os-template-manifest/v1`).

Hata olursa imaj `/Discard` ile kapatılır, ISO ayrılır; kaynak ISO hiç değişmez. Her adımın kanıtı
`<WorkRoot>\<BuildId>\evidence` altında (transcript, DISM logları, önce/sonra CSV+JSON, paketler).

**ADO pipeline'ı:** `azure-pipelines-os-template-windows.yml`, elle tetiklenir ve yalnızca SSI'a ayrılmış
**`SSI-Windows`** havuzunda çalışır (ajan: WINBUILD01, servis hesabı `NT AUTHORITY\SYSTEM`). Ortak
`WindowsPool` kullanılmaz: başka ekiplerin job'ları bu makineye düşmemeli. Parametreler (ISO dosya adı,
**zorunlu** ISO SHA-256, index, ürün, template adı) betiğe yalnızca ortam değişkeniyle geçer ve önce
doğrulanır. Girdiler makinede `E:\SSI-Image\iso` ve `updates` altında; template ISO
`runs\ado-<BuildId>\out` altında kalır. Artefakt: kanıtlar, manifest, `SHA256SUMS`, ISO'nun yeri (ISO'nun
kendisi değil). Her çalıştırma sadece kendi `work`/`scratch` klasörünü siler.

**SSI'da (Faz 4a, API):** Build talebi `OST-…` (`src/lib/osTemplate.js`, migration `013_os_templates.sql`):
Requested → (worker'ın imzalı sonucu) Built → Approved / Rejected. SSI sonucu kendisi yeniden
denetler: talebin ISO'su, index'i ve adı, 0 açık CVE, geçen kapı, tek uygulanan güncelleme, ISO'nun
yeri. Onayda dört göz kuralı publish'teki ayarı izler. API ve yetkiler:
`docs/azure-devops-integration.md` ("OS Templates").

**Ekran (Faz 4b):** Pipeline → **OS Templates** (`src/OsTemplates.jsx`). Katalog (onaylı template'ler:
sürüm, build, ISO SHA-256), build talepleri listesi, talep detayı (kaynak ISO, önce/sonra açık CVE,
KB, ISO'nun yeri ve parmak izi), Requested talepte Azure DevOps paneli (build **onaylı** başlar),
approver için onay/red (red gerekçeli; talep eden kendi talebine karar veremez), operator için yeni
talep formu (kurallar sunucu ve pipeline ile aynı: `validateBuildRequest`). İlk gerçek build'in
manifesti test örneği olarak `poc/os-template/windows/samples/` altında.

**Kapsam dışı (sonraki adım):** WinRE (`winre.wim`) ve kurulum ortamı (`boot.wim`) için Safe OS /
Setup Dynamic Update; imza (Cosign); lisanslı ISO; Windows ajanı ile ADO pipeline'ı.

**Bilinmesi gereken:** Elle çalıştırırken cmd'de QuickEdit kapalı olmalı; pencereye tıklamak DISM'i
dondurur ve bekleyen Ctrl+C commit'i iptal eder.

## Ubuntu (offline build, 2026-11-24)

Windows'taki yol Ubuntu 24.04'e uygulandı: VM **açılmaz**, resmî bulut imajı (cloud image) yerinde
değiştirilir (libguestfs `virt-customize`). Bu yüzden vCenter, Packer ve ajanda nested
virtualization gerekmez; KVM varsa kullanılır, yoksa qemu emüle eder (daha yavaş). 2026-11-20'deki
"vCenter'da build" kararı bu yolla gereksizleşti; Packer/vCenter parçaları (`cloud-init/`,
`wait-cloud-init.sh`, `scan.sh`) o yol için yerinde duruyor.

**Akış** (`linux/build-ubuntu-template.sh`, `linux/Dockerfile` builder konteynerinde):

1. **Sabitle:** Cloud image talepteki SHA-256 ile doğrulanır (önbellekteki kopya her run'da yeniden).
   İsteğe bağlı: `CLOUD_IMAGE_KEYRING` verilirse Canonical'ın imzalı `SHA256SUMS`'ı da `gpgv` ile
   doğrulanır ve sabit hash orada aranır.
2. Kök bölüm istenen boyuta büyütülür (`virt-resize`, varsayılan 20 GiB).
3. **Önce taraması:** İmajdaki dpkg veritabanı ve `os-release` okunur (salt okunur), Trivy
   çevrimdışı tarar (`--skip-db-update --offline-scan --pkg-types os`). Trivy DB'si 72 saatten
   eskiyse build durur. Trivy imajı Ubuntu 24.04 olarak tanımaz ya da paket görmezse build durur:
   işletim sistemini görmeyen bir tarama "0 açık" der ama hiçbir şey kanıtlamaz (ilk ADO run'ında
   `etc/lsb-release` eksik ve `os-release` symlink olduğu için böyle oldu, düzeltildi).
4. **Düzelt:** `guest/patch.sh` imajın içinde (apt full-upgrade, open-vm-tools, qemu-guest-agent;
   `APT_MIRROR` ile iç ayna). Sonra `guest/prune-kernels.sh`: VM hiç açılmadığı için apt eski
   çekirdeği "çalışan çekirdek" diye koruyamaz; yalnızca en yeni çekirdek bırakılır, yoksa eski
   çekirdeğin kapanmış CVE'leri template'te kalırdı.
5. **Sonra taraması** ve **kapı** (`host/template-report.mjs`): düzeltmesi olan açık kalırsa build
   durur (çıkış 1).
6. **Mühürle:** `guest/seal.sh` (cloud-init, machine-id, SSH host anahtarları, loglar, apt önbelleği),
   build dosyaları ve geçici apt proxy ayarı silinir, `virt-sparsify`. Mühür diskin üzerinde
   **ayrıca doğrulanır**: host anahtarı yok, machine-id boş, build dosyası yok, `/etc/ssi-template-release` var.
7. **Export** (`host/export.sh`): QCOW2 (Proxmox/KVM), OVA (vSphere), VHDX (Hyper-V, `EXPORT_VHDX=true`),
   `SHA256SUMS`, `template-manifest.json` (`ssi.os-template-manifest/v1`; araç sürümleri ve Trivy DB tarihi dahil).

Kanıt `reports/` altında: önce/sonra Trivy JSON, paket listeleri, çekirdek, `scan-report.md/json`,
mühürlü diskin release dosyası.

**ADO pipeline'ı:** `azure-pipelines-os-template-ubuntu.yml`, elle tetiklenir, **LinuxPool**'da çalışır.
Builder konteyneri ayrıcalıksızdır (`--privileged` yok, Docker soketi yok, ajan kullanıcısıyla);
`/dev/kvm` varsa verilir. Trivy DB'si canonical scan worker'ıyla aynı digest'li Trivy imajıyla iner.
Parametreler (cloud image URL'si yalnızca `https://cloud-images.ubuntu.com/…`, **zorunlu** SHA-256,
template adı, disk boyutu, iç ayna) yalnızca ortam değişkeniyle geçer ve önce doğrulanır. Doğrulanmış
cloud image ajanda SHA-256 adıyla önbellekte kalır (30 gün kullanılmayan silinir). Artefaktlar:
`os-template-ubuntu-evidence` (her durumda) ve her format için ayrı bir artefakt:
`os-template-ubuntu-qcow2`, `-ova`, `-vhdx` (2026-11-25'ten önceki run'larda üçü birlikte
`os-template-ubuntu-images`). Sonuç SSI'a ancak dosyalar yayımlandıktan sonra gönderilir. Run kendi
çalışma klasörünü ve builder imajını siler.

**İlk gerçek run (ADO 20261124.2, LinuxPool, 14 dk):** cloud image `release-20261017`
(`04e8f246…`), çekirdek 6.8.0-147 → 6.8.0-151, 68 paket güncellendi. Trivy bulguları (CVE × paket)
25.352 → 5.499; düzeltmesi olan 19.870 → **0**; kapı geçti. Kalanların hepsinin Canonical'da henüz
yaması yok. (İlk run 20261124.1 "0 → 0" demişti: Trivy imajı tanımamıştı; düzeltildi, artık build
durur.)

**Rapor:** CVE'ler iki türlü sayılır. **CVE** tablosu her CVE'yi bir kez, en yüksek önem
derecesiyle sayar (bir çekirdek CVE'si her çekirdek paketinde ayrı bulgu olur). **Bulgular** tablosu
Trivy'nin CVE × paket satırlarıdır. "New" CVE tablosunda yalnızca önceden hiç olmayan CVE'dir; adı
değişen çekirdek paketi yeni CVE getirmez. Manifest ikisini de (`scan.cves`, `scan.before/after`) ve
Trivy'nin tanıdığı işletim sistemini (`scan.os`) taşır.

**SSI'da (Faz 5.4):** OS Templates ekranında işletim sistemi seçilir (Windows / Ubuntu 24.04).
Ubuntu talebi: cloud image URL'si (yalnızca `https://cloud-images.ubuntu.com/…`), SHA-256'sı,
template adı, disk boyutu, isteğe bağlı iç ayna. Talep yalnızca kendi işletim sisteminin
pipeline'ını başlatır (`os-template-build-ubuntu`, `SSI_ADO_PIPELINE_OS_TEMPLATE_UBUNTU`). SSI imzalı
sonucu yeniden denetler: talebin URL'si, SHA-256'sı ve adı; Trivy'nin Ubuntu 24.04'ü tanımış olması;
düzeltmesi olan CVE kalmaması; kapının uygulanmış ve geçmiş olması; Trivy DB'sinin 7 günden eski
olmaması; QCOW2/OVA/VHDX'in her birinin bir kez, beklenen adla ve SHA-256'sıyla gelmesi; dosyaların o
ADO run'ının artefaktlarında olması. Sözleşme testi: SSI, manifesti
`template-report.mjs`'in yazdığı haliyle kabul eder (`src/lib/osTemplateUbuntu.test.js`).

**SSI'dan indirme (2026-11-25):** Built ve Approved bir Ubuntu template'inin detayında **Downloads**:
QCOW2, OVA, VHDX (her biri ayrı zip) ve kanıtlar. Dosyalar SSI'da tutulmaz; SSI onları o template'i
build eden ADO run'ından akıtır (`Artifacts - Get Artifact`, zip). Akış:

1. Kullanıcı **Download**'a basar → `POST /os-templates/{id}/download-tickets` (`os-template:download`:
   operator, approver, admin). SSI talebin durumunu ve artefaktın ADO'da hâlâ durduğunu denetler,
   **5 dakikalık, en fazla 3 kez kullanılabilen** bir bağlantı verir (Chrome düz HTTP'deki indirmeyi
   durdurur; "Keep" denince aynı bağlantıyı yeniden ister), `os-template.download.authorized` yazar.
2. Tarayıcı bu bağlantıyı düz bir link olarak indirir (`GET /os-templates/{id}/downloads?ticket=…`).
   SSI talebi yeniden denetler ve dosyayı ADO'dan diske yazmadan akıtır; ADO içeriği Azure blob
   depolamasına yönlendirirse token oraya gönderilmez. Sonunda `os-template.download.completed`
   (bayt sayısıyla) ya da `.failed` (sonuç: failure; bağlantıyı kimin kestiği `closedBy`: browser,
   azure-devops, idle-timeout; gelen ve beklenen bayt, tarayıcının `Range` isteği) yazılır.

   **Kök sebep (2026-11-25):** ADO artefakt zip'ini `Content-Length` olmadan (chunked) gönderiyor; SSI
   eksik başlığı 0 bayt okuyup tarayıcıya `Content-Length: 0` bildiriyordu (boş zip, ilk parçadan sonra
   kopan bağlantı), sonra da "boş arşiv" diye reddetti. Eksik başlık artık "boyut bilinmiyor" sayılıyor;
   regresyon testi var. **İkinci kök sebep (aynı gün):** ADO bağlantısına konan 60 saniyelik "yanıt
   başlığı" süresi isteğin tamamına uygulanıyordu; 60 saniyeden uzun süren her indirme (4 GB arşiv:
   157–298 MB'ta) "The operation was aborted due to timeout" ile kesildi. Süre artık yalnızca başlıkların
   gelmesini bekler; akış başladıktan sonra indirmeyi yalnızca tarayıcının ayrılması ya da 2 dakika
   veri gelmemesi bitirir. **Chrome ve düz HTTP:** Chrome http üzerinden gelen indirmeyi "Insecure download
   blocked" diye bekletir; "Keep" ile devam edilir. Kalıcı çözüm SSI'ın HTTPS ile yayınlanması.
   Kalıcı çözüm SSI'ın HTTPS ile yayınlanması; o zamana kadar dosyalar ADO run'ının Artifacts
   sayfasından da indirilebilir.
3. Zip açılınca dosya ekrandaki SHA-256 ile doğrulanır (`certutil -hashfile … SHA256`).

**Saklama:** Bir Ubuntu template'i onaylanınca SSI, ADO'da o run'a süresiz bir **retention lease**
koyar (`Leases - Add`, sahibi `SSI:OST-…`); onaylı template'in dosyaları ADO'nun temizliğinde
silinmez. Lease alınamazsa onay da verilmez. ADO entegrasyonu kapalıysa onay "elle saklanmalı" notuyla
kaydedilir. Windows ISO'su ADO'ya yüklenmediği için SSI'dan indirilmez (build makinesinde durur).

**Kapsam dışı (sonraki adım):** template'in bir VM'de açılış testi (boot, cloud-init, SSH); onaylı
template'ler için ADO dışında kalıcı bir depo (senior kararı); Windows ISO'sunun indirilmesi; template profili
(`minimize.sh`) bu akışa bağlı değil; imza (Cosign); snap paketleri (Trivy `os` taraması dpkg
paketlerini kapsar).

## Gerekenler (senior'dan istendi)

1. vCenter servis hesabı (sınırlı yetki, secret variable olarak).
2. vCenter adresi ve sürümü; datacenter, cluster/resource pool, datastore, VM klasörü, port group adları; DHCP bilgisi.
3. ADO ajanından vCenter'a (443) ve build VM'ine (SSH, 22) ağ erişimi.
4. Content Library.

## Doğrulama durumu

- Test edilenler: profil kuralları ve önizleme; etki haritası gerçek Ubuntu 24.04'te `apt-get` ile birebir (1.066 paket); `minimize.sh` dry-run (korunan paket, apt reddi, yazılmış komut); rapor ve kapı mantığı, QCOW2/OVA üretimi ve OVA yapısı (gerçek `qemu-img`), SHA-256 ve Cosign imza/doğrulama, betiklerin shellcheck kontrolü.
- Windows: 2026-11-23'te test sunucusunda elle uçtan uca (3.388 → 0); betik fonksiyonları birim testli (PowerShell 7), betiğin kendisi sunucuda doğrulanacak.
- Henüz yok: vCenter'da gerçek build (vSphere şablonu ve pipeline, bilgiler gelince yazılacak).
