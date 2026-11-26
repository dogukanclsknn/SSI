# OS template PoC

Ubuntu 24.04 işletim sistemi template'ini SSI'ın konteyner imajlarına uyguladığı mantıkla üretir:
**kur → tara → güncelle → tekrar tara → kapı → mühürle → OVA + QCOW2 → imzala**. Tasarım ve
kararlar: [`docs/os-template-poc.md`](../../docs/os-template-poc.md).

**Durum:** Ubuntu 24.04 VM açmadan, cloud image üzerinde offline üretilir
(`linux/build-ubuntu-template.sh`, ADO: `azure-pipelines-os-template-ubuntu.yml`, 2026-11-24).
Windows: `windows/`. `cloud-init/`, `guest/wait-cloud-init.sh` ve `guest/scan.sh` VM açan
(Packer/vCenter) yol içindir.

## Dosyalar

| Yol | Ne yapar | Nerede çalışır |
|---|---|---|
| `cloud-init/` | İlk açılışta geçici build kullanıcısını ve SSH anahtarını tanımlar | VM (ilk açılış) |
| `guest/wait-cloud-init.sh` | cloud-init bitene kadar bekler | VM |
| `guest/scan.sh` | Trivy ile işletim sistemi paketlerini tarar (çevrimdışı), paket listesini yazar | VM |
| `guest/patch.sh` | `apt full-upgrade`, VMware ve QEMU ajanları; isteğe bağlı iç ayna (`APT_MIRROR`) | VM |
| `guest/seal.sh` | Makineye özel her şeyi siler, template'i mühürler | VM |
| `host/template-report.mjs` | Önce/sonra raporu, kapı, template manifesti | Build makinesi |
| `host/export.sh` | QCOW2 ve OVA üretir, `SHA256SUMS` yazar | Build makinesi |
| `host/sign.sh` | Cosign ile imzalar ve her imzayı doğrular | Build makinesi |
| `ovf/ubuntu-2404.ovf.tpl` | VMware OVF tanımı (ilk açılış ayarları dahil) | Build makinesi |
| `guest/removal-impact.py` | Her kurulu paketin kaldırma etkisini yazar (hiçbir şey değişmez) | VM |
| `guest/minimize.sh` | Template profilini uygular; korunan paket ya da apt reddi varsa durur | VM |
| `host/template-profile.mjs` | Profil doğrulama, seçim listesi, önizleme, build listesi | Build makinesi |
| `profiles/` | `protected-packages.txt` (korunan paketler), `baseline.json` | Build makinesi |
| `linux/build-ubuntu-template.sh` | Ubuntu cloud image'ını offline günceller, tarar, mühürler, QCOW2/OVA/VHDX ve manifest üretir | Builder konteyneri |
| `linux/Dockerfile` | Builder: libguestfs, qemu-img, sabit digest'li Trivy | LinuxPool ajanı |
| `guest/prune-kernels.sh` | Yalnızca en yeni çekirdeği bırakır (offline build) | İmajın içi |
| `windows/Build-WindowsTemplate.ps1` | Windows ISO'sunu offline günceller, tekrar tarar, bootable ISO ve manifest üretir | Windows build makinesi |
| `windows/Find-WindowsVulnerabilities.ps1` | Windows imaj build'inde açık CVE listesi (MSRC) | Windows build makinesi |
| `windows/SsiWindowsTemplate.psm1` | Ortak PowerShell fonksiyonları | Windows build makinesi |

Betikler her zaman `bash betik.sh` ile çalıştırılır (Windows'tan yapılan commit çalıştırma iznini
taşımaz).

## Rapor ve kapı

```bash
node host/template-report.mjs report --reports-dir <dizin> --fail-on-fixable true
```

`<dizin>` içinde `scan-before.json`, `scan-after.json`, `packages-*.tsv`, `kernel-*.txt` beklenir;
`scan-report.json` ve `scan-report.md` yazılır. Güncellemeden sonra düzeltmesi olan bir açık kaldıysa
çıkış kodu 1'dir.

## Template profili

```bash
node host/template-profile.mjs catalog --impact out/removal-impact.jsonl --scan out/scan-after.json \
  --protected profiles/protected-packages.txt --out packages.json        # seçim listesi
node host/template-profile.mjs preview --profile profiles/web.json --impact out/removal-impact.jsonl \
  --scan out/scan-after.json --protected profiles/protected-packages.txt  # engel varsa çıkış 1
node host/template-profile.mjs plan --profile profiles/web.json \
  --protected profiles/protected-packages.txt --out remove.txt            # VM'e verilecek liste
```

VM'de: `REMOVE_LIST=remove.txt PROTECTED_LIST=protected-packages.txt bash guest/minimize.sh`
(`MINIMIZE_DRY_RUN=1` yalnızca planı yazar). Raporda profil adı: `template-report.mjs report --profile <ad>`.

## Windows template (offline)

Yönetici PowerShell/cmd, Windows ADK Deployment Tools kurulu:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -File windows\Build-WindowsTemplate.ps1 ^
  -IsoPath E:\SSI-Image\iso\WS2025_EVAL_en-us.iso ^
  -ExpectedIsoSha256 7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51 ^
  -ImageIndex 2 -UpdatesPath E:\SSI-Image\updates -WorkRoot E:\SSI-Image\runs
```

ADO'dan: **SSI - OS Template (Windows)** pipeline'ı (`azure-pipelines-os-template-windows.yml`,
havuz `SSI-Windows`). `isoSha256` zorunlu.

`-UpdatesPath` içinde kümülatif güncelleme `.msu` dosyası (Microsoft Update Catalog'daki adıyla;
listede checkpoint varsa o da). Sadece tarama:
`windows\Find-WindowsVulnerabilities.ps1 -ImageBuild 10.0.26100.32230 -Since 2026-01-01 -OutPrefix scan`.

## Export ve imza

```bash
SOURCE_DISK=<template diski> OUT_DIR=<boş dizin> TEMPLATE_NAME=ssi-ubuntu-2404 \
TEMPLATE_VERSION=<sürüm> BUILD_ID=<build no> OVF_TEMPLATE=ovf/ubuntu-2404.ovf.tpl \
  bash host/export.sh

COSIGN=<cosign yolu> KEY_ID_FILE=<dosya> bash host/sign.sh <dizin>/*.qcow2 <dizin>/*.ova <dizin>/SHA256SUMS
```

`sign.sh` anahtarı Supply-Chain Sign pipeline'ıyla aynı biçimde ortam değişkenlerinden alır
(`COSIGN_PRIVATE_KEY`, `COSIGN_PUBLIC_KEY`: PEM'in base64'ü; `COSIGN_PASSWORD`).

## Doğrulama (içe almadan önce)

```bash
sha256sum -c SHA256SUMS
cosign verify-blob --key cosign.pub --insecure-ignore-tlog=true \
  --signature ssi-ubuntu-2404-<sürüm>.ova.sig ssi-ubuntu-2404-<sürüm>.ova
```

## VMware vSphere'e alma (OVA)

vCenter → *Deploy OVF Template* → `.ova`. *Customize template* adımında hostname ve **SSH public
key** girilir (template'te parola ya da anahtar yoktur). Deploy bitince VM → *Template* → *Convert
to Template*. Komut satırı: `ovftool` ya da `govc import.ova` + `govc vm.markastemplate`.

## Proxmox VE'ye alma (QCOW2)

```bash
qm create 9000 --name ssi-ubuntu-2404 --memory 2048 --cores 2 --ostype l26 \
  --net0 virtio,bridge=vmbr0 --scsihw virtio-scsi-pci --agent enabled=1 --serial0 socket --vga serial0
qm disk import 9000 ssi-ubuntu-2404-<sürüm>.qcow2 local-lvm     # eski sürümlerde: qm importdisk
qm set 9000 --scsi0 local-lvm:vm-9000-disk-0 --boot order=scsi0 --ide2 local-lvm:cloudinit
qm template 9000
```

## Mühürlemede silinenler

Build kullanıcısı, SSH anahtarı ve sudo kuralı; SSH host anahtarları; makine kimliği; cloud-init
durumu ve logları; apt önbelleği; shell geçmişi; `/var/log` içeriği; tarayıcı ve veritabanı.
Template'e eklenen tek iz `/etc/ssi-template-release` (ad, sürüm, build numarası, mühürlenme
zamanı).
