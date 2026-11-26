# SSI HTTPS — nginx TLS reverse-proxy

SSI'ın önüne TLS'i sonlandıran bir nginx koyar. Kullanıcılar
`https://ssi.example.com` üzerinden girer; şifreler artık şifreli kanaldan gider.
Doğrulanan sürüm: **nginx 1.30** (stable, 2026).

```
Kullanıcı ──HTTPS──▶ nginx :443 (TLS termination) ──HTTP──▶ ssi :5021
                        │
                        └── iç DNS: ssi.example.com  A  10.0.0.10
```

## Dosyalar

| Dosya | İçerik |
|---|---|
| `ssi.conf` | nginx sunucu bloğu (TLS + güvenlik başlıkları + proxy → ssi:5021). |
| `docker-compose.nginx.yml` | nginx servisi (v1.30 pinli) — temel compose'a eklenir. |

## Önkoşullar

1. **İç DNS kaydı** (infra): `ssi.example.com  A  10.0.0.10`.
2. **DT (Doğuş) TLS sertifikası** (infra): bu ad için sertifika + private key. Wildcard
   (`*.example.com`) de bu adı kapsar; infra hangisini verirse.

## Sertifikayı yerleştir

Sunucuda `/data/SSI/certs/` altına iki dosya koy (infra'nın verdiği isimlerle değil, şu adlarla):

```
/data/SSI/certs/ssi.fullchain.crt   # sunucu sertifikası + ara/CA zinciri
/data/SSI/certs/ssi.key             # özel anahtar
```

Private key'i sıkılaştır:
```
chmod 600 /data/SSI/certs/ssi.key
```

> Sertifika gelmeden **test etmek** istersen, 30 günlük geçici self-signed üret (tarayıcı
> uyarı verir ama boru hattını doğrular). Gerçek sertifika gelince üzerine yaz.
> ```
> mkdir -p /data/SSI/certs
> openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
>   -keyout /data/SSI/certs/ssi.key -out /data/SSI/certs/ssi.fullchain.crt \
>   -subj "/CN=ssi.example.com" \
>   -addext "subjectAltName=DNS:ssi.example.com"
> chmod 600 /data/SSI/certs/ssi.key
> ```

## Çalıştır (repo kökünden)

```bash
docker compose -f docker-compose.yml \
  -f deploy/nginx/docker-compose.nginx.yml up -d --build
```

`.env`'de HTTPS'e geçtiğini işaretle:
```
SSI_SESSION_COOKIE_SECURE=true
```

Doğrula:
```bash
curl -kI https://ssi.example.com/api/v1/health   # 200 beklenir (-k self-signed için)
```

Tarayıcıda `https://ssi.example.com` → giriş ekranı gelir; kilit ikonu görünür
(gerçek DT sertifikasıyla uyarısız).

## Cutover — düz 5021'i dışarı kapat (önemli, güvenlik)

HTTPS çalıştığını doğruladıktan sonra, kimse proxy'yi/TLS'i atlamasın diye SSI'ın düz
portunu dışarı kapat. Temel `docker-compose.yml`'de `ssi` servisinin portunu:

```
    ports:
      - "127.0.0.1:5021:5021"
```

yap (yalnızca sunucu-içi debug açık kalır, dışarı kapanır) — ya da firewall'da 5021'i kapat.
nginx, `ssi`'ye compose ağından (`ssi:5021`) eriştiği için bu değişiklik proxy'yi etkilemez.

> Not: Bu değişikliği **HTTPS çalıştıktan SONRA** yap; önce yaparsan mevcut düz erişimin kesilir.

## Güvenlik notları

- Private key (özellikle wildcard) çok hassastır: `chmod 600`, git'e ASLA koyma
  (repo'da `certs/` yok), hiçbir yere yapıştırma. Infra wildcard key'ini paylaşmak
  istemezse yalnızca `ssi.example.com`'ye özel sertifika iste.
- SSI kimliği yalnızca imzalı oturum çerezinden gelir; nginx istemciden gelen
  `X-SSI-Actor-*` / `X-Forwarded-User/Groups` başlıklarını temizler (header spoofing savunması).
- HSTS `includeSubDomains` içermez (diğer `*.example.com` uygulamalarını etkilemez).

> Kaynak: [nginx stable 1.30](https://nginx.org/), [Mozilla SSL Configuration Generator (intermediate)](https://ssl-config.mozilla.org/).
