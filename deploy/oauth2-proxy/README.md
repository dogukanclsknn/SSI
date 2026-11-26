# SSI Production Kimlik — oauth2-proxy + Microsoft Entra ID

Bu klasör, SSI RBAC'ını gerçek kurumsal girişe (Entra ID / Azure AD) bağlayan
çalıştırılabilir kimlik katmanıdır. SSI kodu bu header'ları okumaya zaten hazırdır
(`src/server/identity.js`); burada yalnızca önüne düşecek proxy yapılandırılır.

Kimlik sağlayıcı kararı **Entra ID** olarak netleşmiştir (Azure DevOps ile uyumlu).

## Akış

```
Kullanıcı ──▶ oauth2-proxy ──(Entra ID OIDC ile doğrula)──▶ Entra ID
                   │
                   └──(X-Forwarded-User + X-Forwarded-Groups)──▶ SSI :5021
                                                                    │
                                                    grup→rol (SSI_RBAC_GROUP_ROLE_MAP)
                                                                    │
                                                            RBAC enforce (401/403)
```

## Dosyalar

| Dosya | İçerik |
|---|---|
| `oauth2-proxy.cfg` | Sır-olmayan proxy yapılandırması (provider, scope, upstream, header geçişi). |
| `docker-compose.oauth2-proxy.yml` | Temel compose'a eklenen oauth2-proxy servisi (v7.15.4 pinli). |
| `oauth2-proxy.env.example` | Entra sırları + grup→rol eşlemesi için örnek ortam değişkenleri. |

## Çalıştırma (repo kökünden)

```bash
docker compose -f docker-compose.yml \
  -f deploy/oauth2-proxy/docker-compose.oauth2-proxy.yml up -d --build
```

Önce sunucudaki `.env`'e şunlar girilmeli (gerçek değerlerle):

```
# Entra sırları
ENTRA_TENANT_ID=...
ENTRA_CLIENT_ID=...
ENTRA_CLIENT_SECRET=...
OAUTH2_PROXY_REDIRECT_URL=https://<ssi-dış-host>/oauth2/callback
OAUTH2_PROXY_COOKIE_SECRET=<32 baytlık rastgele>

# RBAC enforce
SSI_RBAC_ENFORCED=true
SSI_TRUST_ACTOR_HEADER=true
SSI_DEV_LOGIN=false
SSI_RBAC_GROUP_ROLE_MAP=<grup-guid>:approver, <grup-guid>:operator, <grup-guid>:viewer
```

## Sam'in yapacakları (Entra tarafı — 1 kayıt + 2 karar)

1. **App Registration**: Entra ID'de bir uygulama kaydı aç. Redirect URI =
   `OAUTH2_PROXY_REDIRECT_URL` ile birebir aynı olsun. Bir client secret üret.
2. **Groups claim**: App Registration → Token configuration → *groups claim* ekle
   (Security groups). Entra varsayılan olarak grup **GUID'lerini** gönderir.
3. **Grup → rol**: Hangi mevcut grup `approver / operator / viewer / admin`?
   Grupların GUID'lerini ver; `SSI_RBAC_GROUP_ROLE_MAP`'e eşlenir. (Yeni grup
   açmaya gerek yok — mevcut gruplar eşlenebilir; ileride eklenebilir.)

## Güvenlik notu (önemli)

Proxy devredeyken SSI'a **doğrudan** (proxy'siz) erişim ağ düzeyinde kapatılmalıdır.
Aksi halde bir istemci `X-Forwarded-User/Groups` header'larını taklit edip RBAC'ı
atlayabilir. Temel compose SSI'ı 5021'de yayınlar; prod'da bu portu makine dışına
açmayın (firewall ya da `127.0.0.1:5021:5021` bağlaması). Kullanıcı trafiği yalnızca
proxy (4180) üzerinden gelmelidir. TLS'i kurumsal reverse proxy / yük dengeleyici
sonlandırıyorsa 4180'i ona bağlayın.

> Kaynaklar: [oauth2-proxy — Microsoft Entra ID provider](https://oauth2-proxy.github.io/oauth2-proxy/configuration/providers/ms_entra_id/) · doğrulanan sürüm v7.15.4 (Ağu 2026).
