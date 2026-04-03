# 🛡️ Web Güvenliği: "L14 - Token in Query Params" Zafiyeti Vize Projesi

Bu repo, "Token in Query Params" (URL'de taşınan yetkilendirme belirteci) zafiyetinin nasıl istismar edileceğini ve siber güvenlik (Defensive Security & DevSecOps) ilkelerine göre 5 aşamalı çözümünü/simülasyonunu içerir.

> **Sitenin / Uygulamanın yetkili erişim şifresi `1337`'dir.**

## 🗂 Vize Projesi Gereksinimleri ve Dosya Mimarisi

Bu yapı, değerlendirme kriterlerinin tümünü (Kurulum/Cleanup, CI/CD, Docker, Threat Modeling/Auth) eksiksiz kapsayacak şekilde hazırlanmıştır:

1. **Kurulum & Kod Analizi (Reverse Engineering):**
    - `app/server.js` dosyasında `GET /vulnerable/download` ve `GET /secure/download` tasarlanmıştır. Express kullanarak URL token zafiyeti ve Timing-Safe Header tabanlı onay mekanizması kodlanmıştır.
2. **Adli Bilişim (Forensics & Log Analizi):**
    - `forensics/access.log` içerisinde simüle edilen sızıntı gösterilmiş ve bu sızıntının `nginx/nginx.conf` içerisindeki Regex (Log Scrubbing) haritalaması ile nasıl gizleneceği kanıtlanmıştır.
3. **İş Akışları (CI/CD) ve SAST:**
    - `.github/workflows/semgrep-sast.yml` içerisinde kod tabanına entegre, Webhook engellemeli statik güvenlik analizi (Semgrep) çalıştırılmıştır.
4. **Docker & Ağ İzolasyonu:**
    - Kök dizindeki `docker-compose.yml` kullanılarak sistem güvenli bir yerel ağa (`secure-net`) alınmış, açıkta olan sadece Nginx Ters Vekili bırakılmıştır.
    - Nginx ayrıca `Token Stripping` işlemi yaparak güvensiz URL'i Backend'e Güvenli Header olarak yollar.
5. **Tehdit Modelleme (Threat Modeling):**
    - `docs/Threat_Model.md` dosyasında zafiyetin Loglardan, Browser'dan ve Referer başlıklarından yarattığı Risk analizi (Information Disclosure) sunulmuştur.

## 🚀 Sistemi Ayağa Kaldırmak ve Test Etmek

Projeyi yerel makinenizde / sunucuda çalıştırmak için Docker gereklidir.

```bash
docker-compose up -d --build
```

**1. Zafiyetli Endpoint Testi (Token URL'de):**
```bash
curl "http://localhost/vulnerable/download?token=1337"
# Nginx loglarına bakarsanız Token maskelenmiş olacaktır!
# Docker ile: docker logs <proxy_container_name>
```

**2. Güvenli Endpoint Testi (Header'da, Modern Yöntem):**
```bash
curl -H "Authorization: Bearer 1337" http://localhost/secure/download
# Size gizli conf dosyasını indirecektir.
```
