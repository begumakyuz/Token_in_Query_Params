# 🛡️ Web Güvenliği: "L14 - Token in Query Params" Zafiyet Analizi ve Giderme Kılavuzu

Bu depo, "Token in Query Params" (URL üzerinde taşınan yetkilendirme belirteci) zafiyetinin siber güvenlik standartları (OWASP, DevSecOps) çerçevesinde nasıl tespit edileceğini, engelleneceğini ve güvenilir hale getirileceğini gösteren profesyonel bir *Proof of Concept* (Konsept Kanıtı) projesidir.

## 🎯 Projenin Amacı ve Kapsamı
Web uygulamalarında yetkilendirme (Authorization) anahtarlarının URL'de (`?token=...` şeklinde) taşınması Kritik Bilgi İfşası (Information Disclosure) ve Yanlış Yapılandırma (Security Misconfiguration) zafiyetlerine yol açar. Bu proje, söz konusu zafiyeti somut ölçekte simüle edip 5 aşamalı endüstri standardı yaklaşımlarla çözüme kavuşturmayı hedefler.

## 🗂 Mimari Yaklaşım ve Uygulanan Çözümler

Proje, şu temel yapı taşlarını içeren eksiksiz bir iş akışını barındırır:

1. **Kod Analizi & Güvenli Geliştirme (`/app`)**
    - **Zafiyetli Uygulama (`/vulnerable/download`):** Gelen istekleri URL query üzerinden okuyan güvensiz bir API tasarımı içerir.
    - **Güvenli Uygulama (`/secure/download`):** `Authorization: Bearer <TOKEN>` standartlarına uygun yapılandırılmış ve zamanlamaya dayalı saldırıları (Timing Attacks) engelleyen `crypto.timingSafeEqual` doğrulamasıyla donatılmıştır. Tüm anahtarlar `Environment Variables` ile izole edilmiştir.

2. **Ağ Güvenliği & Trafik Manipülasyonu (`/nginx`)**
    - Sistem, Nginx Reverse Proxy (Ters Vekil) ile internete açılır.
    - **Token Stripping:** Zafiyetli istemcilerden gelen URL tabanlı token başvurularını yakalar, token'ı URL'den sıyırır ve backend sistemine güvenli bir `Header` olarak aktarır.

3. **Adli Bilişim & Log Scrubbing (`/forensics`)**
    - Sunucu erişim kayıtları incelendiğinde zafiyetin proxy ve network loglarında ne kadar açıkça ifşa olduğu gösterilmiştir.
    - Nginx konfigürasyonu içerisine entegre edilen Regex haritalaması ile `Log Scrubbing` işlemi yapılarak hassas verilerin sunucu günlük dosyalarında maskelenmesi (örn: `***`) sağlanmıştır.

4. **Kapsamlı Tehdit Modellemesi (`/docs`)**
    - Parolanın hangi yollarla dışarı sızabileceğine ilişkin (Firewall Cache, Browser History, ve Referer Leak) potansiyel bilgi ifşası senaryoları belgelenmiştir.

5. **DevSecOps İş Akışı (`.github/workflows`)**
    - Geliştiricilerin gelecekte bu tür güvensiz kodları sisteme dahil etmesini engellemek için Semgrep tabanlı SAST (Static Application Security Testing) pipeline'ı kurulmuştur. Zafiyet algılandığında sistem PR (Pull Request) sürecinde `Merge` işlemini kilitler.

## 🚀 Başlangıç ve Kurulum

Sistemi dışa kapalı (izole) bir ağda ayağa kaldırmak ve senaryoları simüle etmek için **Docker** altyapısı kullanılmıştır.

### 1. Servisi Başlatma
Proje dizininde (repo kök klasörü) aşağıdaki komutu çalıştırarak altyapıyı başlatın:
```bash
docker-compose up -d --build
```
Bu adımla Node.js backend motoru ve Nginx ters vekili birbiriyle konuşacak şekilde güvenli ağ (`secure-net`) içerisinde başlatılacaktır.

### 2. Test Senaryoları

**A. Zafiyetli Mekanizma (Eski Yöntem)**
```bash
curl "http://localhost/vulnerable/download?token=secure_api_key_placeholder"
```
*(Sunucuya giden logları incelediğinizde Nginx'in otomatik maskeleme yaptığını loglardan teyit edebilirsiniz)*

**B. Güvenli Mekanizma (Modern Header Yaklaşımı)**
```bash
curl -H "Authorization: Bearer secure_api_key_placeholder" http://localhost/secure/download
```

## 🔐 Güvenlik Bildirimi
> Lütfen bu depo içerisinde yer alan `docker-compose.yml` veya `.env` dosyalarındaki anahtarları üretim (Production) ortamlarında kullanmayın. Gerçek dünyada bu parametreler her zaman Vault (HashiCorp) veya Secret Manager gibi merkezi ve yüksek güvenlikli sistemlerden çağrılmalıdır.

---
*Bu sistem modern uygulama güvenliği gereksinimleri (Vize Projesi) kapsamında tam fonksiyonel olarak tasarlanmıştır.*
