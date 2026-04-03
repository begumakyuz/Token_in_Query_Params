# 🛡️ Web Güvenliği: "L14 - Token in Query Params" Zafiyet Analizi ve Giderme Kılavuzu

Siber güvenlikte "Defense in Depth" (Derinlemesine Savunma) prensibini baz alan bu repository, **Token in Query Params** (Yetkilendirme verisinin URL parametreleriyle iletilmesi) zafiyetinin nasıl analiz edileceğini, yapılandırmalardan nasıl temizleneceğini ve CI/CD süreçlerinde nasıl yakalanacağını kanıtlayan kurumsal mimarili bir projedir.

---

## 🛠️ Adım 1: Kurulum & Kod Analizi (Reverse)

Kurulum adımlarını ve projedeki statik yapılandırmayı analiz ettiğimizde, kritik yetkilendirme parametrelerinin sistemde nerede barındırıldığı en önemli güvenlik zafiyetlerinden biridir.

**Sistemde `GET /vulnerable/download?token=xyz` şeklinde çalışan mekanizmanın analizi:**
Geliştiriciler sıklıkla API ve dosya indirme servislerinde oturum doğrulayıcıları (Token, API Key) en kısa yoldan URL içinde `req.query.token` diyerek alırlar. 
* Kodun içerisine baktığımızda (`app/server.js`); zafiyetli uç noktada güvenlik belirteçlerinin (Token) bir `query param` olarak beklendiği görülür. 
* Siber Güvenlik standartlarına (OWASP) göre Token'ın Query Param'da olması bir **Misconfiguration (Yanlış Yapılandırma)** örneğidir. Çünkü URI tabanlı veriler şifrelenmiş SSL/TLS katmanının (HTTPS) dışında kaldığı anda ara katmanlarda (Middleware, Proxy, Modem, ISP vb.) düz metin (plaintext) olarak kaydedilir.
* **Güvenli Mimarideki Çözümü**: Koda gömülü (*hardcoded*) tokenlar yerine `API_SECRET_KEY` çevre değişkeninden (`.env` ortamı üzerinden) çalışma zamanında belleğe alınması ve URL parametresi yerine sadece HTTP Header üzerinden kabul edilmesidir (Bkz. Mimaride Sağlanan Çözüm).

---

## 🔎 Adım 2: Adli Bilişim (Forensics & Log Analysis)

Zafiyetli URL çağrılarının izini sürmek Forensics (Adli Bilişim) yaklaşımı ile oldukça basittir. 

**Nginx Sızıntı Tespiti:** 
Saldırgan (veya sistem ağ yöneticisi), sunucudaki `/var/log/nginx/access.log` dosyasına eriştiğinde, Query kısmındaki token "kabak gibi" karşısına çıkar.
Kötü niyetli bir gözlem; `forensics/access.log` dosyasını `tail -f access.log` komutuyla okuduğunda şu manzarayı görür:

```text
192.168.1.105 - - [03/Apr/2026:10:45:12 +0000] "GET /vulnerable/download?token=secure_api_key_placeholder HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
```

**Sızıntıyı Temizleme: Log Scrubbing & Log Rotate İspatı:**
Eğer legacy sistemler (eski kodlar) hemen güncellenemiyorsa, sunucu katmanında (Nginx) Maskeleme yapılmalıdır. 
1. **Scrubbing:** `nginx.conf` içindeki Regex temelli Scrubbing (`map` modülü) algoritması `?token=xyz` ifadesini `?token=***` olarak maskeler.
2. **Log Rotate:** Log rotasyonu ile çok büyüyen bu dosyalar temizlenmeli ve silinmelidir. Projedeki `nginx/logrotate.conf` ayarı; günlük logları sıkıştırıp (gzip) saklayarak belirli bir süreden sonra kalıcı olarak silecek şekilde konfigüre edilmiştir.

---

## ⚙️ Adım 3: İş Akışları (CI/CD & Secret Management)

Geliştiricilerin URL tabanlı token zafiyetine sahip kodları sunucuya göndermesini statik olarak denetlemeliyiz. Projedeki `.github/workflows/semgrep-sast.yml` dosyası bu devsecops akışını üstlenir.

**SAST (Static Application Security Testing) Akışı ve Webhook:**
GitHub Actions üzerinde kurulan Semgrep Pipeline'ı (Secret Scanning kuralı), sistem kodlarında `req.query.token` ibaresini tarar. 

* **Nasıl Çalışır?** Bir geliştirici "Push" veya "Pull Request" eylemini tetiklediğinde, GitHub bunu bir **Webhook** ile dinler ve pipeline'ı uyandırır. Pipeline statik analize girer ve URL parametrelerinden siber güvenlik riskini tespit edip `Exit 1` koduyla döner. 
* **Etkisi**: Webhook CI sunucusundan aldığı Fail mesajına göre "Merge" butonunu kilitler ve ana (main) yapıya asla zafiyetli kod sızamaz.

---

## 🐳 Adım 4: Docker & Network Isolation (Network Güvenliği)

Dockerfile statik dosyaları izole ederken, `docker-compose.yml` projenin network topolojisini kurar. İki adet konteyner barındırıyoruz (`backend` ve `proxy`) ve bu iki sistem yalnızca kendilerine özel `secure-net` isimli dahili bir izole ağda çalışmaktadır.

**Konteynerlar Arasında URL Token Gezmesinin Riski:**
Dışarıdan (Kullanıcıdan) gelen istek, önce Nginx (Proxy) katmanına çarpar. Eğer Nginx token'ı URL seviyesinde alıp doğrudan Node.js backend'ine iletirse, her iki servisin loglarına, side-car konteynerlara veya ağ dökümlerine (Wireshark PCAP vs.) açık metin sızmış olur.

**Çözüm: Nginx Header Taşınması (Token Stripping Maketleşmesi)**
Bizim `nginx.conf` yapımızda gelen trafiğe manipülasyon uygulanır. Nginx URL'den gelen (`$arg_token`) değerini yakalar, **bunu bir Authorization: Bearer Header'a çevirir** ve arkadaki (internal networkteki) Node.js'e URL parametresini sıfırlayarak (Stripped state) Header olarak servis eder.

---

## 🕷️ Adım 5: Tehdit Modelleme (Threat Modeling)

**Token in Query Params Zafiyeti ile Account Takeover (Hesap Devralma) Senaryosu:**

Hedef (Alice) maaş bordrosunu indirmek üzere `https://hr.corp/download?token=SECURE_APP_VLRN` adresine tıklar. Threat Model vektörüne göre saldırgan şu rotalardan süzülerek tokenı devralır ve hesabı çalar:

1. **Firewall Logları**: Saldırgan (veya kötü niyetli içeriden bir admin) kurumun Firewall veya Gateway Proxy katmanını izler. Kullanıcının indirme linkine tıkladığı saniyede Firewall URL'i plaintext logladığı için tüm API Key log dosyasına düşer.
2. **Browser History (Tarayıcı Geçmişi)**: Alice ofisten kahve almaya gittiğinde, kilidi açık bilgisayarına erişen herhangi biri `Ctrl+H` (Geçmiş) sekmesinden URL ile token'ı kopyalar.
3. Bu işlemler hesabın **Account Takeover / Session Hijacking (Oturum Gaspı)** saldırısına uğramasına olanak tanır.

**Sunucuyu Yalnızca Header'a Zorlayacak Çözüm Snippeti:**
Backend sadece güvenli paketlere izin vermek üzere Token'ın query üzerinden gelmesini reddetmelidir:

```javascript
app.get('/secure/download', (req, res) => {
    // URL parametreleri yerine sadece Başlıklara (Header) göz at.
    const authHeader = req.headers['authorization'];
    
    // Header yapısı Bearer Token mimarisinde değilse veya hiç yoksa reddet.
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Zorunlu Header Hatası.' });
    }

    const token = authHeader.split(' ')[1];

    // Saldırganların tahmine dayalı Time Attack denemelerine karşı korumalı eşleştirme
    if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(VALID_TOKEN))) {
        res.download(confidentialDataPath);
    } else {
        res.status(403).json({ error: 'Erişim Reddedildi' });
    }
});
```

---

## 🏃 Sistemi Test Etme Yönergeleri
Kurulumun 5 aşamalı çözüm setini yerel makinenizde test etmek için şu komutu verin:
```bash
docker-compose up -d --build
```
Log maskelemeyi test etmek için `/vulnerable` adrese URL üzerinden; `secure` adrese ise Header parametresi ile Curl isteği atabilirsiniz. Arka planda Rust Audit Aracı testlerinizin analizi için `tools/log_auditor` içerisindedir.
