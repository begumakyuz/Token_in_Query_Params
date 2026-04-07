# 🛡️ L14 - Token in Query Params (Python/Flask) Analiz ve Çözüm Projesi

![İstinye Üniversitesi](https://upload.wikimedia.org/wikipedia/tr/6/6f/Istinye_Universitesi_Logo.png)

[![Semgrep SAST Scan](https://github.com/begumakyuz/Token_in_Query_Params/actions/workflows/semgrep-sast.yml/badge.svg)](https://github.com/begumakyuz/Token_in_Query_Params/actions/workflows/semgrep-sast.yml)
![License](https://img.shields.io/github/license/begumakyuz/Token_in_Query_Params)
![Python Version](https://img.shields.io/badge/python-3.10-blue.svg)
![Docker Ready](https://img.shields.io/badge/docker-ready-blue.svg)

## 📋 Proje Bilgileri
*   **Öğrenci:** Begüm Akyüz
*   **Danışman:** Öğr. Gör. Keyvan Arasteh Abbasabad
*   **Kurum:** İstinye Üniversitesi - Bilişim Güvenliği Teknolojisi

---

## 📖 İçindekiler
- [🎬 Demo](#-demo)
- [🛠️ Adım 1: Kurulum & Kod Analizi (Reverse)](#️-adım-1-kurulum--kod-analizi-reverse)
- [🔎 Adım 2: Adli Bilişim (Forensics & Log Analysis)](#-adım-2-adli-bilişim-forensics--log-analysis)
- [⚙️ Adım 3: İş Akışları (CI/CD & Secret Management)](#️-adım-3-iş-akışları-cicd--secret-management)
- [🐳 Adım 4: Docker & Network Isolation](#-adım-4-docker--network-isolation)
- [🕷️ Adım 5: Tehdit Modelleme (Threat Modeling)](#️-adım-5-tehdit-modelleme-threat-modeling)
- [🚀 Kurulum ve Çalıştırma Rehberi (Getting Started)](#-kurulum-ve-çalıştırma-rehberi-getting-started)

---

## 🎬 Demo
Aşağıdaki videoda projenin kurulumu, özellikleri ve güvenlik testlerinin çalıştırılması detaylı bir şekilde gösterilmektedir.

> [!TIP]
> Videoyu tam ekran izlemeniz önerilir.

[![Proje Demosu](https://img.shields.io/badge/🎬-İzle_Project_Demo-blue?style=for-the-badge&logo=youtube)](demo/project-demo.webm)

*(Eğer video açılmazsa, `demo/project-demo.webm` dosyasını indirip tarayıcınızda veya VLC Player ile izleyebilirsiniz.)*

---

Bu proje, "Token in Query Params" (Yetkilendirme verisinin URL parametreleriyle iletilmesi) zafiyetinin **Flask tabanlı (app.py)** bir Python uygulamasında nasıl tespit edileceğini ve kurumsal standartlarda nasıl temizleneceğini gösteren profesyonel bir Siber Güvenlik Laboratuvarıdır.

... [rest of the file remains similar but I will provide the full updated content below to be precise]

> 🎓 **Projenin Akademik Çerçevesi (Reasoning):** Siber saldırılar genellikle tek bir zafiyetten değil, zincirleme yapılandırma hatalarından doğar. Bu sistemde sadece zafiyet yamalanmamış, aynı zamanda "Defense in Depth" (Derinlemesine Savunma) felsefesi benimsenerek Nginx Ağ, Adli Bilişim Günlükleri, CI/CD Pipeline kontrolleri ve Rootless Docker katmanlarında sıkılaştırma yapılmıştır.

Aşağıdaki **5 Adım**, projenin güvenlik kriterlerine birebir cevap verecek şekilde akıl yürütme (Reasoning) ile genişletilmiştir:

---

## 🛠️ Adım 1: Kurulum & Kod Analizi (Reverse)
Projeye dahil olan uygulamanın statik kodları incelendiğinde (`app.py`), "Authentication / Authorization" zincirinin en zayıf halkası ortaya çıkar.

* **Zafiyetli Tasarım:** `request.args.get('token')` metodu, gizli anahtarı URL (GET parametresi) olarak kabul eder. (`/vulnerable/download?token=XYZ`)
* 🧠 **Reasoning (Neden Bu Bir Yanlış Yapılandırmadır?):**
  Geliştiriciler sıklıkla kullanım kolaylığı (link paylaşımı vs.) için tokenları URL'ye gömerler. Ancak URI verileri, HTTP(S) protokol standartlarına göre "Request Body"si gibi Payload içerisinde gitmez, HTTP başlığının (Request-Line) direkt parçasıdır. SSL/TLS şifrelemesi sunucuya ulaşana kadar trafiği korusa bile, paketin ulaştığı Gateway Proxy, Web Server, ISP router veya VPN cihazları bu URL'leri kalıcı (persistent) log olarak düz metin (plaintext) biçimde yazar.
* **Kurulum ve Çözüm:** `.env` ile dışsallaştırılan token değişkeni, bellek içinde (Environment Variable) tutulur ve güvenli olan `/secure/download` dizininde sadece HTTP Başlıklarından (Header) denetlenir.

---

## 🔎 Adım 2: Adli Bilişim (Forensics & Log Analysis)
URL parametrelerinde gezinen token sızıntısının ispatlanması Forensics (Adli Bilişim) perspektifinden oldukça basittir. 

Saldırgan (veya yetkisiz bir IT çalışanı), Nginx konteynerindeki `access.log` dosyasına eriştiginde olay anını şu şekilde gözlemler:
```text
192.168.1.105 - - [03/Apr/2026:10:45:12 +0000] "GET /vulnerable/download?token=secure_api_key_placeholder HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
```

* 🧠 **Reasoning (Log Maskeleme ve Rotasyon Mantığı):** 
  Sızan log satırlarını tamamen "silmek" Audit (Denetlenebilirlik) ilkelerine aykırıdır. Bunun yerine Nginx üzerindeki `map` direktifi kullanılarak URL'deki Regex alanlarıyla eşleşen kısımlar gizlenir (Log Scrubbing). Böylece olay: `?token=***` formatında iz bırakır fakat veri ifşa olmaz. 
  Ayrıca sızan verilerin gün geçtikçe sunucu depolama alanını doldurup DoS (Denial of Service) zafiyetine yol açmaması adına `nginx/logrotate.conf` ayarı yapılmış ve bu sızıntı dosyalarının 14 ardışık günün sonunda diskten yok edilmesi kurgulanmıştır.

---

## ⚙️ Adım 3: İş Akışları (CI/CD & Secret Management)
Güvenlik ihlallerinin Üretim (Production) ortamına sızmadan durdurulması, "Shift-Left Security" kavramının kalbidir. 

`.github/workflows/semgrep-sast.yml` içerisinde otomatik token sızıntısı tarayıcı bir analiz yapısı barındırır:
* **Webhook Etkileşimi:** Geliştirici kodunu GitHub'a gönderdiği an (Push / Pull Request) bir Trigger (Tetikleyici) eylemi başlar.
* 🧠 **Reasoning (Neden SAST?):**
  Zafiyetin URL seviyesinde (`request.args.get`) kurgulandığını manuel kod incelemelerinde fark edemeyebiliriz. Semgrep `p/python` hedef rotası ile statik bir Abstract Syntax Tree (AST) araması yapar. Bir kural ihlali yakaladığında kodun GitHub üzerine "Merge" edilmesini `Exit 1` koduyla "Kırarak" (Pipeline Fail) engeller. Webhook bu Fail reaksiyonunu takımla anında paylaşarak sorunun canlı ortama (Root Network) gitmesini tamamen engeller.

---

## 🐳 Adım 4: Docker & Network Isolation
Adım adım ilerlettiğimiz Docker tabanlı orkestrasyon (`docker-compose.yml`), zafiyeti kod bazında bitiremediğimiz durumda mimari ile boğmayı hedefler.

* 🧠 **Reasoning 1 (Rootless User 1000 Uygulaması):** Dockerfile içerisinde eklediğimiz `RUN useradd -m -u 1000 appuser` kuralıdır. Konteyner ihlallerinde uygulamanın `root` yetkileri elinden alınır. Saldırgan Remote Code Execution (RCE) bulsa dahi, VM (Sanal Makine) kaçışları veya ana makineye (Host) sıçrama işlemi engellenir.
* 🧠 **Reasoning 2 (Reverse Proxy Header Mitigasyonu):** İki Docker konteyneri arası (Backend ve Nginx) "Isolated Network" iletişimi izolemizidir ancak içeride paket dökümü alan bir Wireshark izleyicisi hala tokenları görebilir. Bu yüzden kurduğumuz **Nginx Reverse Proxy**, dışarıdan gelen `/secure/download?token=XYZ` yapısındaki Query parametresini ağın "Dış Ön Yüzünde" keser (Intercept). Parametreyi kopyalar, güvenli bir `Authorization: Bearer <TOKEN>` Headers katmanına yerleştirir ve API'ya öyle devreder (Token Stripping). Kendi Internal ağında zafiyet oluşmaz.

---

## 🕷️ Adım 5: Tehdit Modelleme (Threat Modeling)
`Token in Query Params` kullanımında sızan Token'in, basit bir zafiyetten **"Account Takeover" (Hesap Ele Geçirme)** noktasına nasıl evrildiğinin tehdit senaryosudur:

1. **Firewall / Proxy İzleri (Man in the Middle Pasif Loglama)**: Kurum ağından (Enterprise Network) çıkan bir kullanıcı, zafiyetli linke tıklar. Sınır Güvenlik Cihazları (Proxy, Gateway vb.) bu giden isteğin şifreli HTTPS olmasına bakmaksızın Domain ve URL kısımlarını loglar. Logları tarayan kötü niyetli bir Admin veya saldırgan, Gateway üzerinden kullanıcının `secure_token_placeholder` parolasını çekip hesabı (Account Takeover) devralır.
2. **Browser Geçmişi (History) Cihaz Gaspı**: Tarayıcılar sadece GET parametrelerini "Browser History" ve "Cache" tablolarına otomatik kaydeder (Çünkü GET HTTP spesifikasyonunda veriyi idempoteant olarak okumak için vardır, state transferi için değil). Başkasının ofisine / masasına giden biri Ctrl+H kısayolu ile URL'nin bütününü görür ve oturum kimliğini gasp eder.

* 🧠 **Reasoning (Çözüm Yaklaşımı ve Sonuç):** 
Uygulamada devreye soktuğumuz Header tabanlı çözüm (`app.py - secure_download metodu`), sunucuyu sadece Authorization HTTP başlığını (Payload içinde gelir, loglanmaz) dezenfekte etmeye zorlar. Üstelik kriptografik olarak `hmac.compare_digest` (Zaman Atağı / Timing Attack Koruması) eşleşmesi yapılarak Account Takeover istismarının kökü kurumuş olur.

---

## 🚀 Kurulum ve Çalıştırma Rehberi (Getting Started)

Projeyi başka bir cihazda sorunsuzca ayağa kaldırmak için aşağıdaki adımları sırasıyla izleyin. Sistem çift katmanlı konteyner (Docker) mimarisine sahip olduğu için yerel makinenize herhangi bir sunucu paketi kurmanıza gerek yoktur. Sadece Docker kurulu olması yeterlidir.

### 1️⃣ Projeyi İndirin (Clone)
Projeyi cihazınıza kopyalamak ve ana dizine girmek için terminalinizde şu komutları çalıştırın:
```bash
git clone https://github.com/begumakyuz/Token_in_Query_Params.git
cd Token_in_Query_Params
```

### 2️⃣ Çevre Değişkenlerini (Environment Variables) Tanımlayın
Uygulamanın şifreleri güvensiz biçimde "Hardcoded" koda gömülmediği için anahtarlarını `.env` dosyası üzerinden okur. Örnek dosyayı kopyalayarak yapıyı aktif hale getirin:
```bash
# Windows (CMD/PowerShell) için:
copy .env.example .env

# macOS / Linux (Terminal) için:
cp .env.example .env
```
*(Dilerseniz `.env` dosyasını editörünüzle açarak test edebilmek için `API_SECRET_KEY` değerini değiştirebilirsiniz).*

### 3️⃣ Docker ile Sistemi Başlatın
Python (Flask) Backend ve Nginx Proxy katmanlarını tek tuşla, Rootless formatında ayağa bağlamak için sistemi derleyin:
```bash
# İmajların derlenmesi ve arkada planda (detached) başlatılması
docker-compose up -d --build

# Sunucuların sorunsuz çalıştığından emin olmak (Log izlemek) için:
docker-compose logs -f
```

### 4️⃣ Zafiyetli ve Güvenli Uç Noktaları Test Edin (API Curl)
Sunucularımız testleri yapmak için `localhost:80` (Nginx) portunda dinlemektedir:

**A) Zafiyetli Uygulamanın Testi (URL Üzerinden):**
```bash
curl "http://localhost/vulnerable/download?token=secure_api_key_placeholder"
```
*(Çıktıda Başarılı cevabı alırsınız. Ancak Docker loglarına bakıldığında adli bilişim kanıtlarını yok etmeyen ama maskeleyen `<Log Scrubbing>` Regex'i çalıştığı için Nginx access loglarında şifrenizi "***" şeklinde görürsünüz).*

**B) Güvenli Mimarinin Testi (Header Üzerinden):**
Zafiyetli URL engellenmiş, trafik güvenli Header yapısına bağlanmıştır:
```bash
curl -H "Authorization: Bearer secure_api_key_placeholder" http://localhost/secure/download
```

### 5️⃣ Otomatik Güvenlik Testlerini (Unit Test / PyTest) Çalıştırın
CI/CD pipeline'ında çalışan siber güvenlik senaryolarını kendi makinenizde manuel çalıştırmak isterseniz (Makinenizde Python olmalıdır):
```bash
# Python kütüphanelerinin (Flask, PyTest vb.) kurulması
pip install -r requirements.txt

# Yazılan güvenlik doğrulama testlerinin tetiklenmesi
pytest tests/
```
