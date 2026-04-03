# 🛡️ L14 - Token in Query Params (Python/Flask) Analiz ve Çözüm Projesi

Bu proje, "Token in Query Params" (Yetkilendirme verisinin URL parametreleriyle iletilmesi) zafiyetinin **Flask tabanlı (app.py)** bir Python uygulamasında nasıl analiz edileceğini ve yapılandırmalardan temizleneceğini gösteren profesyonel bir Konsept Kanıtıdır.

Aşağıdaki 5 Adım, projenin güvenlik kriterlerine birebir eşleşmektedir:

## 🛠️ Adım 1: Kurulum & Kod Analizi (Reverse)
Projeye dahil olan uygulamanın statik dosyaları (özellikle `app.py`) incelendiğinde zafiyetin kalbi ortaya çıkar.
Kötü niyetli kullanımda `request.args.get('token')` metodu, gizli anahtarı doğrudan URL'nin bir parçası olarak arar.

**Misconfiguration Analizi:**
- `app.py` içerisindeki `/vulnerable/download` uç noktası tasarımı, yetki objesini (Token) URL parametrelerine gömmüştür.
- Bu veriler URL'de olduğu için Proxy, ISP ve ara ağ izleyicileri tarafından açık şekilde görülür. 
- Gerçek dünyada hassas yapılandırma verileri (`SECURE_TOKEN`, `API_KEY`) hiçbir zaman kodun içine hardcode edilmez. Bu projedeki `.env` dosyamız sayesinde, Docker'daki Environment Variables olarak geçilip bellekte güvenle tutulur. Çözüm olan `/secure/download` dizininde URL parametreleri reddedilir.

## 🔎 Adım 2: Adli Bilişim (Forensics & Log Analysis)
URL parametrelerindeki tokenin "gerçek" bir ortama sızdığını ispatlamak Forensics açısından en iyi göstergedir.

Saldırgan, Nginx konteynerindeki `access.log` dosyasına düştüğünde URL zafiyetini (sızıntısını) saniye saniye görür:
```text
192.168.1.105 - - [03/Apr/2026:10:45:12 +0000] "GET /vulnerable/download?token=secure_api_key_placeholder HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
```

**Sızıntıyı Temizleme: Log Scrubbing & Log Rotate İspatı:**
Sistemi log sızıntılarından kurtarmak hayati önem taşır.
1. **Log Scrubbing**: Nginx'e yazdığımız Regex tabanlı `map` kuralıyla (`nginx.conf`) bu alan artık loglara `?token=***` formatında, tamamen maskelenmiş şekilde düşer.
2. **Log Rotate**: Ancak geçmişte kalan sızıntılı logları sonsuza dek tutamayız. İşte bu yüzden projede yer alan `nginx/logrotate.conf` ayarı devreye girer. Disk doluluğunu azaltıp logları compress (sıkıştırarak) saklar ve 14 ünün ardından otomatik yok eder.

## ⚙️ Adım 3: İş Akışları (CI/CD & Secret Management)
DevSecOps prensiplerinde, geliştiricilerin zafiyetli kod (`request.args.get('token')`) yazmasını üretim aşamasında durdurmak gerekir.

Bunun için `.github/workflows/semgrep-sast.yml` hazırlandı. Geliştirici kodunu GitHub'a Pushladığında:
- GitHub, CI/CD sunucusuna bir **Webhook** isteği yollayıp Pipeline'ı başlatır.
- `Static Analysis` aracı olan Semgrep devreye girip, statik Python (Flask) kodlarını tarar. Eğer URL üzerinden Token sızıntısı sağlayan bir kural (misconfiguration) ihlali varsa `Exit 1` kodu fırlatarak Webhook cevabını değiştirir.
- Bu Webhook, ana dallara yapılacak riskli Merge (PR) işlemlerini kalıcı olarak bloke eder.

## 🐳 Adım 4: Docker & Network Isolation
Adım adım ilerlettiğimiz Docker ve Docker Compose ağ yapılandırması güçlü bir yalıtım sağlar.

* **Rootless Docker (USER 1000)**: Proje kökündeki `Dockerfile` incelendiğinde sunucunun `root` olarak çalışmadığını görürüz. `RUN useradd -m -u 1000 appuser` kısıtlaması, Konteyneri dışarı sızmalara karşı güvenceye alır.
* **Internal Network Sızıntısı**: URL'de dolaşan tokenlar; `docker-compose.yml` içindeki sadece iki konteynerin oluşturduğu o dar alanda (Internal Network) dolaşırken dahi side-car konteynerlerine sızar.
* **Nginx'in Header Taşıyıcılığı (Token Stripping)**: Nginx (Reverse Proxy) katmanı URL'de gelen tokeni yakalayıp alır, dışarıya ve sunucu trafiğinde bunu paramdan siler (strip eder) ve sadece güvenli `Authorization: Bearer <TOKEN>` başlığı olarak ana sunucuya taşır.

## 🕷️ Adım 5: Tehdit Modelleme (Threat Modeling)
`Token in Query Params` kullanımında sızan şifreler, basit bir zafiyeti nasıl bir **"Account Takeover" (Hesap Ele Geçirme)** saldırısına evriltebileceğini Threat Modeling belgemizde (`docs/Threat_Model.md`) görebilirsiniz:

1. **Firewall Log Sızıntısı**: Çalışanın indirdiği zafiyetli sayfa NGFW/IDS cihazlarında loglanırken token'ı Gateway açık biçimiyle ele verir, analist olan tehdit aktörü bunu kopyalayıp kurbanın hesabına el koyar.
2. **Browser Geçmişi (History)**: Aynı PC'ye erişen bir iç tehdit objesi, tarayıcı geçmişinin POST bodyleri aksine GET parametrelerini barındırdığını bilerek "Geçmiş" dizinlerinden token'ı çekip hesabın haklarını (Account Takeover) devralır.

**Mimarinin Getirdiği Çözüm (Code Snippet)**
Sadece HTTP Header tabanlı Token Kabulünü zorlayan (app.py) yapı:
```python
@app.route('/secure/download', methods=['GET'])
def secure_download():
    # Sadece Header verisi analiz edilir (Adım 5 Zafiyet Çözümü)
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    token = auth_header.split(" ")[1]
    if hmac.compare_digest(token, VALID_TOKEN):
        return jsonify({"message": "Secure Login Success", "data": "CONFIDENTIAL"})
```

---

## 🏃 Testler ve Çalıştırma Yönergeleri
Projede her bir dosya yapılandırıldı:
1. Adım: `.env.example` dosyasını `.env` olarak değiştirin ve anahtar atanmasını yapın.
2. Adım: Projeyi ayağa kaldırın:
```bash
docker-compose up -d --build
```

**✅ Yazılan Kodlara Yönelik Unit Testler:**
`tests/test_app.py` üzerinde zafiyetli ve güvenli yolların tespit edildiği PyTest altyapısı vardır. Çalıştırmak için:
```bash
pip install -r requirements.txt
pytest tests/
```
