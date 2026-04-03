# L14 Token in Query Params Bypass - Tehdit Modeli (Account Takeover)

Bu doküman, sistemde kritik yetkilendirme (Authorization) nesnelerinin "Query Parametreleri" kullanılarak iletilmesinin sebep olabileceği **Account Takeover (Hesap Devralma)** ihlalini "Siber Tehdit Modellemesi" standartlarında analiz eder.

## Tehdit Vektörü (Threat Vector)
Kurumsal bir çalışanın özel bir serviste oturum açarken veya gizli bir belgeyi (ör: finansal rapor) indirirken URL tabanlı kimlik denetimi kullanması.
**Zafiyetli Link:** `http://hr.corp/vulnerable/download?token=secure_api_key_placeholder`

## Saldırı Senaryosu (Information Disclosure -> Account Takeover)
Yukarıdaki istek sunucuyla başarılı şekilde konuşup dönecektir ancak URL'nin yapısı gereği bu işlem saniyeler içinde üç farklı rotada siber sızıntıya neden olur:

### 1. Firewall Loglarında Sızıntı (Gateway Intercept)
Şirketlerin iç ağlarını korumak için kullandıkları **Next-Gen Firewall (NGFW)**, IDS/IPS cihazları veya SSL Inspection cihazları, trafiği şifreli (TLS) olsa bile araya girip URL'i çözer ve kaydeder. Cihaza log okuma için gelen kötü niyetli bir veri güvenliği analisti, süzdüğü URI değerlerinden tokenı ele geçirir ve hesabı kopyalayarak yetkili bir Account Takeover gerçekleştirir.

### 2. Browser Geçmişi Sızıntısı (Physical Proxy)
Web tarayıcılarındaki "Browser History" ve "Cache" dosyaları, POST bodyleri aksine URL'leri düz metin (plaintext) biçimde saniye saniye kaydeder. Hedefin cihazına erişim sağlayan (Kilit ekranı hatası, veya Remote Execution gibi) bir tehdit aktörü tarayıcı dizinini kazırsak "token: XXX" parolasını zahmetsizce elde eder, hedef cihazdan uzaklaşsa bile kendi bilgisayarında token ile hesabı ele geçirebilir.

### 3. HTTP Referer (3rd Party Leak)
Token içeren HTML sayfasında dışarıya dönük tek bir görsel, tek bir Google Analytics / CDN scripti var ise, kullanıcının tarayıcısı bu scripti yüklemek için 3. partilere bağlanırken `Referer` başlığı olarak o an bulunduğu sayfanın URL'sini boylu boyunca paketler ve gönderir.

## Mimari Çözüm ve Mitigasyon (Sıkılaştırma)
Sistem tasarımları gereği, Yetkilendirme tokenlarının "Header" içinde gönderilmesi endüstri standardıdır. `app/server.js` dosyasında yazılan kod; HTTP katmanını sadece `Authorization: Bearer <TOKEN>` yapısıyla iletişime zorlamaktadır.

Böylelikle Nginx ve Firewall günlüklerinde sadece hedef dizin "GET /secure/download" yazar, içindeki yetki belgesi logların dışına itilmiş olur.
