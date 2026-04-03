# L14 Token in Query Params Bypass - Tehdit Modeli (Information Disclosure)

Bu belge, sistemde taşınan "Token" değerlerinin Query Params üzerinden geçirilmesi sonucunda ne tür tehdit vektörleri oluştuğunu analiz eder.

## Saldırı Senaryosu (Information Disclosure)

Kurumsal bir firmada çalışan "Alice", maaş bordrosunu indirmek için tıklamaktadır:  
`http://localhost/vulnerable/download?token=1337`

Bu esnada "1337" parolası aşağıdaki yollarla saldırganın veya dış üçüncü şahısların eline geçer:

### 1. Proxy Önbelleği (Cache) & Firewall Logları
Şirketin çıkışını sağlayan `Fortinet/Palo Alto` firewall cihazları ya da proxy sunucuları aradaki trafiği analiz etmese bile URL dizilimini kaydeder. Cihaza erişen bir analist token'ı kolayca ele geçirir. Bu senaryo "Geniş Ağ Sızıntısı" olarak bilinir.

### 2. Browser Geçmişi (History)
Makinesini kilitlemeden kalkan bir kullanıcının ardından bilgisayara geçen biri direkt olarak `Chrome->History` menüsünden URL'i ve oradaki `1337` şifresini düz metin görebilir.

### 3. HTTP Referer Sızıntısı
Olayın yaşandığı HTML sayfasında dış bir siteye (ör: Analytics) link/resim varsa, dış sitenin sunucusu bu URL'i `Referer` başlığı üzerinden aynen elde eder. Yani `1337` parolası kontrolümüz dışı bir 3. parti siteye gitmiş olur.

## Çözüm Önerisi ve Uygulama
Node.js (Backend) ve Nginx (Reverse Proxy) üzerinden `Header-Based Authentication`a geçilmiş, URL içindeki token temizlenmiş (Stripping) ve API üzerinden güvenli hale çekilmiştir.
- `app/server.js` modülünde `/secure/download` inceleyiniz.
