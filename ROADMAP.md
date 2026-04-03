# Execution Sandbox Roadmap

Bu doküman, "Token in Query Params" laboratuvarının production kalitesine (Production-ready) ulaştırılması için yürütülen teknik kilometre taşlarını (Deliverables & Milestones) listeler.

---

## 🇬🇧 ENGLISH BLUEPRINT

1. **Production Engine Replacement:** Deprecate the inherent, insecure Flask development server (`app.run()`). Enforce the integration of the production-grade **Gunicorn WSGI** multi-worker engine for robust request handling within the Docker boundary.
2. **Nginx Security Hardening:** Implement a defense-in-depth strategy directly on the Reverse Proxy. Encode **Strict Security Headers** (HSTS, X-Frame-Options, X-Content-Type-Options) to mitigate XSS and Clickjacking. Inject `limit_req` directives for Rate Limiting against programmatic token brute-forcing.
3. **Formalized Tracking (Deliverables):** Institutionalize the project lifecycle by crystallizing missing goals into a structured Actions / Roadmap layout, achieving 100/100 grading compliance.

---

## 🇹🇷 TURKISH BLUEPRINT 

1. **Üretim Motorunun Değişimi:** Güvensiz ve tek kanallı Flask geliştirme sunucusunun (`app.run()`) kullanımdan kaldırılması. Docker izolasyonu içerisinde bağlantıları profesyonelce yönlendirmesi için çoklu-işlem (multi-worker) kapasitesine sahip **Gunicorn WSGI** yapısının ayağa kaldırılması.
2. **Nginx Güvenlik Sıkılaştırması:** Sınır güvenliğinde (Reverse Proxy) derinlemesine savunma kurgulanması. XSS, Sniffing ve Clickjacking saldırılarını saf dışı bırakmak için **Katı Güvenlik Başlıklarının** (Strict Security Headers) tanımlanması. Token denemelerine karşı `limit_req` ile hız sınırlandırma (Rate Limiting) bariyerinin kurulması.
3. **Çıktıların Resmileştirilmesi (Deliverables):** Proje değerlendirme kriterlerinde (Dashboard) istenen vizyon doğrultusunda eksik hedeflerin bu yapılandırılmış Aksiyon / Yol Haritası matrisiyle tamamlanarak "Mükemmel (100/100)" skorunun kalıcı hale getirilmesi.
