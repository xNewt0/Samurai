# Samurai — Domain Reconnaissance & Dork Scanner

**Samurai**, hedef bir domain için açık kaynak OSINT tabanlı URL havuzu toplar ve dork/wordlist eşleştirmesi ile potansiyel hassas endpoint’leri sınıflandırır.  
Wayback Machine, HackerTarget ve AlienVault OTX gibi kaynaklardan URL/Subdomain verisi çekerek tek bir havuzda birleştirir ve sonuçları **CRITICAL / HIGH / NORMAL** seviyelerinde raporlar.

---

## Özellikler

- URL harvesting:
  - Wayback Machine (CDX)
  - HackerTarget hostsearch
  - AlienVault OTX URL list
- Akıllı filtreleme:
  - Statik dosyaları (js/css/png vb.) otomatik eler
  - Assets/static/vendor gibi path’leri dışarıda bırakır
- Dork eşleştirme:
  - `inurl:` / `filetype:` / `ext:` destekli
  - Düşük kaliteli gürültüyü azaltmak için stopword filtresi
- Severity sınıflandırma:
  - **CRITICAL**: `.env`, `.sql`, `.bak`, `wp-config`, `.git` vb.
  - **HIGH**: admin/login/config/dashboard/backup/upload gibi sıcak terimler
- Raporlama:
  - HTML (varsayılan)
  - JSON
  - TXT

---

## Kurulum

Python 3.8+ önerilir.

```bash
pip install -r requirements.txt
```

## Kullanım
```
python3 samurai.py -d example.com -w dorks.txt -o report.html
python3 samurai.py -d example.com -w dorks.txt -t 25
python3 samurai.py -d example.com -w dorks.txt -v ```





