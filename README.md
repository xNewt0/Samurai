<div align="center">

# 侍 Samurai
### Domain Reconnaissance & Dork Scanner

<!-- Badges -->
<p>
  <a href="https://github.com/xNewt0/Samurai/stargazers">
    <img alt="Stars" src="https://img.shields.io/github/stars/xNewt0/Samurai?style=for-the-badge">
  </a>
  <a href="https://github.com/xNewt0/Samurai/network/members">
    <img alt="Forks" src="https://img.shields.io/github/forks/xNewt0/Samurai?style=for-the-badge">
  </a>
  <a href="https://github.com/xNewt0/Samurai/issues">
    <img alt="Issues" src="https://img.shields.io/github/issues/xNewt0/Samurai?style=for-the-badge">
  </a>
  <a href="https://github.com/xNewt0/Samurai/blob/main/LICENSE">
    <img alt="License" src="https://img.shields.io/github/license/xNewt0/Samurai?style=for-the-badge">
  </a>
</p>

<p>
  <img alt="Python" src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <img alt="OSINT" src="https://img.shields.io/badge/OSINT-Recon-111827?style=for-the-badge">
  <img alt="Reports" src="https://img.shields.io/badge/Reports-HTML%20%7C%20JSON%20%7C%20TXT-111827?style=for-the-badge">
</p>

**Samurai**, hedef bir domain için OSINT kaynaklarından URL/Subdomain havuzu toplar ve dork/wordlist eşleştirmesi ile potansiyel hassas endpoint’leri **CRITICAL / HIGH / NORMAL** olarak sınıflandırır.

</div>

---

## İçindekiler
- [Neler Yapar?](#neler-yapar)
- [Özellikler](#özellikler)
- [Veri Kaynakları](#veri-kaynakları)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
- [Parametreler](#parametreler)
- [Çıktılar (Raporlar)](#çıktılar-raporlar)
- [Örnek Wordlist / Dorks](#örnek-wordlist--dorks)
- [Notlar & Limitler](#notlar--limitler)
- [Güvenlik / Yasal Uyarı](#güvenlik--yasal-uyarı)
- [License](#license)

---

## Neler Yapar?
1. **URL/Subdomain Harvesting (OSINT)**
   - Birden fazla kaynaktan URL ve subdomain sinyali çekip tek havuzda birleştirir.
2. **Akıllı Filtreleme**
   - Statik dosyaları (js/css/png vb.) ve düşük değerli path’leri eler.
3. **Dork / Wordlist Eşleştirme**
   - `inurl:` / `filetype:` / `ext:` gibi kalıpları destekler.
4. **Severity Sınıflandırma**
   - `.env`, `.sql`, `.bak`, `wp-config`, `.git` gibi bulguları öne çıkarır.
5. **Raporlama**
   - **HTML (varsayılan)**, JSON veya TXT rapor üretir.

---

## Özellikler
- ✅ Multi-source OSINT URL havuzu
- ✅ Noise azaltma (stopwords + statik dosya filtreleri)
- ✅ Thread’li eşleştirme (hızlı tarama)
- ✅ Severity: **CRITICAL / HIGH / NORMAL**
- ✅ Çıktı formatları: **HTML / JSON / TXT**
- ✅ Terminalde renkli özet ve ön izleme

---

## Veri Kaynakları
Samurai aşağıdaki kaynaklardan veri toplar:

- **Wayback Machine (CDX)** — arşiv URL’leri
- **HackerTarget (hostsearch)** — subdomain sinyali
- **AlienVault OTX** — URL listeleri

> Not: Bazı servislerin rate-limit / kota limitleri olabilir.

---

## Kurulum

> Python **3.8+** önerilir.

```bash
git clone https://github.com/xNewt0/Samurai.git
cd Samurai
pip install -r requirements.txt
```

**requirements.txt**
- `requests`
- `fake-useragent`

---

## Kullanım

### Hızlı Başlangıç
```bash
python3 samurai.py -d example.com -w dorks.txt
```

### Thread Sayısını Arttırma
```bash
python3 samurai.py -d example.com -w dorks.txt -t 50
```

### HTML Rapor Alma
```bash
python3 samurai.py -d example.com -w dorks.txt -o report.html
```

### JSON / TXT Rapor Alma
```bash
python3 samurai.py -d example.com -w dorks.txt -o report.json
python3 samurai.py -d example.com -w dorks.txt -o report.txt
```

---

## Parametreler

| Parametre | Açıklama | Varsayılan |
|---|---|---|
| `-d, --domain` | Hedef domain (örn: `example.com`) | zorunlu |
| `-w, --wordlist` | Dork/wordlist dosyası | zorunlu |
| `-t, --threads` | Thread sayısı (1–200 arası clamp) | `30` |
| `-o, --output` | Çıktı dosyası (`.html` / `.json` / `.txt`) | HTML |
| `-v, --verbose` | Detaylı log | kapalı |

---

## Çıktılar (Raporlar)

### HTML (Varsayılan)
- Modern, okunur tek dosya rapor
- CRITICAL/HIGH/NORMAL sayıları ile özet
- Link’ler tıklanabilir

### JSON
- Otomasyon / pipeline için uygun
- `summary` + `results[]` yapısı

### TXT
- Hızlı paylaşım / terminal-friendly çıktı

---

## Örnek Wordlist / Dorks

Samurai `inurl`, `filetype`, `ext` benzeri yaklaşımları destekler.

Örnek `dorks.txt`:
```txt
inurl:admin
inurl:login
inurl:dashboard
inurl:config
inurl:backup
inurl:upload
filetype:env
filetype:sql
filetype:log
ext:bak
intitle:"index of"
```

> İpucu: Çok genel dork’lar gürültüyü arttırır. Hedefe göre listeyi özelleştirmek en iyi sonuç verir.

---

## Notlar & Limitler
- Bazı servisler (özellikle ücretsiz endpoint’ler) rate-limit uygulayabilir.
- Çıktılar “potansiyel” bulgudur; doğrulama (manual/automated) gerektirir.
- Statik dosya ve bazı path’ler filtrelenir (noise azaltmak için).

---

## Güvenlik / Yasal Uyarı
Bu araç yalnızca **yetkili olduğunuz** sistemlerde güvenlik testi ve OSINT amaçlı kullanılmalıdır.  
Yetkisiz kullanım yasa dışı olabilir. Kullanım sorumluluğu kullanıcıya aittir.

---

## License
MIT — detaylar için: [LICENSE](./LICENSE)
