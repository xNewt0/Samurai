<div align="center">

# 侍 Samurai
### Domain Reconnaissance & Dork Scanner

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
- [Konfigürasyon (Opsiyonel)](#konfigürasyon-opsiyonel)
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
   - `.env`, `.sql`, `.bak`, `wp-config`, `.git` vb. sinyalleri öne çıkarır.
5. **Raporlama**
   - **HTML (varsayılan)**, JSON veya TXT rapor üretir.

---

## Özellikler
- ✅ Multi-source OSINT URL havuzu (Wayback / HackerTarget / OTX)
- ✅ Gürültü azaltma (static extension + path filtreleri + stopwords)
- ✅ Performans odaklı eşleştirme (URL token index + ext index)
- ✅ Severity: **CRITICAL / HIGH / NORMAL**
- ✅ Rapor formatları: **HTML / JSON / TXT**
- ✅ HTML raporda arama + severity filtreleme
- ✅ Kolay kullanım: `-w` opsiyonel, dahili geniş dork seti

---

## Veri Kaynakları
- **Wayback Machine (CDX)** — arşiv URL’leri
- **HackerTarget (hostsearch)** — subdomain sinyali
- **AlienVault OTX** — URL listeleri

> Not: Bazı servisler rate-limit / kota uygulayabilir.

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

### En kolay kullanım (dahili dorks + otomatik HTML rapor)
```bash
python3 samurai.py -d example.com
```

### Kendi wordlist’in ile
```bash
python3 samurai.py -d example.com -w dorks.txt
```

### Thread sayısını arttırma
```bash
python3 samurai.py -d example.com -t 50
```

### JSON/TXT rapor
```bash
python3 samurai.py -d example.com --format json
python3 samurai.py -d example.com --format txt
```

### Report’u stdout’a bas (pipeline)
```bash
python3 samurai.py -d example.com --format json -o -
```

### Kaynakları kapatma (örn: sadece Wayback)
```bash
python3 samurai.py -d example.com --no-otx --no-hackertarget
```

---

## Parametreler

| Parametre | Açıklama | Varsayılan |
|---|---|---|
| `-d, --domain` | Hedef domain (örn: `example.com`) | **zorunlu** |
| `-w, --wordlist` | Dork/wordlist dosyası (opsiyonel) | dahili liste |
| `-t, --threads` | Eşleştirme thread sayısı (1–200) | `30` |
| `-o, --output` | Output dosyası (veya `-` → stdout) | otomatik isim |
| `--format` | `html` / `json` / `txt` | `html` |
| `--no-report` | Rapor yazma | kapalı |
| `-v, --verbose` | Detaylı log | kapalı |
| `-q, --quiet` | Minimal çıktı | kapalı |
| `--no-color` | ANSI renk kapat | kapalı |
| `--version` | Versiyon yazdır ve çık | kapalı |
| `--timeout` | HTTP timeout (sn) | `30` |
| `--retries` | HTTP retry sayısı | `2` |
| `--backoff` | Retry backoff (sn) | `0.7` |
| `--max-urls` | Havuz maksimum URL | `75000` |
| `--wayback-limit` | Wayback CDX limit | `50000` |
| `--otx-pages` | OTX sayfa sayısı (500/page) | `3` |
| `--no-wayback` | Wayback kapat | kapalı |
| `--no-hackertarget` | HackerTarget kapat | kapalı |
| `--no-otx` | OTX kapat | kapalı |
| `--no-ext-filter` | Static ext filtresi kapat | kapalı |
| `--no-path-filter` | Path filtresi kapat | kapalı |
| `--no-stopwords` | Stopwords filtresi kapat | kapalı |
| `--resolve-subdomains` | Subdomain’leri DNS resolve edip ekle | kapalı |
| `--config` | JSON config ile filtreleri override et | kapalı |

---

## Konfigürasyon (Opsiyonel)
Bazı filtreleri dışarıdan yönetmek için `--config` ile JSON dosyası verebilirsin.

Örnek `config.json`:
```json
{
  "banned_ext": [".png", ".jpg", ".css", ".js"],
  "banned_path": ["/assets/", "/static/", "/vendor/"],
  "stopwords": ["the", "and", "www", "http", "https"],
  "crit_patterns": [".env", "wp-config", ".git", ".sql", ".bak"],
  "hot_keywords": ["admin", "login", "swagger", "graphql", "config"]
}
```

Kullanım:
```bash
python3 samurai.py -d example.com --config config.json
```

---

## Çıktılar (Raporlar)

### HTML (Varsayılan)
- Arama kutusu + severity filtreleri
- Tek dosya rapor

### JSON
- Otomasyon/pipeline için uygun
- `results[]` içinde URL bazlı `hits[]` (eşleşen dork/term/type)

### TXT
- CRITICAL/HIGH/NORMAL bölümlere ayrılmış çıktı

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
```

> İpucu: Çok genel dork’lar gürültüyü arttırır. Hedefe göre listeyi özelleştirmek en iyi sonuç verir.

---

## Notlar & Limitler
- Bazı servisler (özellikle ücretsiz endpoint’ler) rate-limit uygulayabilir.
- Çıktılar “potansiyel” bulgudur; doğrulama (manual/automated) gerektirir.
- Filtreler noise azaltır; gerektiğinde `--no-*-filter` ile kapatılabilir.

---

## Güvenlik / Yasal Uyarı
Bu araç yalnızca **yetkili olduğunuz** sistemlerde güvenlik testi ve OSINT amaçlı kullanılmalıdır.  
Yetkisiz kullanım yasa dışı olabilir. Kullanım sorumluluğu kullanıcıya aittir.

---

## License
MIT — detaylar için: [LICENSE](./LICENSE)
