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
  <img alt="Report" src="https://img.shields.io/badge/Reports-HTML%20%7C%20JSON%20%7C%20TXT-111827?style=for-the-badge">
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
