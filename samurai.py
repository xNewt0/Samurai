#!/usr/bin/env python3
import argparse

import json
import os
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION = "1.1"

BANNER = r"""
   ▄████████    ▄████████   ▄▄▄▄███▄▄▄▄   ███    █▄     ▄████████    ▄████████  ▄█  
  ███    ███   ███    ███ ▄██▀▀▀███▀▀▀██▄ ███    ███   ███    ███   ███    ███ ███  
  ███    █▀    ███    ███ ███   ███   ███ ███    ███   ███    ███   ███    ███ ███▌ 
  ███          ███    ███ ███   ███   ███ ███    ███  ▄███▄▄▄▄██▀   ███    ███ ███▌ 
▀███████████ ▀███████████ ███   ███   ███ ███    ███ ▀▀███▀▀▀▀▀   ▀███████████ ███▌ 
         ███   ███    ███ ███   ███   ███ ███    ███ ▀███████████   ███    ███ ███  
   ▄█    ███   ███    ███ ███   ███   ███ ███    ███   ███    ███   ███    ███ ███  
 ▄████████▀    ███    █▀   ▀█   ███   █▀  ████████▀    ███    ███   ███    █▀  █▀   
                                                       ███    ███                   
"""


class Colors:
    R = '\033[91m'
    G = '\033[92m'
    Y = '\033[93m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    W = '\033[97m'
    D = '\033[90m'
    BOLD = '\033[1m'
    RST = '\033[0m'
    BG_R = '\033[41m'
    BG_Y = '\033[43m'
    BG_G = '\033[42m'


BANNED_EXT = (
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp4', '.mp3', '.avi',
    '.mov', '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx',
    '.csv', '.xml', '.map', '.min.js'
)

BANNED_PATH = (
    '/assets/', '/static/', '/wp-content/themes/', '/wp-includes/js/',
    '/node_modules/', '/bower_components/', '/cache/', '/tmp/',
    'jquery', 'bootstrap', 'fontawesome', '/lib/', '/vendor/', '/images/'
)

STOPWORDS = {
    'the', 'and', 'for', 'of', 'to', 'in', 'is', 'on', 'at', 'by', 'my',
    'web', 'www', 'com', 'net', 'org', 'http', 'https', 'html', 'htm',
    'site', 'url', 'file', 'index', 'page', 'home', 'default', 'main'
}

CRIT_EXT = (
    '.env', '.sql', '.log', '.bak', '.old', '.config', '.ini',
    '.db', '.dat', '.pem', '.key', '.secret', 'wp-config', '.zip', '.rar',
    '.tar', '.gz', '.7z', 'passwd', 'shadow', '.htpasswd', '.git'
)

WEAK_EXT = ('.html', '.htm', '.php', '.asp', '.aspx', '.jsp')

HOT_KEYWORDS = (
    'admin', 'login', 'user', 'dashboard', 'config', 'test', 'backup',
    'shell', 'upload', 'panel', 'auth', 'account', 'member', 'db',
    'database', 'install', 'setup', 'beta', 'dev', 'prod', 'staging',
    'secret', 'token', 'api', 'debug', 'monitor', 'manage', 'console',
    'private', 'internal', 'staff', 'root', 'system', 'server'
)

SEV_MAP = {"CRITICAL": 3, "HIGH": 2, "NORMAL": 1}

DEFAULT_DORKS = [
    "inurl:admin", "inurl:login", "inurl:admin/login", 
    "inurl:cpanel", "inurl:phpmyadmin", "inurl:wp-admin",
    "filetype:log", "filetype:env", "filetype:sql",
    "filetype:bak", "filetype:old", "inurl:config",
    "index of /", "intitle:\"index of\"", "inurl:dashboard",
    "inurl:shell", "inurl:upload", "inurl:passwd",
    "site:github.com password", "site:pastebin.com password"
]


def banner():
    print(f"{Colors.R}{Colors.BOLD}{BANNER}{Colors.RST}")
    print(f"{Colors.D}{'─' * 78}{Colors.RST}")
    print(f"{Colors.W}  ► Domain Reconnaissance & Dork Scanner{Colors.RST}  {Colors.D}│{Colors.RST}  {Colors.Y}v{VERSION}{Colors.RST}")
    print(f"{Colors.D}{'─' * 78}{Colors.RST}\n")


def log_info(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"{Colors.D}[{ts}]{Colors.RST} {Colors.C}[*]{Colors.RST} {msg}")


def log_ok(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"{Colors.D}[{ts}]{Colors.RST} {Colors.G}[+]{Colors.RST} {Colors.G}{msg}{Colors.RST}")


def log_warn(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"{Colors.D}[{ts}]{Colors.RST} {Colors.Y}[!]{Colors.RST} {Colors.Y}{msg}{Colors.RST}")


def log_err(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"{Colors.D}[{ts}]{Colors.RST} {Colors.R}[X]{Colors.RST} {Colors.R}{msg}{Colors.RST}")


def log_crit(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"{Colors.D}[{ts}]{Colors.RST} {Colors.BG_R}{Colors.W} KRİTİK {Colors.RST} {Colors.R}{msg}{Colors.RST}")


def log_high(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"{Colors.D}[{ts}]{Colors.RST} {Colors.BG_Y}{Colors.W} YÜKSEK {Colors.RST} {Colors.Y}{msg}{Colors.RST}")


def log_norm(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"{Colors.D}[{ts}]{Colors.RST} {Colors.D}[BİLGİ]{Colors.RST} {msg}")


def usage():
    print(f"""
{Colors.Y}KULLANIM:{Colors.RST}
  python3 samurai.py -d <domain> -w <wordlist> [seçenekler]

{Colors.Y}ZORUNLU:{Colors.RST}
  -d, --domain     Hedef domain (örnek: example.com)
  -w, --wordlist   Dork/wordlist dosyası

{Colors.Y}OPSİYONEL:{Colors.RST}
  -t, --threads    Thread sayısı (varsayılan: 30)
  -o, --output     Çıktı dosyası (html/json/txt)
  -v, --verbose    Detaylı çıktı
  -h, --help       Bu yardım mesajını göster

{Colors.Y}ÖRNEKLER:{Colors.RST}
  {Colors.G}python3 samurai.py -d example.com -w dorks.txt{Colors.RST}
  {Colors.G}python3 samurai.py -d target.org -w dorks.txt -t 50{Colors.RST}
  {Colors.G}python3 samurai.py -d site.net -w dorks.txt -o rapor.html{Colors.RST}
""")


def check_deps():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append('requests')
    try:
        from fake_useragent import UserAgent
    except ImportError:
        missing.append('fake-useragent')

    if 'requests' in missing:
        log_err(f"Eksik paketler: {', '.join(missing)}")
        print(f"\n{Colors.Y}Çözüm:{Colors.RST} pip install requests")
        sys.exit(1)

    return requests, UserAgent


def load_wordlist(path=None):
    if not path:
        return DEFAULT_DORKS

    if not os.path.exists(path):
        log_err(f"Dosya bulunamadı: {path}")
        print(f"\n{Colors.Y}Kontrol edin:{Colors.RST}")
        print(f"  • Dosya yolu doğru mu?")
        print(f"  • Dosya mevcut mu?")
        sys.exit(1)

    if not os.path.isfile(path):
        log_err(f"Bu bir dosya değil: {path}")
        sys.exit(1)

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [ln.strip() for ln in f if len(ln.strip()) > 2]
    except PermissionError:
        log_err(f"Dosya okuma izni yok: {path}")
        sys.exit(1)
    except Exception as e:
        log_err(f"Dosya okunamadı: {e}")
        sys.exit(1)

    if not lines:
        log_err("Wordlist boş veya geçersiz")
        print(f"\n{Colors.Y}Not:{Colors.RST} Wordlist en az 3 karakterli satırlar içermeli")
        sys.exit(1)

    return lines


class Engine:
    def __init__(self, threads=30, verbose=False):
        requests, UserAgent = check_deps()
        self.requests = requests
        self.threads = max(1, min(threads, 200))
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'Accept-Language': 'en-US,en;q=0.9'})
        try:
            self.ua = UserAgent()
        except Exception:
            self.ua = None
        self.pool = set()
        self.stop = threading.Event()
        self.stats = {'wayback': 0, 'hackertarget': 0, 'alienvault': 0}

    def _headers(self):
        ua = self.ua.random if self.ua else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
        return {'User-Agent': ua}

    def is_valid(self, url):
        if not url or len(url) < 10:
            return False
        low = url.lower().split('?')[0]
        if low.endswith(BANNED_EXT):
            return False
        for kw in BANNED_PATH:
            if kw in low:
                return False
        return True

    def fetch_wayback(self, domain):
        if self.stop.is_set():
            return
        log_info("Wayback Machine taranıyor...")
        api = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&filter=statuscode:200&limit=50000"
        try:
            r = self.session.get(api, headers=self._headers(), timeout=60)
            if r.status_code == 200:
                cnt = 0
                for ln in r.text.splitlines():
                    if self.stop.is_set():
                        break
                    u = ln.strip()
                    if self.is_valid(u):
                        self.pool.add(u)
                        cnt += 1
                self.stats['wayback'] = cnt
                log_ok(f"Wayback Machine: {cnt} URL toplandı")
            else:
                log_warn(f"Wayback yanıt kodu: {r.status_code}")
        except self.requests.exceptions.Timeout:
            log_warn("Wayback zaman așımı (60s)")
        except self.requests.exceptions.ConnectionError:
            log_warn("Wayback bağlantı hatası")
        except Exception as e:
            if self.verbose:
                log_warn(f"Wayback hatası: {e}")

    def fetch_hackertarget(self, domain):
        if self.stop.is_set():
            return
        log_info("HackerTarget API taranıyor...")
        api = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            r = self.session.get(api, headers=self._headers(), timeout=30)
            if "API count exceeded" in r.text:
                log_warn("HackerTarget API limiti aşıldı")
                return
            cnt = 0
            for ln in r.text.splitlines():
                if self.stop.is_set():
                    break
                p = ln.split(',')
                if p and p[0]:
                    sub = p[0].strip()
                    if sub and '.' in sub:
                        self.pool.add(f"http://{sub}")
                        self.pool.add(f"https://{sub}")
                        cnt += 1
            self.stats['hackertarget'] = cnt
            log_ok(f"HackerTarget: {cnt} subdomain bulundu")
        except self.requests.exceptions.Timeout:
            log_warn("HackerTarget zaman aşımı")
        except Exception as e:
            if self.verbose:
                log_warn(f"HackerTarget hatası: {e}")

    def fetch_alienvault(self, domain):
        if self.stop.is_set():
            return
        log_info("AlienVault OTX taranıyor...")
        api = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1"
        try:
            r = self.session.get(api, headers=self._headers(), timeout=30)
            if r.status_code == 200:
                data = r.json()
                cnt = 0
                for item in data.get('url_list', []):
                    if self.stop.is_set():
                        break
                    u = item.get('url', '')
                    if self.is_valid(u):
                        self.pool.add(u)
                        cnt += 1
                self.stats['alienvault'] = cnt
                log_ok(f"AlienVault: {cnt} URL toplandı")
            else:
                log_warn(f"AlienVault yanıt kodu: {r.status_code}")
        except Exception as e:
            if self.verbose:
                log_warn(f"AlienVault hatası: {e}")

    def harvest(self, domain):
        print(f"{Colors.D}{'─' * 78}{Colors.RST}")
        log_info(f"Hedef: {Colors.W}{domain}{Colors.RST}")
        log_info(f"Thread: {Colors.W}{self.threads}{Colors.RST}")
        print(f"{Colors.D}{'─' * 78}{Colors.RST}\n")

        start = time.time()

        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = [
                ex.submit(self.fetch_wayback, domain),
                ex.submit(self.fetch_hackertarget, domain),
                ex.submit(self.fetch_alienvault, domain)
            ]
            for f in as_completed(futures):
                pass

        elapsed = time.time() - start
        print()
        print(f"{Colors.D}{'─' * 78}{Colors.RST}")

        if not self.pool:
            log_err("Hiçbir URL toplanamadı")
            print(f"\n{Colors.Y}Olası nedenler:{Colors.RST}")
            print(f"  • Domain geçersiz veya çok yeni")
            print(f"  • API servisleri erişilemez durumda")
            print(f"  • İnternet bağlantısı sorunu")
            return 0

        log_ok(f"Toplam havuz: {Colors.W}{len(self.pool)}{Colors.RST} benzersiz URL ({elapsed:.1f}s)")
        return len(self.pool)

    def match(self, dorks, domain):
        if not self.pool:
            return []

        log_info(f"Eşleştirme başlıyor: {len(self.pool)} URL x {len(dorks)} dork")
        print()

        matches = []
        root = domain.split('.')[0].lower()
        lock = threading.Lock()
        processed = [0]

        def process_dork(dork_raw):
            if self.stop.is_set():
                return []
            dork = dork_raw.strip()
            if len(dork) < 3:
                return []

            term, mode = "", "generic"
            try:
                if "inurl:" in dork:
                    term = dork.split("inurl:")[1].strip().split(" ")[0].replace('"', '').replace("'", "")
                    mode = "inurl"
                elif "filetype:" in dork or "ext:" in dork:
                    raw = dork.split("type:")[1] if "type:" in dork else dork.split("ext:")[1]
                    term = "." + raw.strip().split(" ")[0].replace(".", "")
                    mode = "ext"
                else:
                    parts = [p for p in dork.split(" ") if not any(x in p for x in ["site:", "intitle:", "intext:"])]
                    if parts:
                        term = parts[0].replace('"', '').replace("'", "").strip()
                        mode = "path"

                if not term or len(term) < 2:
                    return []

                tl = term.lower()
                if tl in STOPWORDS or tl in root:
                    return []
            except Exception:
                return []

            local = []
            term = term.lower()

            for url in self.pool:
                if self.stop.is_set():
                    break
                low = url.lower()
                try:
                    parsed = urllib.parse.urlparse(low)
                    path_q = parsed.path + "?" + parsed.query
                except Exception:
                    path_q = low

                hit = False

                if mode == "ext":
                    base = low.split('?')[0]
                    if base.endswith(term):
                        hit = True
                        if term in WEAK_EXT:
                            if not any(kw in path_q for kw in HOT_KEYWORDS):
                                hit = False
                elif mode in ("inurl", "path"):
                    if term in path_q:
                        hit = True

                if hit:
                    sev = "NORMAL"
                    if any(c in low for c in CRIT_EXT):
                        sev = "CRITICAL"
                    elif any(kw in term for kw in ("admin", "login", "config", "dashboard", "backup", "shell", "upload")):
                        sev = "HIGH"
                    elif any(kw in low for kw in ("admin", "login", "config", "dashboard")):
                        sev = "YÜKSEK"

                    local.append({
                        'url': url,
                        'dork': dork,
                        'term': term,
                        'type': mode.upper(),
                        'severity': sev
                    })

            with lock:
                processed[0] += 1
                if processed[0] % 50 == 0:
                    pct = int((processed[0] / len(dorks)) * 100)
                    print(f"\r{Colors.D}[{time.strftime('%H:%M:%S')}]{Colors.RST} {Colors.M}[~]{Colors.RST} İşleniyor: {processed[0]}/{len(dorks)} ({pct}%)", end='', flush=True)

            return local

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(process_dork, d): d for d in dorks}
            for fut in as_completed(futures):
                if self.stop.is_set():
                    break
                matches.extend(fut.result())

        print(f"\r{' ' * 80}\r", end='')

        seen = set()
        unique = []
        for m in matches:
            if m['url'] not in seen:
                seen.add(m['url'])
                unique.append(m)

        unique.sort(key=lambda x: (-SEV_MAP.get(x['severity'], 0), x['url']))
        return unique


def build_html(domain, results):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    crit = sum(1 for r in results if r['severity'] == 'CRITICAL')
    high = sum(1 for r in results if r['severity'] == 'HIGH')
    norm = len(results) - crit - high

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Samurai Raporu - {domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', -apple-system, sans-serif;
            background: linear-gradient(135deg, #0d0d0d 0%, #1a1a2e 50%, #16213e 100%);
            min-height: 100vh; color: #e0e0e0; padding: 2rem;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ 
            background: rgba(255,255,255,0.03); border-radius: 16px;
            padding: 2rem; margin-bottom: 2rem;
            border: 1px solid rgba(255,255,255,0.08);
            backdrop-filter: blur(10px);
        }}
        h1 {{ 
            font-size: 2.5rem; font-weight: 700;
            background: linear-gradient(90deg, #ff4444 0%, #ff8888 50%, #ff4444 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem; letter-spacing: 2px;
        }}
        .meta {{ color: #888; font-size: 0.9rem; }}
        .meta strong {{ color: #aaa; }}
        .stats {{ 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 1rem; margin: 2rem 0;
        }}
        .stat {{ 
            background: rgba(255,255,255,0.04); padding: 1.5rem;
            border-radius: 12px; text-align: center;
            border: 1px solid rgba(255,255,255,0.06);
            transition: transform 0.2s, background 0.2s;
        }}
        .stat:hover {{ transform: translateY(-2px); background: rgba(255,255,255,0.06); }}
        .stat-num {{ font-size: 2.2rem; font-weight: 700; }}
        .stat-label {{ color: #888; font-size: 0.8rem; margin-top: 0.5rem; text-transform: uppercase; letter-spacing: 1px; }}
        .stat.crit .stat-num {{ color: #ff4444; }}
        .stat.high .stat-num {{ color: #ffaa00; }}
        .stat.norm .stat-num {{ color: #44ff88; }}
        .stat.total .stat-num {{ color: #4488ff; }}
        .section-title {{ 
            font-size: 1.1rem; color: #888; margin: 2rem 0 1rem 0;
            padding-bottom: 0.5rem; border-bottom: 1px solid rgba(255,255,255,0.08);
        }}
        .results {{ display: flex; flex-direction: column; gap: 0.5rem; }}
        .item {{ 
            background: rgba(255,255,255,0.03); border-radius: 8px;
            padding: 0.9rem 1.1rem; display: flex; align-items: center;
            gap: 1rem; border-left: 4px solid #444;
            transition: all 0.15s ease;
        }}
        .item:hover {{ background: rgba(255,255,255,0.06); transform: translateX(4px); }}
        .item.CRITICAL {{ border-left-color: #ff4444; background: rgba(255,68,68,0.1); }}
        .item.HIGH {{ border-left-color: #ffaa00; background: rgba(255,170,0,0.08); }}
        .badge {{ 
            font-size: 0.65rem; font-weight: 700; padding: 0.25rem 0.5rem;
            border-radius: 4px; min-width: 55px; text-align: center;
            letter-spacing: 0.5px;
        }}
        .badge.CRITICAL {{ background: #ff4444; color: #fff; }}
        .badge.HIGH {{ background: #ffaa00; color: #000; }}
        .badge.NORMAL {{ background: #444; color: #aaa; }}
        .url {{ 
            flex: 1; word-break: break-all;
            color: #88ccff; text-decoration: none; font-size: 0.9rem;
        }}
        .url:hover {{ color: #aaddff; text-decoration: underline; }}
        .info {{ display: flex; gap: 0.5rem; align-items: center; }}
        .term {{ 
            font-size: 0.75rem; color: #666; background: rgba(255,255,255,0.05);
            padding: 0.2rem 0.5rem; border-radius: 4px;
        }}
        .type {{ font-size: 0.7rem; color: #555; }}
        .footer {{ 
            text-align: center; margin-top: 3rem; padding-top: 2rem;
            border-top: 1px solid rgba(255,255,255,0.08); color: #444;
            font-size: 0.85rem;
        }}
        @media (max-width: 768px) {{
            body {{ padding: 1rem; }}
            h1 {{ font-size: 1.8rem; }}
            .stat {{ padding: 1rem; }}
            .stat-num {{ font-size: 1.8rem; }}
            .item {{ flex-wrap: wrap; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>侍 SAMURAI</h1>
            <p class="meta">Hedef: <strong>{domain}</strong> &nbsp;|&nbsp; Tarih: {now} &nbsp;|&nbsp; Versiyon: {VERSION}</p>
        </div>
        <div class="stats">
            <div class="stat total">
                <div class="stat-num">{len(results)}</div>
                <div class="stat-label">Toplam</div>
            </div>
            <div class="stat crit">
                <div class="stat-num">{crit}</div>
                <div class="stat-label">Kritik</div>
            </div>
            <div class="stat high">
                <div class="stat-num">{high}</div>
                <div class="stat-label">Yüksek</div>
            </div>
            <div class="stat norm">
                <div class="stat-num">{norm}</div>
                <div class="stat-label">Normal</div>
            </div>
        </div>
        <div class="section-title">Bulunan Sonuçlar</div>
        <div class="results">
"""

    for r in results:
        html += f"""            <div class="item {r['severity']}">
                <span class="badge {r['severity']}">{r['severity']}</span>
                <a href="{r['url']}" target="_blank" rel="noopener" class="url">{r['url']}</a>
                <div class="info">
                    <span class="term">{r['term']}</span>
                    <span class="type">{r['type']}</span>
                </div>
            </div>
"""

    html += f"""        </div>
        <div class="footer">Samurai Recon Tool v{VERSION}</div>
    </div>
</body>
</html>"""
    return html


def build_json(domain, results):
    return json.dumps({
        "tool": "samurai",
        "version": VERSION,
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": len(results),
            "critical": sum(1 for r in results if r['severity'] == 'CRITICAL'),
            "high": sum(1 for r in results if r['severity'] == 'HIGH'),
            "normal": sum(1 for r in results if r['severity'] == 'NORMAL')
        },
        "results": results
    }, ensure_ascii=False, indent=2)


def build_txt(domain, results):
    crit = sum(1 for r in results if r['severity'] == 'CRITICAL')
    high = sum(1 for r in results if r['severity'] == 'HIGH')
    lines = [
        "=" * 70,
        f"  SAMURAI RAPORU v{VERSION}",
        "=" * 70,
        f"  Hedef    : {domain}",
        f"  Tarih    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Toplam   : {len(results)} (Kritik: {crit}, Yüksek: {high})",
        "=" * 70,
        ""
    ]
    for r in results:
        sev = f"[{r['severity']:8}]"
        lines.append(f"{sev} {r['url']}")
        lines.append(f"           Terim: {r['term']} | Tip: {r['type']}")
        lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


def save_report(path, domain, results):
    ext = os.path.splitext(path)[1].lower()
    if ext == '.json':
        content = build_json(domain, results)
    elif ext == '.txt':
        content = build_txt(domain, results)
    else:
        content = build_html(domain, results)

    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except PermissionError:
        log_err(f"Dosya yazma izni yok: {path}")
        return False
    except Exception as e:
        log_err(f"Dosya yazılamadı: {e}")
        return False


def main():
    if len(sys.argv) == 1:
        banner()
        usage()
        sys.exit(0)

    # Argparse helps only for parsing, we handle logic
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-d', '--domain')
    parser.add_argument('-w', '--wordlist')
    parser.add_argument('-t', '--threads', type=int, default=30)
    parser.add_argument('-o', '--output')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-h', '--help', action='store_true')

    args, unknown = parser.parse_known_args()

    if args.help:
        banner()
        usage()
        sys.exit(0)

    banner()

    if not args.domain:
        log_err("Domain belirtilmedi!")
        print(f"{Colors.Y}İpucu:{Colors.RST} Hedef belirtmek için {Colors.BOLD}-d{Colors.RST} parametresini kullanın.")
        print(f"{Colors.D}Örnek:{Colors.RST} python3 samurai.py -d example.com -w dorks.txt")
        sys.exit(1)

    if not args.wordlist:
        log_err("Wordlist belirtilmedi!")
        print(f"{Colors.Y}İpucu:{Colors.RST} Bir dork listesi belirtmelisiniz.")
        print(f"{Colors.D}Örnek:{Colors.RST} python3 samurai.py -d example.com -w dorks.txt")
        sys.exit(1)

    domain = args.domain.replace('http://', '').replace('https://', '').strip('/').lower()
    if not domain or '.' not in domain:
        log_err(f"Geçersiz domain: {args.domain}")
        print(f"{Colors.Y}İpucu:{Colors.RST} Geçerli bir domain adresi girin (örnek: google.com)")
        sys.exit(1)

    # Load wordlist (mandatory provided)
    dorks = load_wordlist(args.wordlist)
    log_ok(f"Wordlist yüklendi: {len(dorks)} satır")

    eng = Engine(threads=args.threads, verbose=args.verbose)

    try:
        total = eng.harvest(domain)
    except KeyboardInterrupt:
        print()
        log_warn("Kullanıcı tarafından iptal edildi")
        sys.exit(130)

    if total == 0:
        log_warn("Hiçbir URL bulunamadı, tarama sonlandırılıyor.")
        sys.exit(1)

    print()

    try:
        results = eng.match(dorks, domain)
    except KeyboardInterrupt:
        print()
        log_warn("Kullanıcı tarafından iptal edildi")
        sys.exit(130)

    crit = sum(1 for r in results if r['severity'] == 'CRITICAL')
    high = sum(1 for r in results if r['severity'] == 'HIGH')

    print(f"{Colors.D}{'─' * 78}{Colors.RST}")

    if results:
        log_ok(f"Tarama tamamlandı: {Colors.W}{len(results)}{Colors.RST} sonuç bulundu")
        
        # Summary Box
        print(f"\n   {Colors.BG_G}{Colors.D} ÖZET RAPOR {Colors.RST}")
        print(f"   {Colors.D}──────────{Colors.RST}")
        print(f"   {Colors.R}Kritik :{Colors.RST} {crit}")
        print(f"   {Colors.Y}Yüksek :{Colors.RST} {high}")
        print(f"   {Colors.C}Normal :{Colors.RST} {len(results) - crit - high}")
        print(f"   {Colors.D}──────────{Colors.RST}")
        print()

        shown = 0
        for r in results:
            if shown >= 30:
                break
            if r['severity'] == 'CRITICAL':
                log_crit(r['url'])
                shown += 1
            elif r['severity'] == 'HIGH':
                log_high(r['url'])
                shown += 1

        if shown == 0:
            for r in results[:15]:
                log_norm(r['url'])
            shown = min(15, len(results))

        if len(results) > shown:
            print()
            log_info(f"+{len(results) - shown} sonuç daha (rapor dosyasına bakın)")
    else:
        log_warn("Eşleşen sonuç bulunamadı")
        print(f"\n{Colors.Y}Öneriler:{Colors.RST}")
        print(f"  • Farklı dork listesi deneyin (-w)")
        print(f"  • Domain'in archive kayıtlarını kontrol edin")

    if args.output and results:
        print()
        if save_report(args.output, domain, results):
            log_ok(f"Rapor kaydedildi: {Colors.W}{args.output}{Colors.RST}")
    elif results:
         # Suggest saving if they didn't
         print(f"\n{Colors.D}[BİLGİ] Sonuçları kaydetmek için -o parametresini kullanabilirsiniz.{Colors.RST}")

    print(f"\n{Colors.D}{'─' * 78}{Colors.RST}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.Y}[!] Çıkış{Colors.RST}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.R}[X] Beklenmeyen hata: {e}{Colors.RST}")
        sys.exit(1)
