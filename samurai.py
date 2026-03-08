#!/usr/bin/env python3
"""Samurai — Domain Reconnaissance & Dork Scanner

Goal: usability + performance for broad, everyday recon usage.

- Harvest URLs/subdomains from OSINT sources (Wayback, HackerTarget, AlienVault OTX)
- Filter noise (static assets, vendor paths, stopwords)
- Match against a dork/wordlist (optional; defaults included)
- Classify findings: CRITICAL / HIGH / NORMAL
- Report: HTML / JSON / TXT

NOTE: Use only on targets you are authorized to test.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

VERSION = "1.2"

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


# -----------------
# Defaults / Config
# -----------------

DEFAULT_BANNED_EXT = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
    ".webm",
    ".pdf",
    ".doc",
    ".docx",
    ".ppt",
    ".pptx",
    ".xls",
    ".xlsx",
    ".csv",
    ".xml",
    ".map",
)

DEFAULT_BANNED_PATH = (
    "/assets/",
    "/static/",
    "/vendor/",
    "/lib/",
    "/images/",
    "/img/",
    "/fonts/",
    "/node_modules/",
    "/bower_components/",
    "/wp-includes/js/",
    "/wp-content/themes/",
    "/cache/",
    "/tmp/",
    "jquery",
    "bootstrap",
    "fontawesome",
)

DEFAULT_STOPWORDS = {
    "the",
    "and",
    "for",
    "of",
    "to",
    "in",
    "is",
    "on",
    "at",
    "by",
    "web",
    "www",
    "com",
    "net",
    "org",
    "http",
    "https",
    "html",
    "htm",
    "site",
    "url",
    "file",
    "index",
    "page",
    "home",
    "default",
    "main",
    "public",
    "private",
}

# Things that are almost always sensitive if exposed.
DEFAULT_CRIT_PATTERNS = (
    ".env",
    "wp-config",
    ".git",
    ".svn",
    ".hg",
    ".DS_Store",
    ".htpasswd",
    ".htaccess",
    "id_rsa",
    "authorized_keys",
    "kubeconfig",
    "config.json",
    "settings.py",
    "localsettings",
    "database.yml",
    "credentials",
    "secret",
    "apikey",
    "api_key",
    "private_key",
    ".pem",
    ".key",
    ".pfx",
    ".keystore",
    ".jks",
    ".bak",
    ".old",
    ".backup",
    ".sql",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".dump",
    ".zip",
    ".rar",
    ".tar",
    ".tar.gz",
    ".7z",
    "backup",
    "dump",
)

DEFAULT_HOT_KEYWORDS = (
    "admin",
    "login",
    "signin",
    "sign-in",
    "signup",
    "register",
    "auth",
    "oauth",
    "sso",
    "jwt",
    "token",
    "apikey",
    "api_key",
    "key",
    "secret",
    "config",
    "settings",
    "setup",
    "install",
    "debug",
    "trace",
    "console",
    "panel",
    "dashboard",
    "manage",
    "internal",
    "private",
    "staff",
    "root",
    "phpmyadmin",
    "pma",
    "grafana",
    "kibana",
    "prometheus",
    "jenkins",
    "gitlab",
    "nexus",
    "sonarqube",
    "swagger",
    "openapi",
    "api-docs",
    "graphql",
    "actuator",
)

# Expanded default dorks (URL-focused; safe for generic recon usage).
DEFAULT_DORKS: List[str] = [
    # auth/admin
    "inurl:admin",
    "inurl:administrator",
    "inurl:admin/login",
    "inurl:login",
    "inurl:signin",
    "inurl:sign-in",
    "inurl:logout",
    "inurl:register",
    "inurl:signup",
    "inurl:auth",
    "inurl:oauth",
    "inurl:sso",
    "inurl:callback",
    # config/secrets
    "inurl:config",
    "inurl:settings",
    "inurl:setup",
    "inurl:install",
    "inurl:debug",
    "inurl:trace",
    "inurl:console",
    "inurl:status",
    # backups/dumps
    "inurl:backup",
    "inurl:backups",
    "inurl:dump",
    "inurl:db",
    "inurl:database",
    "inurl:export",
    # uploads/files
    "inurl:upload",
    "inurl:uploads",
    "inurl:files",
    "inurl:download",
    "inurl:attachment",
    # APIs
    "inurl:api",
    "inurl:v1",
    "inurl:v2",
    "inurl:graphql",
    "inurl:swagger",
    "inurl:openapi",
    "inurl:api-docs",
    # popular panels/tools
    "inurl:phpmyadmin",
    "inurl:pma",
    "inurl:wp-admin",
    "inurl:wp-login",
    "inurl:cpanel",
    "inurl:webmail",
    "inurl:jenkins",
    "inurl:gitlab",
    "inurl:grafana",
    "inurl:kibana",
    "inurl:prometheus",
    "inurl:sonarqube",
    "inurl:nexus",
    # sensitive file extensions
    "filetype:env",
    "filetype:log",
    "filetype:sql",
    "filetype:bak",
    "filetype:old",
    "filetype:ini",
    "filetype:conf",
    "filetype:config",
    "filetype:yml",
    "filetype:yaml",
    "filetype:json",
    "filetype:xml",
    "filetype:zip",
    "filetype:tar",
    "filetype:gz",
    "filetype:7z",
    "ext:env",
    "ext:bak",
    "ext:old",
    "ext:sql",
    "ext:log",
]


SEV_MAP = {"CRITICAL": 3, "HIGH": 2, "NORMAL": 1}


@dataclass
class Options:
    domain: str
    wordlist: Optional[str]
    threads: int
    verbose: bool
    quiet: bool
    no_color: bool

    fmt: str
    output: Optional[str]
    no_report: bool

    timeout: float
    retries: int
    backoff: float

    # limits
    max_urls: int
    wayback_limit: int
    otx_pages: int

    # sources
    use_wayback: bool
    use_hackertarget: bool
    use_otx: bool

    # filters
    ext_filter: bool
    path_filter: bool
    stopwords_filter: bool

    # optional verification
    resolve_subdomains: bool

    # external config
    config_path: Optional[str]


class Colors:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.R = "\033[91m" if enabled else ""
        self.G = "\033[92m" if enabled else ""
        self.Y = "\033[93m" if enabled else ""
        self.B = "\033[94m" if enabled else ""
        self.M = "\033[95m" if enabled else ""
        self.C = "\033[96m" if enabled else ""
        self.W = "\033[97m" if enabled else ""
        self.D = "\033[90m" if enabled else ""
        self.BOLD = "\033[1m" if enabled else ""
        self.RST = "\033[0m" if enabled else ""
        self.BG_R = "\033[41m" if enabled else ""
        self.BG_Y = "\033[43m" if enabled else ""
        self.BG_G = "\033[42m" if enabled else ""


def now_ts() -> str:
    return time.strftime("%H:%M:%S")


class Logger:
    def __init__(self, c: Colors, quiet: bool = False):
        self.c = c
        self.quiet = quiet

    def _p(self, s: str) -> None:
        if self.quiet:
            return
        print(s, flush=True)

    def info(self, msg: str) -> None:
        self._p(f"{self.c.D}[{now_ts()}]{self.c.RST} {self.c.C}[*]{self.c.RST} {msg}")

    def ok(self, msg: str) -> None:
        self._p(f"{self.c.D}[{now_ts()}]{self.c.RST} {self.c.G}[+]{self.c.RST} {self.c.G}{msg}{self.c.RST}")

    def warn(self, msg: str) -> None:
        self._p(f"{self.c.D}[{now_ts()}]{self.c.RST} {self.c.Y}[!]{self.c.RST} {self.c.Y}{msg}{self.c.RST}")

    def err(self, msg: str) -> None:
        self._p(f"{self.c.D}[{now_ts()}]{self.c.RST} {self.c.R}[X]{self.c.RST} {self.c.R}{msg}{self.c.RST}")

    def crit(self, msg: str) -> None:
        self._p(f"{self.c.D}[{now_ts()}]{self.c.RST} {self.c.BG_R}{self.c.W} CRITICAL {self.c.RST} {self.c.R}{msg}{self.c.RST}")

    def high(self, msg: str) -> None:
        self._p(f"{self.c.D}[{now_ts()}]{self.c.RST} {self.c.BG_Y}{self.c.W} HIGH {self.c.RST} {self.c.Y}{msg}{self.c.RST}")


def banner(c: Colors, quiet: bool = False) -> None:
    if quiet:
        return
    print(f"{c.R}{c.BOLD}{BANNER}{c.RST}")
    print(f"{c.D}{'─' * 78}{c.RST}")
    print(
        f"{c.W}  ► Domain Reconnaissance & Dork Scanner{c.RST}  {c.D}│{c.RST}  {c.Y}v{VERSION}{c.RST}"
    )
    print(f"{c.D}{'─' * 78}{c.RST}\n")


def load_json_config(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@dataclass
class Filters:
    banned_ext: Tuple[str, ...]
    banned_path: Tuple[str, ...]
    stopwords: Set[str]
    crit_patterns: Tuple[str, ...]
    hot_keywords: Tuple[str, ...]

    @staticmethod
    def from_defaults_and_config(cfg: Optional[Dict] = None) -> "Filters":
        cfg = cfg or {}

        banned_ext = tuple(cfg.get("banned_ext", DEFAULT_BANNED_EXT))
        banned_path = tuple(cfg.get("banned_path", DEFAULT_BANNED_PATH))
        stopwords = set(cfg.get("stopwords", list(DEFAULT_STOPWORDS)))
        crit_patterns = tuple(cfg.get("crit_patterns", DEFAULT_CRIT_PATTERNS))
        hot_keywords = tuple(cfg.get("hot_keywords", DEFAULT_HOT_KEYWORDS))

        # normalize
        banned_ext = tuple(e.lower() for e in banned_ext)
        banned_path = tuple(p.lower() for p in banned_path)
        stopwords = {s.lower() for s in stopwords}
        crit_patterns = tuple(p.lower() for p in crit_patterns)
        hot_keywords = tuple(k.lower() for k in hot_keywords)

        return Filters(
            banned_ext=banned_ext,
            banned_path=banned_path,
            stopwords=stopwords,
            crit_patterns=crit_patterns,
            hot_keywords=hot_keywords,
        )


def check_deps(log: Logger):
    missing = []
    try:
        import requests  # type: ignore

    except ImportError:
        missing.append("requests")
        requests = None

    try:
        from fake_useragent import UserAgent  # type: ignore

    except ImportError:
        # optional
        UserAgent = None

    if missing:
        log.err(f"Missing Python packages: {', '.join(missing)}")
        log.err("Install: pip install -r requirements.txt")
        sys.exit(1)

    return requests, UserAgent


def normalize_domain(raw: str) -> str:
    d = raw.strip()
    d = d.replace("http://", "").replace("https://", "").strip("/")
    d = d.lower()
    return d


def is_domain_valid(domain: str) -> bool:
    return bool(domain) and "." in domain and " " not in domain


def read_wordlist(path: str, log: Logger) -> List[str]:
    if not os.path.exists(path):
        log.err(f"Wordlist not found: {path}")
        sys.exit(1)
    if not os.path.isfile(path):
        log.err(f"Not a file: {path}")
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [ln.strip() for ln in f if len(ln.strip()) >= 2 and not ln.strip().startswith("#")]
    except Exception as e:
        log.err(f"Failed to read wordlist: {e}")
        sys.exit(1)

    if not lines:
        log.err("Wordlist is empty")
        sys.exit(1)

    return lines


# --------------
# Dork parsing
# --------------

DORK_RE_INURL = re.compile(r"inurl:(?P<term>[^\s]+)", re.IGNORECASE)
DORK_RE_EXT = re.compile(r"(?:filetype|ext):(?P<ext>[^\s]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Dork:
    raw: str
    kind: str  # INURL | EXT | PATH
    term: str  # normalized term, for EXT starts with '.'


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


def parse_dork(line: str) -> Optional[Dork]:
    raw = line.strip()
    if not raw:
        return None

    m = DORK_RE_INURL.search(raw)
    if m:
        term = _strip_quotes(m.group("term")).strip().lower()
        if term:
            return Dork(raw=raw, kind="INURL", term=term)

    m = DORK_RE_EXT.search(raw)
    if m:
        ext = _strip_quotes(m.group("ext")).strip().lower().lstrip(".")
        if ext:
            return Dork(raw=raw, kind="EXT", term=f".{ext}")

    # fallback: treat first useful token as PATH term
    parts = [p for p in re.split(r"\s+", raw) if p and not p.startswith("site:") and not p.startswith("intitle:") and not p.startswith("intext:")]
    if not parts:
        return None
    term = _strip_quotes(parts[0]).strip().lower()
    if not term:
        return None
    return Dork(raw=raw, kind="PATH", term=term)


def tokenize(text: str) -> Set[str]:
    # split on boundaries but keep common URL token chars like '-' and '_'
    toks = set(re.split(r"[^a-z0-9_-]+", text.lower()))
    toks.discard("")
    return toks


@dataclass
class UrlEntry:
    url: str
    base: str
    path_q: str
    tokens: Set[str]


def build_url_entry(url: str) -> Optional[UrlEntry]:
    low = url.strip()
    if not low:
        return None
    try:
        p = urllib.parse.urlparse(low)
        base = (p.scheme + "://" + p.netloc + p.path) if p.scheme and p.netloc else low.split("?")[0]
        path_q = (p.path or "") + ("?" + p.query if p.query else "")
        tokens = tokenize(p.netloc + " " + path_q)
        return UrlEntry(url=url, base=base.lower(), path_q=path_q.lower(), tokens=tokens)
    except Exception:
        # best effort
        base = low.split("?")[0].lower()
        return UrlEntry(url=url, base=base, path_q=low.lower(), tokens=tokenize(low))


# --------------
# Engine
# --------------


class Engine:
    def __init__(self, opts: Options, filters: Filters, log: Logger):
        requests, UserAgent = check_deps(log)
        self.requests = requests
        self.UserAgent = UserAgent
        self.opts = opts
        self.filters = filters
        self.log = log

        self.pool: Set[str] = set()
        self.stop = threading.Event()

        self.session = requests.Session()
        self.session.headers.update({"Accept-Language": "en-US,en;q=0.9"})
        self.ua = None
        if UserAgent is not None:
            try:
                self.ua = UserAgent()
            except Exception:
                self.ua = None

        self.stats = {"wayback": 0, "hackertarget": 0, "otx": 0}

    def _headers(self) -> Dict[str, str]:
        ua = None
        try:
            ua = self.ua.random if self.ua else None
        except Exception:
            ua = None
        if not ua:
            ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
        return {"User-Agent": ua}

    def _request(self, url: str, timeout: float) -> Optional["requests.Response"]:
        # simple retry/backoff wrapper
        last_err = None
        for attempt in range(self.opts.retries + 1):
            if self.stop.is_set():
                return None
            try:
                r = self.session.get(url, headers=self._headers(), timeout=timeout)
                return r
            except self.requests.exceptions.RequestException as e:
                last_err = e
                if attempt < self.opts.retries:
                    time.sleep(self.opts.backoff * (2 ** attempt))
        if self.opts.verbose and last_err:
            self.log.warn(f"Request failed: {url} ({last_err})")
        return None

    def _pool_add(self, url: str) -> None:
        if self.stop.is_set():
            return
        if len(self.pool) >= self.opts.max_urls:
            self.stop.set()
            return
        self.pool.add(url)

    def is_valid(self, url: str) -> bool:
        if not url or len(url) < 10:
            return False

        low = url.lower()
        base = low.split("?")[0]

        if self.opts.ext_filter:
            if base.endswith(self.filters.banned_ext):
                return False

        if self.opts.path_filter:
            for kw in self.filters.banned_path:
                if kw in base:
                    return False

        return True

    # --- sources ---

    def fetch_wayback(self, domain: str) -> None:
        if self.stop.is_set():
            return
        self.log.info("Harvesting from Wayback Machine...")

        limit = max(1, min(self.opts.wayback_limit, 200000))
        api = (
            "http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey"
            f"&filter=statuscode:200&limit={limit}"
        )

        r = self._request(api, timeout=max(self.opts.timeout, 60.0))
        if not r:
            return
        if r.status_code != 200:
            self.log.warn(f"Wayback HTTP {r.status_code}")
            return

        cnt = 0
        for ln in r.text.splitlines():
            if self.stop.is_set():
                break
            u = ln.strip()
            if self.is_valid(u):
                self._pool_add(u)
                cnt += 1
        self.stats["wayback"] = cnt
        self.log.ok(f"Wayback: collected {cnt} URLs")

    def _resolve_hosts(self, hosts: Sequence[str]) -> Set[str]:
        # Best-effort DNS resolve for subdomains (optional)
        resolvable: Set[str] = set()

        def worker(h: str) -> Optional[str]:
            try:
                socket.gethostbyname(h)
                return h
            except Exception:
                return None

        # DNS lookups can be slow; cap threads
        t = min(max(10, self.opts.threads), 80)
        with ThreadPoolExecutor(max_workers=t) as ex:
            futs = [ex.submit(worker, h) for h in hosts]
            for f in as_completed(futs):
                v = f.result()
                if v:
                    resolvable.add(v)
        return resolvable

    def fetch_hackertarget(self, domain: str) -> None:
        if self.stop.is_set():
            return
        self.log.info("Harvesting from HackerTarget (hostsearch)...")

        api = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = self._request(api, timeout=self.opts.timeout)
        if not r:
            return

        if "API count exceeded" in r.text:
            self.log.warn("HackerTarget API limit exceeded")
            return

        subs: List[str] = []
        for ln in r.text.splitlines():
            if self.stop.is_set():
                break
            p = ln.split(",")
            if p and p[0]:
                sub = p[0].strip().lower()
                if sub and "." in sub:
                    subs.append(sub)

        if self.opts.resolve_subdomains and subs:
            self.log.info(f"Resolving {len(subs)} subdomains (DNS)...")
            subs = sorted(self._resolve_hosts(subs))
            self.log.ok(f"Resolved {len(subs)} subdomains")

        cnt = 0
        for sub in subs:
            if self.stop.is_set():
                break
            # keep these even if "is_valid" would filter (no path)
            self._pool_add(f"http://{sub}")
            self._pool_add(f"https://{sub}")
            cnt += 1

        self.stats["hackertarget"] = cnt
        self.log.ok(f"HackerTarget: found {cnt} subdomains")

    def fetch_otx(self, domain: str) -> None:
        if self.stop.is_set():
            return
        self.log.info("Harvesting from AlienVault OTX...")

        pages = max(1, min(self.opts.otx_pages, 50))
        cnt = 0

        for page in range(1, pages + 1):
            if self.stop.is_set():
                break
            api = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page={page}"
            r = self._request(api, timeout=self.opts.timeout)
            if not r:
                continue
            if r.status_code != 200:
                if self.opts.verbose:
                    self.log.warn(f"OTX HTTP {r.status_code} (page {page})")
                continue

            try:
                data = r.json()
            except Exception:
                if self.opts.verbose:
                    self.log.warn(f"OTX invalid JSON (page {page})")
                continue

            items = data.get("url_list", []) or []
            if not items:
                break

            for item in items:
                if self.stop.is_set():
                    break
                u = (item or {}).get("url", "")
                if self.is_valid(u):
                    self._pool_add(u)
                    cnt += 1

        self.stats["otx"] = cnt
        self.log.ok(f"OTX: collected {cnt} URLs")

    # --- harvest ---

    def harvest(self, domain: str) -> int:
        self.log.info(f"Target: {domain}")
        self.log.info(f"Threads: {self.opts.threads}")

        start = time.time()

        tasks = []
        if self.opts.use_wayback:
            tasks.append(self.fetch_wayback)
        if self.opts.use_hackertarget:
            tasks.append(self.fetch_hackertarget)
        if self.opts.use_otx:
            tasks.append(self.fetch_otx)

        if not tasks:
            self.log.err("No data sources enabled")
            return 0

        with ThreadPoolExecutor(max_workers=min(3, len(tasks))) as ex:
            futs = [ex.submit(fn, domain) for fn in tasks]
            for _ in as_completed(futs):
                pass

        elapsed = time.time() - start
        if not self.pool:
            self.log.err("No URLs collected")
            return 0

        self.log.ok(f"Pool: {len(self.pool)} unique URLs ({elapsed:.1f}s)")
        if self.stop.is_set() and len(self.pool) >= self.opts.max_urls:
            self.log.warn(f"Reached max pool size: {self.opts.max_urls}")
        return len(self.pool)

    # --- matching ---

    def _should_skip_term(self, term: str, root_label: str) -> bool:
        if not term or len(term) < 2:
            return True

        if self.opts.stopwords_filter:
            if term in self.filters.stopwords:
                return True

        # avoid trivial self-matches
        if root_label and root_label in term:
            return True

        return False

    def classify(self, url_low: str, d: Dork) -> str:
        # 1) critical patterns anywhere in url
        if any(p in url_low for p in self.filters.crit_patterns):
            return "CRITICAL"

        # 2) keyword-based high
        term = d.term
        if any(k in term for k in ("admin", "login", "config", "backup", "upload", "swagger", "graphql")):
            return "HIGH"
        if any(k in url_low for k in ("/admin", "/login", "/config", "/dashboard", "/swagger", "/api-docs", "/graphql")):
            return "HIGH"

        return "NORMAL"

    def match(self, dorks_raw: Sequence[str], domain: str) -> List[Dict]:
        if not self.pool:
            return []

        # parse dorks
        root_label = domain.split(".")[0].lower()

        dorks: List[Dork] = []
        for ln in dorks_raw:
            d = parse_dork(ln)
            if not d:
                continue
            if self._should_skip_term(d.term.lstrip("."), root_label):
                continue
            dorks.append(d)

        if not dorks:
            self.log.warn("No usable dorks after parsing/filters")
            return []

        # build URL entries + indexes
        entries: List[UrlEntry] = []
        token_index: Dict[str, List[int]] = {}
        ext_index: Dict[str, List[int]] = {}

        for u in self.pool:
            e = build_url_entry(u)
            if not e:
                continue
            idx = len(entries)
            entries.append(e)

            # token index for pre-filter
            for t in e.tokens:
                # keep only reasonably selective tokens
                if 3 <= len(t) <= 40:
                    token_index.setdefault(t, []).append(idx)

            # ext index
            base = e.base
            # last extension
            m = re.search(r"(\.[a-z0-9]{1,8})$", base)
            if m:
                ext = m.group(1)
                ext_index.setdefault(ext, []).append(idx)

        self.log.info(f"Matching: {len(entries)} URLs × {len(dorks)} dorks")

        results_by_url: Dict[str, Dict] = {}

        # dork evaluation
        processed = 0
        lock = threading.Lock()

        def eval_dork(d: Dork) -> None:
            nonlocal processed

            # candidate selection
            candidates: Optional[Iterable[int]] = None
            key = d.term.lstrip(".")

            if d.kind == "EXT":
                candidates = ext_index.get(d.term, [])
            else:
                # prefilter by token if term is simple
                if re.fullmatch(r"[a-z0-9_-]{3,40}", key):
                    candidates = token_index.get(key, [])

            if candidates is None:
                candidates = range(len(entries))

            for i in candidates:
                e = entries[i]

                hit = False
                if d.kind == "EXT":
                    if e.base.endswith(d.term):
                        hit = True
                else:
                    if d.term in e.path_q:
                        hit = True

                if not hit:
                    continue

                sev = self.classify(e.base + " " + e.path_q, d)

                with lock:
                    rec = results_by_url.get(e.url)
                    if not rec:
                        rec = {
                            "url": e.url,
                            "severity": sev,
                            "hits": [],
                        }
                        results_by_url[e.url] = rec
                    else:
                        if SEV_MAP[sev] > SEV_MAP.get(rec["severity"], 0):
                            rec["severity"] = sev

                    rec["hits"].append({"dork": d.raw, "term": d.term, "type": d.kind, "severity": sev})

            with lock:
                processed += 1
                if not self.opts.quiet and processed % 50 == 0:
                    pct = int((processed / len(dorks)) * 100)
                    print(
                        f"\r{self.log.c.D}[{now_ts()}]{self.log.c.RST} {self.log.c.M}[~]{self.log.c.RST} Processing: {processed}/{len(dorks)} ({pct}%)",
                        end="",
                        flush=True,
                    )

        with ThreadPoolExecutor(max_workers=self.opts.threads) as ex:
            futs = [ex.submit(eval_dork, d) for d in dorks]
            for _ in as_completed(futs):
                if self.stop.is_set():
                    break

        if not self.opts.quiet:
            print(f"\r{' ' * 100}\r", end="")

        results: List[Dict] = list(results_by_url.values())
        # sort by severity then url
        results.sort(key=lambda r: (-SEV_MAP.get(r["severity"], 0), r["url"]))
        return results


# --------------
# Report builders
# --------------


def build_html(domain: str, results: Sequence[Dict]) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    crit = sum(1 for r in results if r["severity"] == "CRITICAL")
    high = sum(1 for r in results if r["severity"] == "HIGH")
    norm = len(results) - crit - high

    # Render hits summary as small badges
    def hits_badges(hits: Sequence[Dict]) -> str:
        # unique terms, cap
        terms = []
        seen = set()
        for h in hits:
            t = h.get("term")
            if not t or t in seen:
                continue
            seen.add(t)
            terms.append(t)
            if len(terms) >= 5:
                break
        if not terms:
            return ""
        return " ".join(f"<span class=\"pill\">{html_escape(t)}</span>" for t in terms)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Samurai Report — {domain}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial;
      background: #0b1220;
      color: #e5e7eb;
      padding: 24px;
    }}
    a {{ color: #7dd3fc; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .hero {{
      border: 1px solid rgba(255,255,255,.08);
      background: rgba(255,255,255,.03);
      border-radius: 16px;
      padding: 20px 22px;
    }}
    .title {{ font-size: 22px; font-weight: 800; letter-spacing: -0.02em; }}
    .meta {{ margin-top: 6px; color: #94a3b8; font-size: 13px; }}
    .grid {{
      margin-top: 16px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
    }}
    .card {{
      border: 1px solid rgba(255,255,255,.08);
      background: rgba(255,255,255,.03);
      border-radius: 14px;
      padding: 14px 16px;
    }}
    .num {{ font-size: 22px; font-weight: 800; }}
    .lbl {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: .12em; margin-top: 4px; }}
    .crit {{ color: #fb7185; }}
    .high {{ color: #fbbf24; }}
    .norm {{ color: #34d399; }}

    .toolbar {{
      margin-top: 18px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
    }}
    .search {{
      flex: 1;
      min-width: 240px;
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.03);
      border-radius: 12px;
      padding: 10px 12px;
      color: #e5e7eb;
      outline: none;
    }}
    .filters {{ display: flex; gap: 8px; }}
    .btn {{
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.03);
      color: #e5e7eb;
      border-radius: 12px;
      padding: 8px 10px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 600;
    }}
    .btn.active {{ border-color: rgba(125,211,252,.5); box-shadow: 0 0 0 3px rgba(125,211,252,.12); }}

    .list {{ margin-top: 14px; display: grid; gap: 10px; }}
    .item {{
      border: 1px solid rgba(255,255,255,.08);
      background: rgba(255,255,255,.03);
      border-radius: 14px;
      padding: 12px 14px;
      display: grid;
      gap: 8px;
    }}
    .row {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
    .badge {{
      font-size: 11px;
      font-weight: 800;
      padding: 4px 8px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,.14);
      letter-spacing: .04em;
    }}
    .badge.CRITICAL {{ background: rgba(251,113,133,.14); border-color: rgba(251,113,133,.35); color: #fb7185; }}
    .badge.HIGH {{ background: rgba(251,191,36,.14); border-color: rgba(251,191,36,.35); color: #fbbf24; }}
    .badge.NORMAL {{ background: rgba(148,163,184,.10); border-color: rgba(148,163,184,.20); color: #94a3b8; }}
    .url {{ word-break: break-all; font-size: 13px; }}
    .pill {{
      display: inline-flex;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(255,255,255,.03);
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 11px;
      color: #cbd5e1;
    }}
    .muted {{ color: #94a3b8; font-size: 12px; }}

    @media (max-width: 640px) {{
      body {{ padding: 14px; }}
      .title {{ font-size: 18px; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <div class="title">侍 Samurai Report</div>
      <div class="meta">Target: <b>{domain}</b> • Generated: {now} • Version: {VERSION}</div>
      <div class="grid">
        <div class="card"><div class="num">{len(results)}</div><div class="lbl">Total</div></div>
        <div class="card"><div class="num crit">{crit}</div><div class="lbl">Critical</div></div>
        <div class="card"><div class="num high">{high}</div><div class="lbl">High</div></div>
        <div class="card"><div class="num norm">{norm}</div><div class="lbl">Normal</div></div>
      </div>

      <div class="toolbar">
        <input id="q" class="search" placeholder="Search URL / term…" />
        <div class="filters">
          <button class="btn active" data-sev="ALL">All</button>
          <button class="btn" data-sev="CRITICAL">Critical</button>
          <button class="btn" data-sev="HIGH">High</button>
          <button class="btn" data-sev="NORMAL">Normal</button>
        </div>
      </div>
    </div>

    <div id="list" class="list">
"""

    for r in results:
        sev = r.get("severity", "NORMAL")
        url = r.get("url", "")
        hits = r.get("hits", []) or []
        html += f"""      <div class="item" data-sev="{sev}" data-text="{html_escape((url + ' ' + ' '.join(h.get('term','') for h in hits)).lower())}">
        <div class="row">
          <span class="badge {sev}">{sev}</span>
          <a class="url" href="{html_escape(url)}" target="_blank" rel="noopener">{html_escape(url)}</a>
        </div>
        <div class="row">
          {hits_badges(hits)}
          <span class="muted">hits: {len(hits)}</span>
        </div>
      </div>
"""

    html += """    </div>
  </div>

  <script>
    const q = document.getElementById('q');
    const list = document.getElementById('list');
    let sev = 'ALL';

    function apply() {
      const needle = (q.value || '').trim().toLowerCase();
      const items = list.querySelectorAll('.item');
      for (const it of items) {
        const s = it.getAttribute('data-sev');
        const t = it.getAttribute('data-text') || '';
        const okSev = (sev === 'ALL') || (s === sev);
        const okQ = (!needle) || t.includes(needle);
        it.style.display = (okSev && okQ) ? '' : 'none';
      }
    }

    q.addEventListener('input', apply);

    for (const btn of document.querySelectorAll('.btn')) {
      btn.addEventListener('click', () => {
        for (const b of document.querySelectorAll('.btn')) b.classList.remove('active');
        btn.classList.add('active');
        sev = btn.getAttribute('data-sev');
        apply();
      });
    }
  </script>
</body>
</html>
"""
    return html


def build_json(domain: str, results: Sequence[Dict]) -> str:
    payload = {
        "tool": "samurai",
        "version": VERSION,
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": len(results),
            "critical": sum(1 for r in results if r.get("severity") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("severity") == "HIGH"),
            "normal": sum(1 for r in results if r.get("severity") == "NORMAL"),
        },
        "results": list(results),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def build_txt(domain: str, results: Sequence[Dict]) -> str:
    crit = [r for r in results if r.get("severity") == "CRITICAL"]
    high = [r for r in results if r.get("severity") == "HIGH"]
    norm = [r for r in results if r.get("severity") == "NORMAL"]

    lines: List[str] = []
    lines.append("=" * 72)
    lines.append(f"SAMURAI REPORT v{VERSION}")
    lines.append("=" * 72)
    lines.append(f"Target     : {domain}")
    lines.append(f"Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Total      : {len(results)} (Critical: {len(crit)}, High: {len(high)}, Normal: {len(norm)})")
    lines.append("=" * 72)

    def section(title: str, arr: Sequence[Dict]) -> None:
        lines.append("")
        lines.append(f"[{title}] ({len(arr)})")
        lines.append("-" * 72)
        for r in arr:
            url = r.get("url", "")
            hits = r.get("hits", []) or []
            terms = []
            seen = set()
            for h in hits:
                t = h.get("term")
                if not t or t in seen:
                    continue
                seen.add(t)
                terms.append(t)
                if len(terms) >= 6:
                    break
            lines.append(url)
            if terms:
                lines.append("  terms: " + ", ".join(terms))
            lines.append(f"  hits : {len(hits)}")
            lines.append("")

    section("CRITICAL", crit)
    section("HIGH", high)
    section("NORMAL", norm)

    lines.append("=" * 72)
    return "\n".join(lines)


def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def write_output(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def default_report_name(domain: str, fmt: str) -> str:
    safe = re.sub(r"[^a-z0-9_.-]+", "_", domain.lower())
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"html": "html", "json": "json", "txt": "txt"}.get(fmt, "html")
    return f"samurai_{safe}_{ts}.{ext}"


def build_report(fmt: str, domain: str, results: Sequence[Dict]) -> str:
    if fmt == "json":
        return build_json(domain, results)
    if fmt == "txt":
        return build_txt(domain, results)
    return build_html(domain, results)


def parse_args(argv: Sequence[str]) -> Options:
    p = argparse.ArgumentParser(
        prog="samurai",
        description="Samurai — Domain Reconnaissance & Dork Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument("-d", "--domain", required=False, help="Target domain (e.g. example.com)")
    p.add_argument("-w", "--wordlist", required=False, help="Dork/wordlist file (optional; defaults included)")
    p.add_argument("-t", "--threads", type=int, default=30, help="Worker threads for matching")
    p.add_argument("-o", "--output", default=None, help="Output path (or '-' for stdout)")
    p.add_argument("--format", dest="fmt", choices=["html", "json", "txt"], default="html", help="Report format")
    p.add_argument("--no-report", action="store_true", help="Do not write any report file")

    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (minimal output)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("--version", action="store_true", help="Print version and exit")

    # timeouts/retry
    p.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout seconds")
    p.add_argument("--retries", type=int, default=2, help="HTTP retries")
    p.add_argument("--backoff", type=float, default=0.7, help="Retry backoff base seconds")

    # limits
    p.add_argument("--max-urls", type=int, default=75000, help="Max URLs in pool (hard cap)")
    p.add_argument("--wayback-limit", type=int, default=50000, help="Wayback CDX limit")
    p.add_argument("--otx-pages", type=int, default=3, help="OTX pages to fetch (500 URLs per page)")

    # sources
    p.add_argument("--no-wayback", action="store_true", help="Disable Wayback source")
    p.add_argument("--no-hackertarget", action="store_true", help="Disable HackerTarget source")
    p.add_argument("--no-otx", action="store_true", help="Disable OTX source")

    # filters
    p.add_argument("--no-ext-filter", action="store_true", help="Disable static-extension filtering")
    p.add_argument("--no-path-filter", action="store_true", help="Disable path keyword filtering")
    p.add_argument("--no-stopwords", action="store_true", help="Disable stopword filtering")

    # verification
    p.add_argument("--resolve-subdomains", action="store_true", help="DNS-resolve subdomains before adding")

    # external config
    p.add_argument("--config", dest="config_path", default=None, help="JSON config to override filters (banned_ext/path/stopwords/hot keywords)")

    args = p.parse_args(list(argv))

    if args.version:
        # use stdout only
        print(VERSION)
        sys.exit(0)

    if not args.domain:
        p.print_help()
        sys.exit(1)

    domain = normalize_domain(args.domain)

    return Options(
        domain=domain,
        wordlist=args.wordlist,
        threads=max(1, min(int(args.threads), 200)),
        verbose=bool(args.verbose),
        quiet=bool(args.quiet),
        no_color=bool(args.no_color),
        fmt=str(args.fmt),
        output=args.output,
        no_report=bool(args.no_report),
        timeout=float(args.timeout),
        retries=max(0, int(args.retries)),
        backoff=max(0.0, float(args.backoff)),
        max_urls=max(1000, int(args.max_urls)),
        wayback_limit=max(1, int(args.wayback_limit)),
        otx_pages=max(1, int(args.otx_pages)),
        use_wayback=not bool(args.no_wayback),
        use_hackertarget=not bool(args.no_hackertarget),
        use_otx=not bool(args.no_otx),
        ext_filter=not bool(args.no_ext_filter),
        path_filter=not bool(args.no_path_filter),
        stopwords_filter=not bool(args.no_stopwords),
        resolve_subdomains=bool(args.resolve_subdomains),
        config_path=args.config_path,
    )


def main(argv: Sequence[str]) -> int:
    opts = parse_args(argv)

    c = Colors(enabled=not opts.no_color)
    log = Logger(c, quiet=opts.quiet)

    if not is_domain_valid(opts.domain):
        log.err(f"Invalid domain: {opts.domain}")
        return 2

    banner(c, quiet=opts.quiet)

    cfg = None
    if opts.config_path:
        try:
            cfg = load_json_config(opts.config_path)
            log.ok(f"Loaded config: {opts.config_path}")
        except Exception as e:
            log.err(f"Failed to load config: {e}")
            return 2

    filters = Filters.from_defaults_and_config(cfg)

    # wordlist
    if opts.wordlist:
        dorks_raw = read_wordlist(opts.wordlist, log)
        log.ok(f"Wordlist: loaded {len(dorks_raw)} lines")
    else:
        dorks_raw = list(DEFAULT_DORKS)
        log.ok(f"Wordlist: using built-in defaults ({len(dorks_raw)} dorks)")

    eng = Engine(opts=opts, filters=filters, log=log)

    try:
        total = eng.harvest(opts.domain)
    except KeyboardInterrupt:
        log.warn("Interrupted")
        return 130

    if total == 0:
        return 1

    try:
        results = eng.match(dorks_raw, opts.domain)
    except KeyboardInterrupt:
        log.warn("Interrupted")
        return 130

    crit = sum(1 for r in results if r.get("severity") == "CRITICAL")
    high = sum(1 for r in results if r.get("severity") == "HIGH")
    norm = len(results) - crit - high

    if results:
        log.ok(f"Done: {len(results)} results (CRITICAL: {crit}, HIGH: {high}, NORMAL: {norm})")

        # preview
        if not opts.quiet:
            shown = 0
            for r in results:
                if shown >= 30:
                    break
                if r.get("severity") == "CRITICAL":
                    log.crit(r.get("url", ""))
                    shown += 1
                elif r.get("severity") == "HIGH":
                    log.high(r.get("url", ""))
                    shown += 1

            if shown == 0:
                for r in results[:15]:
                    log.info(r.get("url", ""))
                shown = min(15, len(results))

            if len(results) > shown:
                log.info(f"+{len(results) - shown} more results in the report")

    else:
        log.warn("No matches found")

    # report
    if opts.no_report:
        return 0

    if results:
        content = build_report(opts.fmt, opts.domain, results)

        # stdout
        if opts.output == "-":
            # if quiet, still emit report
            print(content)
            return 0

        out_path = opts.output or default_report_name(opts.domain, opts.fmt)
        try:
            write_output(out_path, content)
            log.ok(f"Report saved: {out_path}")
        except Exception as e:
            log.err(f"Failed to write report: {e}")
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
