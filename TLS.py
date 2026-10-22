import os, sys, json, random, uuid, time, gzip, zlib, threading, asyncio, concurrent.futures, re, urllib.parse, gc
from pathlib import Path
for pkg in ["tls_client", "uvicorn", "fastapi", "brotli", "zstandard", "curl_cffi", "httpx[http2]"]:
    try:
        __import__(pkg.replace("-", "_").split("[")[0])
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
import tls_client
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
try:
    from curl_cffi.requests import Session as CurlSession
    HAS_CURL = True
except ImportError:
    HAS_CURL = False
try:
    import brotli as _brotli; HAS_BROTLI = True
except: HAS_BROTLI = False
try:
    import zstandard as _zstd; HAS_ZSTD = True
except: HAS_ZSTD = False
try:
    import httpx; HAS_HTTPX = True
except: HAS_HTTPX = False
PORT = int(os.environ.get("PORT", 9000))
TIMEOUT = 30
SESSION_TTL = 300
MAX_REDIRECTS = 15
MAX_CONCURRENT = 100
_req_sem = asyncio.Semaphore(MAX_CONCURRENT)
PROXY_CACHE = {}
_STICKY_PROVIDERS = {
    "dataimpulse.com":   lambda u, s: f"{u}__sid.{s[:12]}",
    "brightdata.com":    lambda u, s: f"{u}-session-{s[:12]}",
    "brightproxies.com": lambda u, s: f"{u}-session-{s[:12]}",
    "oxylabs.io":        lambda u, s: f"{u}-sessid-{s[:12]}",
    "iproyal.com":       lambda u, s: f"{u}_session-{s[:12]}",
    "smartproxy.com":    lambda u, s: f"{u}-sessid-{s[:12]}",
}
def _make_sticky_proxy(proxy_url: str, session_id: str) -> str:
    if not proxy_url:
        return proxy_url
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(proxy_url)
        host = (parsed.hostname or "").lower()
        for domain, inject in _STICKY_PROVIDERS.items():
            if domain in host:
                netloc = parsed.netloc
                if "@" not in netloc:
                    return proxy_url
                auth, hostport = netloc.rsplit("@", 1)
                user, _, pwd = auth.partition(":")
                if any(k in user for k in ("__sid", "-session-", "-sessid-", "_session-")):
                    return proxy_url
                sid_clean = session_id.replace("-", "")
                new_netloc = f"{inject(user, sid_clean)}:{pwd}@{hostport}"
                return urlunparse((parsed.scheme, new_netloc, "", "", "", ""))
    except Exception:
        pass
    return proxy_url
def normalize_proxy(raw):
    if not raw:
        return None, False
    p = str(raw).strip().strip('"').strip("'")
    if p.lower() in {"", ":@:", "null", "none", "false", "off", "direct",
                     "no_proxy", "localhost", "127.0.0.1", "0.0.0.0", "undefined", "nil", "0"}:
        return None, False
    if p.startswith("<") and p.endswith(">"):
        return None, False
    if p in PROXY_CACHE:
        return PROXY_CACHE[p]
    scheme = "http"
    if "://" in p:
        sc, rest = p.split("://", 1)
        sc = sc.lower()
        if sc in ("http", "https", "socks4", "socks4a", "socks5", "socks5h"):
            scheme = sc
        p = rest
    is_socks = scheme in ("socks4", "socks4a", "socks5", "socks5h")
    if "@" in p:
        auth, host_port = p.rsplit("@", 1)
        user, pwd = auth, ""
        if ":" in auth:
            user, pwd = auth.split(":", 1)
        host, port = host_port, ""
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)
        if port and port.isdigit() and 1 <= int(port) <= 65535:
            result = f"{scheme}://{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(pwd, safe='')}@{host}:{port}"
            PROXY_CACHE[p] = (result, is_socks)
            return result, is_socks
        result = f"{scheme}://{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(pwd, safe='')}@{host_port}"
        PROXY_CACHE[p] = (result, is_socks)
        return result, is_socks
    parts = p.split(":")
    n = len(parts)
    if n == 2:
        host, port = parts[0], parts[1]
        if port.isdigit() and 1 <= int(port) <= 65535:
            result = f"{scheme}://{host}:{port}"
            PROXY_CACHE[p] = (result, is_socks)
            return result, is_socks
        result = f"{scheme}://{p}"
        PROXY_CACHE[p] = (result, is_socks)
        return result, is_socks
    if n == 4:
        p3_is_port = parts[3].isdigit() and 1 <= len(parts[3]) <= 5
        if p3_is_port:
            user, pwd, host, port = parts[0], parts[1], parts[2], parts[3]
            result = f"{scheme}://{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(pwd, safe='')}@{host}:{port}"
            PROXY_CACHE[p] = (result, is_socks)
            return result, is_socks
        p1_is_port = parts[1].isdigit() and 1 <= len(parts[1]) <= 5
        if p1_is_port:
            host, port, user, pwd = parts[0], parts[1], parts[2], parts[3]
            result = f"{scheme}://{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(pwd, safe='')}@{host}:{port}"
            PROXY_CACHE[p] = (result, is_socks)
            return result, is_socks
    if n == 3:
        if parts[1].isdigit() and 1 <= len(parts[1]) <= 5:
            result = f"{scheme}://{parts[0]}:{parts[1]}"
            PROXY_CACHE[p] = (result, is_socks)
            return result, is_socks
        user, pwd, host = parts[0], parts[1], parts[2]
        result = f"{scheme}://{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(pwd, safe='')}@{host}"
        PROXY_CACHE[p] = (result, is_socks)
        return result, is_socks
    if p.startswith("[") and "]" in p:
        ipv6_part, rest = p.split("]", 1)
        ipv6 = ipv6_part[1:]
        port = rest.lstrip(":")
        if port.isdigit():
            result = f"{scheme}://[{ipv6}]:{port}"
            PROXY_CACHE[p] = (result, is_socks)
            return result, is_socks
        result = f"{scheme}://[{ipv6}]"
        PROXY_CACHE[p] = (result, is_socks)
        return result, is_socks
    result = f"{scheme}://{p}"
    PROXY_CACHE[p] = (result, is_socks)
    return result, is_socks
def extract_proxy(headers_dict):
    for k in ("x-tp-proxy", "x-tp-proxie", "x-tp-proxies", "x-proxy", "proxy", "x-tp-p", "x-tp-prx", "x-tp-proxi"):
        v = headers_dict.get(k)
        if v:
            p = str(v).strip().strip('"').strip("'")
            if p and p.lower() not in {"", ":@:", "null", "none", "false", "off", "direct", "no_proxy", "undefined", "0"}:
                return p
    return None
def parse_ua(ua):
    if not ua:
        return ("chrome", 0)
    u = ua.lower()
    m = re.search(r'chrome/(\d+)', u)
    if m:
        return ("chrome", int(m.group(1)))
    m = re.search(r'firefox/(\d+)', u)
    if m:
        return ("firefox", int(m.group(1)))
    m = re.search(r'edg/(\d+)', u)
    if m:
        return ("edge", int(m.group(1)))
    if "safari" in u and "chrome" not in u:
        m = re.search(r'version/(\d+)', u)
        if m:
            return ("safari", int(m.group(1)))
        m = re.search(r'os (\d+)_\d+', u)
        if m:
            return ("safari", int(m.group(1)))
        return ("safari", 0)
    if "opera" in u or "opr" in u:
        return ("opera", 0)
    return ("chrome", 0)
def is_mobile_ua(ua):
    if not ua:
        return False
    u = ua.lower()
    return any(x in u for x in ["android", "iphone", "ipad", "ios", "mobile"])
def generate_client_hints(browser, ver, ua_str):
    hints = {}
    if browser == "chrome":
        hints["sec-ch-ua"] = f'"Not(A:Brand";v="24", "Chromium";v="{ver}", "Google Chrome";v="{ver}"'
        hints["sec-ch-ua-mobile"] = "?0"
        hints["sec-ch-ua-platform"] = '"Windows"'
        hints["sec-ch-ua-bitness"] = '"64"'
        hints["sec-ch-ua-arch"] = '"x86"'
        hints["sec-ch-ua-full-version"] = f'"{ver}.0.0.0"'
        hints["sec-ch-ua-full-version-list"] = f'"Not(A:Brand";v="24.0.0.0", "Chromium";v="{ver}.0.0.0", "Google Chrome";v="{ver}.0.0.0"'
        hints["sec-ch-ua-platform-version"] = '"15.0.0"'
        hints["sec-ch-ua-model"] = '""'
    elif browser == "edge":
        hints["sec-ch-ua"] = f'"Not(A:Brand";v="24", "Chromium";v="{ver}", "Microsoft Edge";v="{ver}"'
        hints["sec-ch-ua-mobile"] = "?0"
        hints["sec-ch-ua-platform"] = '"Windows"'
        hints["sec-ch-ua-bitness"] = '"64"'
        hints["sec-ch-ua-arch"] = '"x86"'
        hints["sec-ch-ua-full-version"] = f'"{ver}.0.0.0"'
        hints["sec-ch-ua-full-version-list"] = f'"Not(A:Brand";v="24.0.0.0", "Chromium";v="{ver}.0.0.0", "Microsoft Edge";v="{ver}.0.0.0"'
        hints["sec-ch-ua-platform-version"] = '"15.0.0"'
        hints["sec-ch-ua-model"] = '""'
    elif browser == "firefox":
        hints["sec-ch-ua"] = '"", "Not_A Brand";v="99"'
        hints["sec-ch-ua-mobile"] = "?0"
        hints["sec-ch-ua-platform"] = '"Windows"'
        hints["sec-ch-ua-bitness"] = '"64"'
        hints["sec-ch-ua-arch"] = '"x86"'
    elif browser == "safari":
        hints["sec-ch-ua"] = '""'
        hints["sec-ch-ua-mobile"] = "?0" if "iphone" not in ua_str.lower() else "?1"
        hints["sec-ch-ua-platform"] = '"macOS"' if "macintosh" in ua_str.lower() else '"iOS"'
        hints["sec-ch-ua-bitness"] = '"64"'
        hints["sec-ch-ua-arch"] = '"arm"' if "iphone" in ua_str.lower() else '"x86"'
    else:
        hints["sec-ch-ua"] = '"Not(A:Brand";v="24", "Chromium";v="131", "Google Chrome";v="131"'
        hints["sec-ch-ua-mobile"] = "?0"
        hints["sec-ch-ua-platform"] = '"Windows"'
    return hints
def find_best_profile(browser, ver, profiles):
    pool = []
    for p in profiles:
        tid = p.get("tls_id", p.get("impersonate", "")).lower()
        if browser in tid:
            pool.append(p)
    if not pool:
        if browser == "firefox":
            pool = [p for p in profiles if "firefox" in p.get("tls_id", p.get("impersonate", "")).lower()]
        elif browser == "safari":
            pool = [p for p in profiles if "safari" in p.get("tls_id", p.get("impersonate", "")).lower()]
        elif browser == "edge":
            pool = [p for p in profiles if "edge" in p.get("tls_id", p.get("impersonate", "")).lower()]
        else:
            pool = [p for p in profiles if "chrome" in p.get("tls_id", p.get("impersonate", "")).lower()]
    if not pool:
        return random.choice(profiles) if profiles else None
    best = pool[0]
    bd = float('inf')
    for p in pool:
        m = re.search(r'(\d+)', p.get("tls_id", p.get("impersonate", "")))
        if m:
            d = abs(int(m.group(1)) - ver)
            if d < bd:
                bd = d
                best = p
    return best
def parse_cookies(cookie_str):
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
        else:
            cookies[part] = ""
    return cookies
def build_cookies(cookies_dict):
    if not cookies_dict:
        return ""
    return "; ".join(f"{k}={v}" for k, v in cookies_dict.items())
def merge_cookies(existing, new):
    merged = dict(existing) if existing else {}
    if new:
        merged.update(new)
    return merged
def _norm_name(name):
    n = name.lower().strip().replace("_", "").replace("-", "").replace(" ", "")
    for prefix in ["tls", "curl"]:
        if n.startswith(prefix):
            n = n[len(prefix):]
    return n
def _extract_browser_ver(n):
    prefixes = ["okhttp", "firefox", "chrome", "edge", "safari", "opera", "tor"]
    for prefix in prefixes:
        if n.startswith(prefix):
            rest = n[len(prefix):]
            nums = re.findall(r'(\d+)', rest)
            if nums:
                return (prefix, int(nums[0]))
            return (prefix, 0)
    return (n, 0)
CURL_PROFILES = {
    "chrome99":  {"impersonate": "chrome99",  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36"},
    "chrome100":  {"impersonate": "chrome100",  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36"},
    "chrome101":  {"impersonate": "chrome101",  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36"},
    "chrome104":  {"impersonate": "chrome104",  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36"},
    "chrome107":  {"impersonate": "chrome107",  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36"},
    "chrome110":  {"impersonate": "chrome110",  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36"},
    "chrome116":  {"impersonate": "chrome116",  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.188 Safari/537.36"},
    "edge99":  {"impersonate": "edge99",  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.30"},
    "edge101": {"impersonate": "edge101", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.32"},
    "safari153": {"impersonate": "safari153", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"},
    "safari155": {"impersonate": "safari155", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15"},
    "safari170": {"impersonate": "safari170", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"},
    "safari180": {"impersonate": "safari180", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"},
    "safari184": {"impersonate": "safari184", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15"},
    "safari260": {"impersonate": "safari260", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15"},
    "safari2601": {"impersonate": "safari2601", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15"},
    "safari172_ios": {"impersonate": "safari172_ios", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"},
    "safari180_ios": {"impersonate": "safari180_ios", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"},
    "safari184_ios": {"impersonate": "safari184_ios", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1"},
    "safari260_ios": {"impersonate": "safari260_ios", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"},
    "firefox133": {"impersonate": "firefox133", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"},
    "firefox135": {"impersonate": "firefox135", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"},
    "firefox144": {"impersonate": "firefox144", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"},
    "firefox147": {"impersonate": "firefox147", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0"},
    "tor145": {"impersonate": "tor145", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"},
}
TLS_PROFILES = [
    {"tls_id": "chrome_100", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36"},
    {"tls_id": "chrome_101", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36"},
    {"tls_id": "chrome_103", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36"},
    {"tls_id": "chrome_104", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36"},
    {"tls_id": "chrome_105", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36"},
    {"tls_id": "chrome_106", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.103 Safari/537.36"},
    {"tls_id": "chrome_107", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36"},
    {"tls_id": "chrome_108", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.124 Safari/537.36"},
    {"tls_id": "chrome_109", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.119 Safari/537.36"},
    {"tls_id": "chrome_110", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36"},
    {"tls_id": "chrome_111", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.64 Safari/537.36"},
    {"tls_id": "chrome_112", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.49 Safari/537.36"},
    {"tls_id": "chrome_116", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.188 Safari/537.36"},
    {"tls_id": "chrome_116_PSK", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.188 Safari/537.36"},
    {"tls_id": "chrome_116_PSK_PQ", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.188 Safari/537.36"},
    {"tls_id": "chrome_117", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.62 Safari/537.36"},
    {"tls_id": "chrome_119", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"},
    {"tls_id": "chrome_120", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
    {"tls_id": "chrome_123", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"},
    {"tls_id": "chrome_124", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"},
    {"tls_id": "chrome_131", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
    {"tls_id": "chrome_133", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"},
    {"tls_id": "chrome_144", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"},
    {"tls_id": "chrome_146", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"},
    {"tls_id": "edge_99",  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.30"},
    {"tls_id": "edge_101", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.32"},
    {"tls_id": "safari_15_3",  "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"},
    {"tls_id": "safari_15_6_1", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15"},
    {"tls_id": "safari_16_0",  "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"},
    {"tls_id": "safari_18_0",  "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"},
    {"tls_id": "safari_18_4",  "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15"},
    {"tls_id": "safari_26_0",  "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15"},
    {"tls_id": "safari_ipad_15_6", "ua": "Mozilla/5.0 (iPad; CPU OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1"},
    {"tls_id": "safari_ios_15_5",  "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1"},
    {"tls_id": "safari_ios_15_6",  "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1"},
    {"tls_id": "safari_ios_16_0",  "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"},
    {"tls_id": "safari_ios_17_2",  "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"},
    {"tls_id": "safari_ios_18_0",  "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"},
    {"tls_id": "safari_ios_18_4",  "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1"},
    {"tls_id": "safari_ios_26_0",  "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"},
    {"tls_id": "firefox_102", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"},
    {"tls_id": "firefox_104", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"},
    {"tls_id": "firefox_105", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"},
    {"tls_id": "firefox_106", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"},
    {"tls_id": "firefox_108", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0"},
    {"tls_id": "firefox_110", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0"},
    {"tls_id": "firefox_117", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0"},
    {"tls_id": "firefox_120", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"},
    {"tls_id": "firefox_133", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"},
    {"tls_id": "firefox_135", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"},
    {"tls_id": "firefox_144", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"},
    {"tls_id": "firefox_147", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0"},
    {"tls_id": "opera_89", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36 OPR/89.0.4447.51"},
    {"tls_id": "opera_90", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36 OPR/90.0.4480.54"},
    {"tls_id": "opera_91", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 OPR/91.0.4516.20"},
    {"tls_id": "zalando_ios_mobile", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"},
    {"tls_id": "nike_ios_mobile", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"},
    {"tls_id": "mms_ios", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"},
    {"tls_id": "mms_ios_2", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"},
    {"tls_id": "mms_ios_3", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"},
    {"tls_id": "mesh_ios", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"},
    {"tls_id": "mesh_ios_2", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"},
    {"tls_id": "confirmed_ios", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"},
]
CURL_BY_NORM = {}
for k, p in CURL_PROFILES.items():
    norm = _norm_name(k)
    CURL_BY_NORM[norm] = p
    browser, ver = _extract_browser_ver(norm)
    if browser and ver:
        CURL_BY_NORM[f"{browser}{ver}"] = p
TLS_BY_NORM = {}
for p in TLS_PROFILES:
    tid = p.get("tls_id", "")
    norm = _norm_name(tid)
    TLS_BY_NORM[norm] = p
    browser, ver = _extract_browser_ver(norm)
    if browser and ver:
        TLS_BY_NORM[f"{browser}{ver}"] = p
CURL_DESKTOP_PROFILES = {}
CURL_MOBILE_PROFILES = {}
for k, p in CURL_PROFILES.items():
    if any(x in k for x in ["android", "ios", "ipad", "mobile", "okhttp"]):
        CURL_MOBILE_PROFILES[k] = p
    else:
        CURL_DESKTOP_PROFILES[k] = p
TLS_DESKTOP_PROFILES = []
TLS_MOBILE_PROFILES = []
for p in TLS_PROFILES:
    tid = p.get("tls_id", "")
    if any(tid.startswith(x) for x in ["chrome_", "edge_", "firefox_"]) or (tid.startswith("safari_") and "ios" not in tid and "ipad" not in tid):
        TLS_DESKTOP_PROFILES.append(p)
    elif any(x in tid for x in ["android", "ios", "ipad"]):
        TLS_MOBILE_PROFILES.append(p)
    elif "opera" in tid:
        TLS_DESKTOP_PROFILES.append(p)
    elif any(x in tid for x in ["okhttp", "zalando", "nike", "mms", "mesh", "confirmed"]):
        TLS_MOBILE_PROFILES.append(p)
CURL_BROWSER_PROFILES = {}
for k, p in CURL_DESKTOP_PROFILES.items():
    if any(x in k for x in ["chrome", "edge", "firefox", "safari", "opera", "tor"]):
        CURL_BROWSER_PROFILES[k] = p
TLS_BROWSER_PROFILES = []
for p in TLS_DESKTOP_PROFILES:
    tid = p.get("tls_id", "")
    if any(x in tid for x in ["chrome", "edge", "firefox", "safari", "opera"]):
        TLS_BROWSER_PROFILES.append(p)
ALL_CURL_PROFILES = list(CURL_PROFILES.values())
ALL_TLS_PROFILES = list(TLS_PROFILES)
ALL_CURL_MOBILE = list(CURL_MOBILE_PROFILES.values())
ALL_TLS_MOBILE = list(TLS_MOBILE_PROFILES)
ALL_CURL_BROWSER = list(CURL_BROWSER_PROFILES.values())
ALL_TLS_BROWSER = list(TLS_BROWSER_PROFILES)
LANGS = ["en-US,en;q=0.9", "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
         "fr-FR,fr;q=0.9,en;q=0.8", "de-DE,de;q=0.9,en;q=0.8",
         "pt-BR,pt;q=0.9,en;q=0.8", "it-IT,it;q=0.9,en;q=0.8"]
_sessions = {}
_curl_sessions = {}
_lock = threading.Lock()
_sticky_proxies = {}
_sticky_lock = threading.Lock()
_curl_lock = threading.Lock()
def _pick_random_profile(engine, mode):
    if engine == "curl":
        if mode == "randommobile":
            pool = ALL_CURL_MOBILE if ALL_CURL_MOBILE else ALL_CURL_PROFILES
        elif mode == "randombrowser":
            pool = ALL_CURL_BROWSER if ALL_CURL_BROWSER else ALL_CURL_PROFILES
        else:
            pool = ALL_CURL_PROFILES
        return random.choice(pool)
    else:
        if mode == "randommobile":
            pool = ALL_TLS_MOBILE if ALL_TLS_MOBILE else ALL_TLS_PROFILES
        elif mode == "randombrowser":
            pool = ALL_TLS_BROWSER if ALL_TLS_BROWSER else ALL_TLS_PROFILES
        else:
            pool = ALL_TLS_PROFILES
        return random.choice(pool)
def _pick_auto_profile(client_ua, engine):
    client_is_mobile = is_mobile_ua(client_ua)
    client_browser, client_ver = parse_ua(client_ua)
    if engine == "curl":
        if client_is_mobile:
            pool = ALL_CURL_MOBILE if ALL_CURL_MOBILE else ALL_CURL_PROFILES
        else:
            pool = ALL_CURL_BROWSER if ALL_CURL_BROWSER else ALL_CURL_PROFILES
        return find_best_profile(client_browser, client_ver, pool)
    else:
        if client_is_mobile:
            pool = ALL_TLS_MOBILE if ALL_TLS_MOBILE else ALL_TLS_PROFILES
        else:
            pool = ALL_TLS_BROWSER if ALL_TLS_BROWSER else ALL_TLS_PROFILES
        return find_best_profile(client_browser, client_ver, pool)
def _resolve_profile(mode, client_ua, engine):
    norm = _norm_name(mode)
    p = CURL_BY_NORM.get(norm)
    if not p:
        p = TLS_BY_NORM.get(norm)
    if not p:
        browser, ver = _extract_browser_ver(norm)
        if browser and ver:
            key = f"{browser}{ver}"
            p = CURL_BY_NORM.get(key)
            if not p:
                p = TLS_BY_NORM.get(key)
    return p
def get_stored_profile(sid, engine, mode, client_ua):
    store = _curl_sessions if engine == "curl" else _sessions
    lock = _curl_lock if engine == "curl" else _lock
    with lock:
        e = store.get(sid)
        if e and "sticky_profile" in e:
            return e["sticky_profile"]
        if mode in ("random", "randombrowser", "randommobile"):
            p = _pick_random_profile(engine, mode)
        elif mode == "auto":
            p = _pick_auto_profile(client_ua, engine)
        else:
            p = _resolve_profile(mode, client_ua, engine)
        if not p:
            p = _pick_random_profile(engine, "random")
        if e:
            e["sticky_profile"] = p
            e["ts"] = time.time()
        else:
            if engine == "curl":
                store[sid] = {"ts": time.time(), "cookies": {}, "sticky_profile": p, "imp": p.get("impersonate"), "ja3": p.get("ja3")}
            else:
                store[sid] = {"ts": time.time(), "profile": p, "lang": random.choice(LANGS), "cookies": {}, "sticky_profile": p}
        return p
def get_curl_sess(sid, imp=None, ja3=None):
    now = time.time()
    cache_key = f"{sid}:{imp or 'custom'}:{ja3 or 'none'}"
    with _curl_lock:
        e = _curl_sessions.get(cache_key)
        if e and (now - e["ts"]) < SESSION_TTL:
            e["ts"] = now
            return e["sess"]
        if imp:
            s = CurlSession(impersonate=imp, verify=False)
        else:
            s = CurlSession(verify=False)
        _curl_sessions[cache_key] = {
            "sess": s, "imp": imp or "custom", "ja3": ja3, "ts": now,
            "lang": random.choice(LANGS), "cookies": {}
        }
        return s
def get_tls_sess(sid, profile, force_new=False):
    now = time.time()
    with _lock:
        if not force_new:
            e = _sessions.get(sid)
            if e and e.get("profile") == profile and "sess" in e:
                e["ts"] = now
                return e["sess"]
        existing_cookies = _sessions.get(sid, {}).get("cookies", {}) if sid in _sessions else {}
        existing_lang = _sessions.get(sid, {}).get("lang", random.choice(LANGS)) if sid in _sessions else random.choice(LANGS)
        s = tls_client.Session(client_identifier=profile["tls_id"], random_tls_extension_order=True)
        _sessions[sid] = {"sess": s, "ts": now, "profile": profile, "lang": existing_lang, "cookies": existing_cookies}
        return s
def decompress(data, enc):
    e = (enc or "").lower()
    try:
        if "zstd" in e and HAS_ZSTD:
            return _zstd.ZstdDecompressor().stream_reader(data).read()
        if "br" in e and HAS_BROTLI:
            return _brotli.decompress(data)
        if "gzip" in e:
            return gzip.decompress(data)
        if "deflate" in e:
            try:
                return zlib.decompress(data)
            except:
                return zlib.decompress(data, -zlib.MAX_WBITS)
    except:
        pass
    return data
def _get_header_case_insensitive(hdrs_dict, key):
    key_lower = key.lower()
    for k, v in hdrs_dict.items():
        if k.lower() == key_lower:
            return v
    return None
from contextlib import asynccontextmanager
@asynccontextmanager
async def lifespan(app):
    loop = asyncio.get_event_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=500))
    asyncio.create_task(cleaner())
    yield
app = FastAPI(lifespan=lifespan)
async def cleaner():
    while True:
        await asyncio.sleep(60)
        now = time.time()
        with _lock:
            for k in [k for k, v in _sessions.items() if now - v["ts"] > SESSION_TTL]:
                del _sessions[k]
        with _curl_lock:
            for k in [k for k, v in _curl_sessions.items() if now - v["ts"] > SESSION_TTL]:
                try:
                    _curl_sessions.pop(k)["sess"].close()
                except:
                    pass
        gc.collect()
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str = ""):
    async with _req_sem:
        return await _proxy_core(request, path)
async def _proxy_core(request: Request, path: str = ""):
    sid = ""
    try:
        raw_headers = {}
        for raw_name, raw_val in request.headers.items():
            name = str(raw_name).strip()
            val = str(raw_val) if raw_val is not None else ""
            raw_headers[name] = val
        hdrs = {}
        for name, val in raw_headers.items():
            if " " in name and ":" in name:
                parts = name.split(" ")
                for part in parts:
                    if ":" in part:
                        k, v = part.split(":", 1)
                        hdrs[k.strip()] = v.strip()
                continue
            name_lower = name.lower()
            if name_lower in {"host", "x-tp-url", "x-tp-session", "x-tp-proxy",
                              "x-tp-proxie", "x-tp-proxies", "x-tp-useragent",
                              "x-tp-profile", "content-length",
                              "x-tp-redirects", "x-tp-sticky-session", "x-tp-proxy-fallback"}:
                continue
            hdrs[name] = val
        url = raw_headers.get("x-tp-url")
        if not url:
            with _lock:
                if sid in _sessions:
                    url = _sessions[sid].get("url")
            with _curl_lock:
                if not url and sid in _curl_sessions:
                    url = _curl_sessions[sid].get("url")
            if not url:
                return Response("Missing x-tp-url header", status_code=400)
        method = request.method.upper()
        sid = raw_headers.get("x-tp-session") or str(uuid.uuid4())
        client_ua = raw_headers.get("user-agent", "")
        x_ua = raw_headers.get("x-tp-useragent", "").lower().strip()
        keep_ua = x_ua in ("true", "1", "yes", "on") if x_ua else True
        x_tp_profile = raw_headers.get("x-tp-profile", "").strip()
        mode = x_tp_profile.lower().strip() if x_tp_profile else "auto"
        raw_proxy = extract_proxy({k.lower(): v for k, v in raw_headers.items()})
        proxy_url, is_socks = normalize_proxy(raw_proxy) if raw_proxy else (None, False)
        raw_fallback_proxy = raw_headers.get("x-tp-proxy-fallback", "").strip()
        has_fallback = bool(raw_fallback_proxy)
        if has_fallback:
            fallback_proxy_url, fallback_is_socks = normalize_proxy(raw_fallback_proxy)
        else:
            fallback_proxy_url, fallback_is_socks = None, False
        sticky = raw_headers.get("x-tp-sticky-session", "").lower() not in ("false", "0", "no", "off")
        if sticky:
            with _sticky_lock:
                _pinned = _sticky_proxies.get(sid)
                if not _pinned and proxy_url:
                    proxy_url = _make_sticky_proxy(proxy_url, sid)
                    _sticky_proxies[sid] = proxy_url
                elif _pinned:
                    proxy_url = _pinned
        body = await request.body()
        x_redir = raw_headers.get("x-tp-redirects", "true").lower().strip()
        follow_redirects = x_redir not in ("false", "0", "no", "off")
        session_cookies = {}
        with _lock:
            if sid in _sessions:
                session_cookies = dict(_sessions[sid].get("cookies", {}))
        with _curl_lock:
            if sid in _curl_sessions:
                session_cookies = merge_cookies(session_cookies, _curl_sessions[sid].get("cookies", {}))
        client_cookie_str = ""
        for k, v in list(hdrs.items()):
            if k.lower() == "cookie":
                client_cookie_str = v
                del hdrs[k]
                break
        client_cookies = parse_cookies(client_cookie_str)
        merged_cookies = merge_cookies(session_cookies, client_cookies)
        if merged_cookies:
            hdrs["Cookie"] = build_cookies(merged_cookies)
        parsed_url = urllib.parse.urlparse(url)
        target_host = parsed_url.netloc
        if target_host:
            for k in list(hdrs.keys()):
                if k.lower() == "host":
                    del hdrs[k]
            hdrs["Host"] = target_host
        if not any(k.lower() == "accept-language" for k in hdrs.keys()):
            lang = None
            with _lock:
                if sid in _sessions:
                    lang = _sessions[sid].get("lang")
            with _curl_lock:
                if not lang and sid in _curl_sessions:
                    lang = _curl_sessions[sid].get("lang")
            if not lang:
                lang = random.choice(LANGS)
                with _lock:
                    if sid in _sessions:
                        _sessions[sid]["lang"] = lang
                with _curl_lock:
                    if sid in _curl_sessions:
                        _curl_sessions[sid]["lang"] = lang
            hdrs["Accept-Language"] = lang
        if not any(k.lower() == "accept-encoding" for k in hdrs.keys()):
            encs = []
            if HAS_BROTLI:
                encs.append("br")
            encs.extend(["gzip", "deflate"])
            hdrs["Accept-Encoding"] = ", ".join(encs)
        resolved_tls = None
        resolved_curl = None
        specific_mode = False
        if mode and mode not in ("auto", "random", "randombrowser", "randommobile"):
            specific_mode = True
            norm = _norm_name(mode)
            resolved_curl = CURL_BY_NORM.get(norm)
            if not resolved_curl:
                resolved_tls = TLS_BY_NORM.get(norm)
            if not resolved_curl and not resolved_tls:
                browser, ver = _extract_browser_ver(norm)
                if browser and ver:
                    key = f"{browser}{ver}"
                    resolved_curl = CURL_BY_NORM.get(key)
                    if not resolved_curl:
                        resolved_tls = TLS_BY_NORM.get(key)
            if resolved_curl and HAS_CURL:
                engines = ["curl"]
            elif resolved_tls:
                engines = ["tls"]
                if HAS_HTTPX:
                    engines.append("httpx")
            else:
                specific_mode = False
                mode = "auto"
        if not specific_mode:
            if is_socks:
                if HAS_CURL:
                    engines = ["curl"]
                else:
                    return JSONResponse({"success": False, "error": "SOCKS requiere curl_cffi"}, status_code=200)
            else:
                engines = []
                if HAS_CURL:
                    engines.append("curl")
                engines.append("tls")
                if HAS_HTTPX:
                    engines.append("httpx")
        async def do_req(proxy, engine):
            send_hdrs = {str(k): str(v) for k, v in hdrs.items()}
            p = None
            pname = "unknown"
            if specific_mode:
                if engine == "curl" and resolved_curl and HAS_CURL:
                    p = resolved_curl
                    pname = p.get("impersonate") or mode
                elif engine == "tls" and resolved_tls:
                    p = resolved_tls
                    pname = p.get("tls_id", mode)
                else:
                    p = get_stored_profile(sid, engine, mode, client_ua)
                    pname = p.get("impersonate") or p.get("tls_id", "fallback")
            else:
                p = get_stored_profile(sid, engine, mode, client_ua)
                pname = p.get("impersonate") or p.get("tls_id", mode)
            for k in list(send_hdrs.keys()):
                if k.lower() == "user-agent":
                    del send_hdrs[k]
            if keep_ua:
                if client_ua:
                    send_hdrs["User-Agent"] = client_ua
            else:
                profile_ua = p.get("ua", "")
                if profile_ua:
                    send_hdrs["User-Agent"] = profile_ua
                elif client_ua:
                    send_hdrs["User-Agent"] = client_ua
            current_ua = _get_header_case_insensitive(send_hdrs, "user-agent") or ""
            pb, pv = parse_ua(current_ua)
            hints = generate_client_hints(pb, pv, current_ua)
            for hk, hv in hints.items():
                if not any(k.lower() == hk.lower() for k in send_hdrs.keys()):
                    send_hdrs[hk] = hv
            if not any(k.lower() == "dnt" for k in send_hdrs.keys()):
                send_hdrs["DNT"] = "1"
            if not any(k.lower() == "sec-gpc" for k in send_hdrs.keys()):
                send_hdrs["Sec-GPC"] = "1"
            if not any(k.lower() == "cache-control" for k in send_hdrs.keys()):
                send_hdrs["Cache-Control"] = "max-age=0"
            if not any(k.lower() == "pragma" for k in send_hdrs.keys()):
                send_hdrs["Pragma"] = "no-cache"
            if not any(k.lower() == "upgrade-insecure-requests" for k in send_hdrs.keys()):
                send_hdrs["Upgrade-Insecure-Requests"] = "1"
            if pb in ("chrome", "edge"):
                if not any(k.lower() == "sec-fetch-dest" for k in send_hdrs.keys()):
                    send_hdrs["Sec-Fetch-Dest"] = "document"
                if not any(k.lower() == "sec-fetch-mode" for k in send_hdrs.keys()):
                    send_hdrs["Sec-Fetch-Mode"] = "navigate"
                if not any(k.lower() == "sec-fetch-site" for k in send_hdrs.keys()):
                    send_hdrs["Sec-Fetch-Site"] = "same-origin"
                if not any(k.lower() == "sec-fetch-user" for k in send_hdrs.keys()):
                    send_hdrs["Sec-Fetch-User"] = "?1"
            elif pb == "firefox":
                if not any(k.lower() == "sec-fetch-dest" for k in send_hdrs.keys()):
                    send_hdrs["Sec-Fetch-Dest"] = "document"
                if not any(k.lower() == "sec-fetch-mode" for k in send_hdrs.keys()):
                    send_hdrs["Sec-Fetch-Mode"] = "navigate"
                if not any(k.lower() == "sec-fetch-site" for k in send_hdrs.keys()):
                    send_hdrs["Sec-Fetch-Site"] = "same-origin"
            if pb in ("chrome", "edge") and pv >= 120:
                if not any(k.lower() == "priority" for k in send_hdrs.keys()):
                    send_hdrs["Priority"] = "u=0, i"
            final_ua = _get_header_case_insensitive(send_hdrs, "user-agent") or ""
            if engine == "curl":
                if not HAS_CURL:
                    raise Exception("curl_cffi not available")
                imp = p.get("impersonate") if p else None
                ja3 = p.get("ja3") if p else None
                s = get_curl_sess(sid, imp=imp, ja3=ja3)
                def _call():
                    kw = {"headers": send_hdrs, "allow_redirects": follow_redirects, "timeout": TIMEOUT}
                    if proxy:
                        kw["proxies"] = {"https": proxy, "http": proxy}
                    if body and method not in ("GET", "HEAD", "OPTIONS"):
                        kw["data"] = body
                    if ja3:
                        kw["ja3"] = ja3
                    return s.request(method, url, **kw)
                return (await asyncio.to_thread(_call)), pname, final_ua
            elif engine == "tls":
                tls_timeout = TIMEOUT * 2 if proxy else TIMEOUT
                s = get_tls_sess(sid, p)
                def _call():
                    return s.execute_request(
                        method=method,
                        url=url,
                        headers=send_hdrs,
                        proxy=proxy,
                        data=body if body and method not in ("GET", "HEAD", "OPTIONS") else None,
                        allow_redirects=follow_redirects,
                        timeout_seconds=tls_timeout,
                    )
                try:
                    r = await asyncio.to_thread(_call)
                    return r, pname, final_ua
                except Exception as ex:
                    err_str = str(ex).lower()
                    if proxy and any(x in err_str for x in ["timeout", "proxy", "connect", "dial", "refused", "closed", "reset", "tunnel"]):
                        with _lock:
                            if sid in _sessions:
                                del _sessions[sid]
                        s = get_tls_sess(sid, p, force_new=True)
                        def _call2():
                            return s.execute_request(
                                method=method,
                                url=url,
                                headers=send_hdrs,
                                proxy=proxy,
                                data=body if body and method not in ("GET", "HEAD", "OPTIONS") else None,
                                allow_redirects=follow_redirects,
                                timeout_seconds=tls_timeout,
                            )
                        r = await asyncio.to_thread(_call2)
                        return r, pname, final_ua
                    raise
            elif engine == "httpx":
                if not HAS_HTTPX:
                    raise Exception("httpx not available")
                def _call():
                    proxies = {"https://": proxy, "http://": proxy} if proxy else None
                    with httpx.Client(proxies=proxies, timeout=TIMEOUT, follow_redirects=follow_redirects, http2=True) as client:
                        return client.request(method, url, headers=send_hdrs,
                                            content=body if body and method not in ("GET", "HEAD", "OPTIONS") else None)
                return (await asyncio.to_thread(_call)), pname, final_ua
        resp = None
        last_err = None
        used_proxy = proxy_url
        start_time = time.time()
        used_engine = None
        used_profile = "unknown"
        used_ua = ""
        for engine in engines:
            remaining = (TIMEOUT + 2) - (time.time() - start_time)
            if remaining <= 0:
                last_err = last_err or "Global timeout exceeded"
                break
            try:
                resp, used_profile, used_ua = await asyncio.wait_for(do_req(used_proxy, engine), timeout=remaining)
                used_engine = engine
                break
            except asyncio.TimeoutError:
                last_err = f"Timeout in {engine}"
                continue
            except Exception as ex:
                last_err = f"{engine}: {str(ex)}"
                continue
        if not resp and has_fallback:
            used_proxy = fallback_proxy_url
            start_time = time.time()
            for engine in engines:
                remaining = (TIMEOUT + 2) - (time.time() - start_time)
                if remaining <= 0:
                    break
                try:
                    resp, used_profile, used_ua = await asyncio.wait_for(do_req(used_proxy, engine), timeout=remaining)
                    used_engine = engine
                    break
                except asyncio.TimeoutError:
                    last_err = f"Fallback timeout in {engine}"
                    continue
                except Exception as ex:
                    last_err = f"Fallback {engine}: {str(ex)}"
                    continue
        if not resp:
            err_msg = last_err or "Request failed"
            if proxy_url and any(x in err_msg.lower() for x in ["refused", "timeout", "no connection", "dial tcp", "proxy"]):
                err_msg = f"Proxy error: {err_msg}"
            return JSONResponse(
                {"success": False, "error": err_msg, "proxy": bool(proxy_url),
                 "url": url, "attempts": 1},
                status_code=200,
            )
        new_cookies = {}
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                cookie_part = v.split(";")[0].strip()
                if "=" in cookie_part:
                    ck, cv = cookie_part.split("=", 1)
                    new_cookies[ck.strip()] = cv.strip()
        with _lock:
            if sid in _sessions:
                existing = _sessions[sid].get("cookies", {})
                _sessions[sid]["cookies"] = merge_cookies(existing, new_cookies)
        with _curl_lock:
            if sid in _curl_sessions:
                existing = _curl_sessions[sid].get("cookies", {})
                _curl_sessions[sid]["cookies"] = merge_cookies(existing, new_cookies)
        final_url = url
        try:
            if hasattr(resp, "url") and resp.url:
                final_url = str(resp.url)
        except Exception:
            pass
        with _lock:
            if sid in _sessions:
                _sessions[sid]["url"] = final_url
        with _curl_lock:
            if sid in _curl_sessions:
                _curl_sessions[sid]["url"] = final_url
        raw_content = resp.content if resp.content is not None else b""
        dec = decompress(raw_content, resp.headers.get("content-encoding", ""))
        if dec is None:
            dec = b""
        out = Response(content=dec, status_code=resp.status_code)
        for k, v in resp.headers.items():
            lk = k.lower()
            if lk not in {"content-encoding", "transfer-encoding", "content-length", "connection"}:
                out.headers[k] = str(v)
        out.headers["x-tp-final-url"] = final_url
        try:
            text_content = dec.decode('utf-8', errors='ignore') if dec else ""
            if "cf-ray" in text_content.lower() or "cloudflare" in text_content.lower() or "challenge-platform" in text_content.lower():
                out.headers["X-WAF-Detected"] = "cloudflare"
        except:
            pass
        if has_fallback and used_proxy == fallback_proxy_url:
            conn = "FALLBACK"
        elif sticky and proxy_url:
            conn = "STICKY"
        elif proxy_url:
            conn = "PROXY"
        else:
            conn = "DIRECT"
        ua_log = used_ua[:90] if used_ua else "EMPTY"
        print(f"[{sid}] - [{resp.status_code}] - [{method}] [{url}] - [BROWSER={used_profile}] - [ENGINE={(used_engine or 'NONE').upper()}] [CONNECTION={conn}]")
        return out
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return JSONResponse({"success": False, "error": str(e), "trace": tb}, status_code=200)
if __name__ == "__main__":
    print(f"[JOIN] [https://t.me/+xJcjMnq1Gw5jZWE0]")
    print("[RUNNING] [http://localhost:9000]")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="error", access_log=False, timeout_keep_alive=60)
