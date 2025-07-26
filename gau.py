#!/usr/bin/env python3

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Callable, Dict, Optional, Set
import urllib.parse as up
import requests
import re
import threading
import random
import tldextract
from pathlib import Path
import signal
import functools
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ------------------------------------------------------------------
# ANSI colours – bold everywhere
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[31;1m"
    GREEN   = "\033[32;1m"
    YELLOW  = "\033[33;1m"
    BLUE    = "\033[34;1m"
    MAGENTA = "\033[35;1m"
    CYAN    = "\033[36;1m"
    WHITE   = "\033[37;1m"

# ------------------------------------------------------------------
# Ctrl-C instant kill
def _sigint_handler(signum, frame):
    os._exit(0)
signal.signal(signal.SIGINT, _sigint_handler)
random.seed(42)

# ------------------------------------------------------------------
# fast HTTP layer
# Increased concurrency (default 150), can be configured with env var
MAX_THREADS = int(os.environ.get("GAU_THREADS", 150))
_LOCK = threading.Semaphore(MAX_THREADS)

session = requests.Session()
_adapter = HTTPAdapter(
    max_retries=Retry(
        total=3,
        backoff_factor=0.15,
        status_forcelist=[429, 500, 502, 503, 504],
    )
)
session.mount("http://", _adapter)
session.mount("https://", _adapter)
session.headers.update({"User-Agent": "gau++/2.0"})

def _get(url: str, params=None) -> requests.Response:
    with _LOCK:
        # Lower sleep for more aggressive fetching
        time.sleep(random.uniform(0.001, 0.01))
    r = session.get(url, params=params, timeout=20)
    r.raise_for_status()
    return r

# ------------------------------------------------------------------
# Data model
class WURL:
    __slots__ = ("date", "url", "status")
    def __init__(self, date: str, url: str, status: Optional[int]=None):
        self.date = date
        self.url = url
        self.status = status

# ------------------------------------------------------------------
# CLI
class ColorHelp(argparse.HelpFormatter):
    def _format_action(self, action):
        if action.dest == "help":
            return f"{C.CYAN}{action.option_strings[0]}{C.RESET}  {action.help}"
        return super()._format_action(action)

    def format_help(self):
        raw = super().format_help()
        raw = re.sub(r"(-\w)", rf"{C.GREEN}\1{C.RESET}", raw)
        raw = re.sub(r"(^positional arguments:|^optional arguments:)", rf"{C.BOLD}{C.YELLOW}\1{C.RESET}", raw, flags=re.M)
        return raw

def parse_args(argv: List[str]):
    p = argparse.ArgumentParser(
        description=f"{C.BOLD}{C.CYAN}Get All URLs – passive & fast{C.RESET}",
        formatter_class=ColorHelp,
        add_help=False
    )
    p.add_argument("domain", nargs="?", help="single target domain")
    p.add_argument("-h", "--help", action="help", help=f"{C.RED}show this help{C.RESET}\n\n")
    p.add_argument("-dl", metavar="FILE", help="file with list of domains (one per line)")
    p.add_argument("-d", nargs='?', const=True, help="show date column (optionally YYYY or YYYY:YYYY)")
    p.add_argument("-ns", action="store_true", help="don't include subdomains of the target")
    p.add_argument("-gv", "--get-versions", action="store_true", dest="get_versions",
                   help="list URLs for crawled versions of input URL(s)")
    p.add_argument("-f", metavar="FILTERS", help=f"comma list of {C.MAGENTA}https,params{C.RESET}")
    p.add_argument("-fc", metavar="CODES", nargs='?', const=True,
                   help="show status code; or keep only comma list CODES (passive)")
    p.add_argument("-fe", metavar="EXTS", help="include only URLs with these extensions")
    p.add_argument("-e", metavar="EXTS", help=f"comma list of extensions to {C.RED}exclude{C.RESET}")
    p.add_argument("-o", metavar="FILE", help="output file [txt|json]")
    p.add_argument("-r", metavar="SRCS", help=f"use only listed resources {C.CYAN}wbu,cc,otx,urlscan,cr,ht,rdns{C.RESET}")
    p.add_argument("-ss", action="store_true", help="show unique subdomains only")

    args = p.parse_args(argv)

    # --- validation -------------------------------------------------
    allowed_srcs = {"wbu", "cc", "vt", "otx", "urlscan", "cr", "ht", "rdns"}
    if args.r:
        bad = [s for s in args.r.split(",") if s.strip().lower() not in allowed_srcs]
        if bad:
            p.error(f"Invalid -r sources: {','.join(bad)}. Allowed: {','.join(allowed_srcs)}")

    if args.d and isinstance(args.d, str):
        if ":" in args.d:
            try:
                y1, y2 = map(int, args.d.split(":", 1))
                if y1 > y2:
                    raise ValueError
            except ValueError:
                p.error("-d range must be YYYY:YYYY with start ≤ end")
        else:
            if not args.d.isdigit() or len(args.d) != 4:
                p.error("-d must be YYYY or YYYY:YYYY")

    if args.fc and isinstance(args.fc, str):
        try:
            args.fc_codes = {int(c) for c in args.fc.split(",") if c}
        except ValueError:
            p.error("-fc expects comma-separated integers: 200,301,404")
    else:
        args.fc_codes = None

    return args

# ------------------------------------------------------------------
# Fetchers
FetchFn = Callable[[str, bool], List[WURL]]

# --- Wayback (with status) -------------------------------------------------
def get_wayback_urls(domain: str, no_subs: bool) -> List[WURL]:
    sub_wild = "*." if not no_subs else ""
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={sub_wild}{domain}/*&output=json&collapse=urlkey&fl=timestamp,original,statuscode"
    )
    try:
        resp = _get(url).json()
    except Exception:
        return []
    out = []
    for row in resp[1:]:
        ts, orig, st = row[0], row[1], (int(row[2]) if len(row) > 2 and str(row[2]).isdigit() else None)
        out.append(WURL(date=ts, url=orig, status=st))
    return out

# --- Common Crawl ----------------------------------------------------------
def get_commoncrawl_urls(domain: str, no_subs: bool) -> List[WURL]:
    sub_wild = "*." if not no_subs else ""
    url = (
        "https://index.commoncrawl.org/CC-MAIN-2023-50-index"
        f"?url={sub_wild}{domain}/*&output=json"
    )
    try:
        lines = _get(url).text.splitlines()
    except Exception:
        return []
    out = []
    for ln in lines:
        try:
            j = json.loads(ln)
            st = j.get("status")
            out.append(WURL(date=j["timestamp"], url=j["url"], status=int(st) if st else None))
        except Exception:
            continue
    return out

# --- VirusTotal ------------------------------------------------------------
def get_virustotal_urls(domain: str, no_subs: bool) -> List[WURL]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return []
    url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {"apikey": api_key, "domain": domain}
    try:
        j = _get(url, params=params).json()
    except Exception:
        return []
    urls = []
    for u in j.get("detected_urls", []) + j.get("undetected_urls", []):
        if isinstance(u, dict) and "url" in u:
            urls.append(WURL(date="", url=u["url"], status=None))
    return urls

# --- OTX -------------------------------------------------------------------
def get_otx_urls(domain: str, no_subs: bool) -> List[WURL]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=1000"
    try:
        j = _get(url).json()
    except Exception:
        return []
    return [WURL(date="", url=item["url"], status=None) for item in j.get("url_list", [])]

# --- URLScan ---------------------------------------------------------------
def get_urlscan_urls(domain: str, no_subs: bool) -> List[WURL]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    try:
        j = _get(url).json()
    except Exception:
        return []
    return [WURL(date="", url=item["page"]["url"], status=None) for item in j.get("results", [])]

# --- crt.sh ----------------------------------------------------------------
def get_crtsh_urls(domain: str, no_subs: bool) -> List[WURL]:
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        resp = _get(url).json()
    except Exception:
        return []
    seen = set()
    out = []
    for entry in resp:
        for sub in (entry.get("name_value") or "").splitlines():
            sub = sub.strip().lstrip("*.")
            if not sub or sub in seen:
                continue
            seen.add(sub)
            if no_subs and sub != domain:
                continue
            out.append(WURL(date="", url=f"https://{sub}", status=None))
    return out

# --- HackerTarget pagelinks (NEW) ------------------------------------------
def get_hackertarget_urls(domain: str, no_subs: bool) -> List[WURL]:
    # Returns plain URLs, one per line
    url = f"https://api.hackertarget.com/pagelinks/?q={domain}"
    try:
        resp = _get(url).text
    except Exception:
        return []
    urls = []
    for line in resp.splitlines():
        u = line.strip()
        if u and not u.startswith("error"):
            urls.append(WURL(date="", url=u, status=None))
    return urls

# --- RapidDNS subdomain (NEW) ---------------------------------------------
def get_rapiddns_urls(domain: str, no_subs: bool) -> List[WURL]:
    # Returns a CSV, first column is subdomain
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        resp = _get(url).text
    except Exception:
        return []
    urls = []
    # Some lines might be HTML; extract with regex
    # Example: <td>sub.example.com</td><td>...</td>
    for match in re.findall(r'<td>([a-zA-Z0-9_.-]+\.' + re.escape(domain) + r')</td>', resp):
        u = f"https://{match.strip()}"
        urls.append(WURL(date="", url=u, status=None))
    # fallback: collect plain CSV lines
    for line in resp.splitlines():
        if ',' in line:
            parts = line.split(',')
            sub = parts[0].strip()
            if sub.endswith(domain):
                urls.append(WURL(date="", url=f"https://{sub}", status=None))
    return urls

# ------------------------------------------------------------------
# Helpers
def is_sub(raw_url: str, domain: str) -> bool:
    try:
        host = up.urlparse(raw_url).hostname or ""
        return host.lower() != domain.lower()
    except Exception:
        return False

def get_versions(u: str) -> List[str]:
    url = f"https://web.archive.org/cdx/search/cdx?url={u}&output=json"
    try:
        resp = _get(url).json()
    except Exception:
        return []
    out, seen = [], set()
    for row in resp[1:]:
        digest = row[5]
        if digest in seen:
            continue
        seen.add(digest)
        ts, orig = row[1], row[2]
        out.append(f"https://web.archive.org/web/{ts}if_/{orig}")
    return out

def passes_date(w: WURL, d_arg) -> bool:
    if d_arg is True or d_arg is None:
        return True
    try:
        year = int(w.date[:4])
        if ":" in str(d_arg):
            y1, y2 = map(int, str(d_arg).split(":", 1))
            return y1 <= year <= y2
        else:
            return year == int(d_arg)
    except Exception:
        return False

def passes_filters(url: str, filters: List[str]) -> bool:
    if not filters:
        return True
    if "https" in filters and not url.startswith("https"):
        return False
    if "params" in filters and "?" not in url:
        return False
    return True

def passes_extensions(url: str, include: List[str], exclude: List[str]) -> bool:
    path = up.urlparse(url).path.lower()
    if include:
        return any(path.endswith(f".{ext.strip().lower()}") for ext in include)
    if exclude:
        return not any(path.endswith(f".{ext.strip().lower()}") for ext in exclude)
    return True

def colour_status(code: Optional[int]) -> str:
    if code is None:
        return f"{C.BOLD}[{C.WHITE}-{C.RESET}{C.BOLD}]{C.RESET}"
    if 200 <= code < 300:
        return f"{C.BOLD}[{C.GREEN}{code}{C.RESET}{C.BOLD}]{C.RESET}"
    if 300 <= code < 400:
        return f"{C.BOLD}[{C.YELLOW}{code}{C.RESET}{C.BOLD}]{C.RESET}"
    if 400 <= code < 500:
        return f"{C.BOLD}[{C.RED}{code}{C.RESET}{C.BOLD}]{C.RESET}"
    if 500 <= code < 600:
        return f"{C.BOLD}[{C.MAGENTA}{code}{C.RESET}{C.BOLD}]{C.RESET}"
    return f"{C.BOLD}[{C.WHITE}{code}{C.RESET}{C.BOLD}]{C.RESET}"

def write_output(data: List[str], fmt: str, outfile: str):
    uniq = sorted(set(data), key=lambda x: x.lower())
    if fmt == "json":
        with open(outfile, "w") as fh:
            json.dump(uniq, fh, indent=2)
    else:
        with open(outfile, "w") as fh:
            fh.write("\n".join(uniq))

# ------------------------------------------------------------------
# Main
def main(argv: List[str] = None):
    argv = argv if argv is not None else sys.argv[1:]
    args = parse_args(argv)

    domains = []
    if args.dl:
        try:
            domains = [ln.strip() for ln in Path(args.dl).read_text().splitlines() if ln.strip()]
        except Exception as e:
            print(f"{C.RED}[!] -dl error: {e}{C.RESET}", file=sys.stderr)
            sys.exit(1)
    elif args.domain:
        domains = [args.domain]
    else:
        domains = [ln.strip() for ln in sys.stdin if ln.strip()]

    if not domains:
        print(f"{C.RED}[!] No domains supplied{C.RESET}", file=sys.stderr)
        sys.exit(1)

    if args.get_versions:
        for u in domains:
            for v in get_versions(u):
                print(v)
        return

    # Added 'ht' for HackerTarget, 'rdns' for RapidDNS
    resource_map = {
        "wbu": get_wayback_urls,
        "cc":  get_commoncrawl_urls,
        "vt":  get_virustotal_urls,
        "otx": get_otx_urls,
        "urlscan": get_urlscan_urls,
        "cr": get_crtsh_urls,
        "ht": get_hackertarget_urls,
        "rdns": get_rapiddns_urls,
    }
    srcs = resource_map.keys() if not args.r else [s.strip().lower() for s in str(args.r).split(",") if s.strip()]
    fetchers = [resource_map[s] for s in srcs if s in resource_map]

    filters = [f.lower().strip() for f in (args.f or "").split(",") if f] if args.f else []
    include_ext = [e.lower().strip() for e in (args.fe or "").split(",") if e] if args.fe else []
    exclude_ext = [e.lower().strip() for e in (args.e or "").split(",") if e] if args.e else []

    domains = sorted(set(domains))       # deterministic input order
    all_urls: List[str] = []
    subdomains: Set[str] = set()

    for domain in domains:
        results: Dict[str, WURL] = {}
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            future_to_fetch = {ex.submit(fn, domain, args.ns): fn for fn in fetchers}
            for f in as_completed(future_to_fetch):
                try:
                    for w in f.result():
                        if not passes_date(w, args.d):
                            continue
                        if args.ns and is_sub(w.url, domain):
                            continue
                        if not passes_extensions(w.url, include_ext, exclude_ext):
                            continue
                        if not passes_filters(w.url, filters):
                            continue
                        if args.fc_codes is not None and w.status not in args.fc_codes:
                            continue
                        results[w.url] = w
                        subdomains.add(tldextract.extract(w.url).fqdn)
                except Exception:
                    pass

        if args.ss:
            continue

        for w in results.values():
            prefix = ""
            if args.fc is not None:
                prefix = colour_status(w.status) + " "
            if args.d is not None and args.d is not False:
                try:
                    date_str = f"{C.BOLD}{C.CYAN}{datetime.strptime(w.date, '%Y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S')}{C.RESET} "
                except Exception:
                    date_str = ""
            else:
                date_str = ""
            all_urls.append(date_str + prefix + w.url)
            print(date_str + prefix + w.url)

    if args.ss:
        uniq_subs = sorted({s for s in subdomains if s})
        for sub in uniq_subs:
            print(f"{C.BOLD}{C.GREEN}[SUB] →{C.RESET} {sub}")
        print(f"\n{C.BOLD}{C.GREEN}[+] Total unique subdomains found:{C.RESET} {len(uniq_subs)}", file=sys.stderr)
        return
    else:
        print(f"\n{C.BOLD}{C.GREEN}[+] Total unique URLs found:{C.RESET} {len(set(all_urls))}", file=sys.stderr)

    if args.o and not args.ss:
        fmt = "json" if str(args.o).lower().endswith(".json") else "txt"
        write_output(all_urls, fmt, args.o)
        print(f"{C.BOLD}{C.CYAN}[+] Output saved →{C.RESET} {args.o}", file=sys.stderr)


if __name__ == "__main__":
    main()
