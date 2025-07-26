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
# Increased concurrency (default 300), can be configured with env var
MAX_THREADS = int(os.environ.get("GAU_THREADS", 300))
_LOCK = threading.Semaphore(MAX_THREADS)

session = requests.Session()
_adapter = HTTPAdapter(
    max_retries=Retry(
        total=3,
        backoff_factor=0.10,
        status_forcelist=[429, 500, 502, 503, 504],
    ),
    pool_connections=MAX_THREADS,
    pool_maxsize=MAX_THREADS
)
session.mount("http://", _adapter)
session.mount("https://", _adapter)
session.headers.update({"User-Agent": "gau++/2.0"})

def _get(url: str, params=None) -> requests.Response:
    with _LOCK:
        # Lower sleep for more aggressive fetching
        time.sleep(random.uniform(0.0005, 0.005))
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
def color_table(rows):
    # Returns a colorized ASCII table for help menu
    col1_width = max(len(r[0]) for r in rows)
    table = []
    border = f"{C.CYAN}{'─'*(col1_width+2)}{'─'*47}{C.RESET}"
    table.append(f"{C.CYAN}┌{'─'*(col1_width+2)}┬{'─'*47}┐{C.RESET}")
    header = f"{C.CYAN}│ {C.BOLD}{rows[0][0].ljust(col1_width)}{C.RESET}{C.CYAN} │ {C.BOLD}{rows[0][1].ljust(45)}{C.RESET}{C.CYAN} │{C.RESET}"
    table.append(header)
    table.append(f"{C.CYAN}├{'─'*(col1_width+2)}┼{'─'*47}┤{C.RESET}")
    for row in rows[1:]:
        line = f"{C.CYAN}│{C.RESET} {C.GREEN}{row[0].ljust(col1_width)}{C.RESET} {C.CYAN}│{C.RESET} {row[1].ljust(45)} {C.CYAN}│{C.RESET}"
        table.append(line)
    table.append(f"{C.CYAN}└{'─'*(col1_width+2)}┴{'─'*47}┘{C.RESET}")
    return "\n".join(table)

class ColorHelp(argparse.HelpFormatter):
    def format_help(self):
        help_table = [
            ["Command/Flag", "Description"],
            ["domain", "Single target domain."],
            ["-dl FILE", "File with list of domains (one per line)."],
            ["-d DATE", "Show date column (optionally YYYY or range)."],
            ["-ns NO-SUBS", "Don't include subdomains of the target."],
            ["-gv", "URLs for crawled versions of input URL(s)."],
            ["-f FILTERS", "Comma list: https,params."],
            ["-fc [CODES]", "Show status code or keep only listed codes."],
            ["-fe EXTS", "Include only URLs with these extensions."],
            ["-e EXTS", "Comma list of extensions to exclude."],
            ["-o FILE", "Output file [txt|json]."],
            ["-r SRCS", "Resources: wbu,cc,vt,otx,urlscan,cr,ht,rdns."],
            ["-ss SUBS", "Show unique subdomains only."],
            ["-h HELP", "Show this help menu."]
        ]
        descr = f"\n{C.BOLD}{C.CYAN}Get All URLs – passive & super fast{C.RESET}\n"
        table = color_table(help_table)
        return descr + table + "\n"

def parse_args(argv: List[str]):
    p = argparse.ArgumentParser(
        description="",
        formatter_class=ColorHelp,
        add_help=False
    )
    p.add_argument("domain", nargs="?", help="single target domain")
    p.add_argument("-h", "--help", action="help", help="show this help menu\n")
    p.add_argument("-dl", metavar="FILE", help="file with list of domains (one per line)")
    p.add_argument("-d", nargs='?', const=True, help="show date column (optionally YYYY or YYYY:YYYY)")
    p.add_argument("-ns", action="store_true", help="don't include subdomains of the target")
    p.add_argument("-gv", action="store_true", dest="get_versions", help="list URLs for crawled versions of input URL(s)")
    p.add_argument("-f", metavar="FILTERS", help="comma list of https,params")
    p.add_argument("-fc", metavar="CODES", nargs='?', const=True, help="show status code; or keep only comma list CODES (passive)")
    p.add_argument("-fe", metavar="EXTS", help="include only URLs with these extensions")
    p.add_argument("-e", metavar="EXTS", help="comma list of extensions to exclude")
    p.add_argument("-o", metavar="FILE", help="output file [txt|json]")
    p.add_argument("-r", metavar="SRCS", help="use only listed resources wbu,cc,vt,otx,urlscan,cr,ht,rdns")
    p.add_argument("-ss", action="store_true", help="show unique subdomains only")

    args = p.parse_args(argv)

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

def valid_fqdn(fqdn: str, domain: str, no_subs: bool) -> bool:
    extracted = tldextract.extract(fqdn)
    domain_ext = tldextract.extract(domain)
    if extracted.suffix != domain_ext.suffix or extracted.domain != domain_ext.domain:
        return False
    if no_subs:
        return extracted.fqdn.lower() == domain_ext.fqdn.lower()
    return extracted.fqdn.lower().endswith(domain_ext.fqdn.lower())

def valid_url_domain(url: str, domain: str, no_subs: bool) -> bool:
    try:
        uhost = up.urlparse(url).hostname or ""
        return valid_fqdn(uhost, domain, no_subs)
    except Exception:
        return False

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
        if not valid_url_domain(orig, domain, no_subs):
            continue
        out.append(WURL(date=ts, url=orig, status=st))
    return out

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
            orig = j["url"]
            if not valid_url_domain(orig, domain, no_subs):
                continue
            out.append(WURL(date=j["timestamp"], url=orig, status=int(st) if st else None))
        except Exception:
            continue
    return out

def get_virustotal_urls(domain: str, no_subs: bool) -> List[WURL]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return []
    urls = []
    base_url = "https://www.virustotal.com/api/v3/domains/"
    headers = {"x-apikey": api_key}
    try:
        resp = _get(base_url + domain + "/urls", params=None)
        j = resp.json()
        for d in j.get("data", []):
            urlid = d.get("id")
            if urlid:
                url_info = d.get("attributes", {}).get("url")
                if url_info and valid_url_domain(url_info, domain, no_subs):
                    urls.append(WURL(date="", url=url_info, status=None))
    except Exception:
        pass
    if not urls:
        url = "https://www.virustotal.com/vtapi/v2/domain/report"
        params = {"apikey": api_key, "domain": domain}
        try:
            j = _get(url, params=params).json()
            for u in j.get("detected_urls", []) + j.get("undetected_urls", []):
                if isinstance(u, dict) and "url" in u and valid_url_domain(u["url"], domain, no_subs):
                    urls.append(WURL(date="", url=u["url"], status=None))
        except Exception:
            pass
    return urls

def get_otx_urls(domain: str, no_subs: bool) -> List[WURL]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=1000"
    try:
        j = _get(url).json()
    except Exception:
        return []
    return [WURL(date="", url=item["url"], status=None) for item in j.get("url_list", []) if valid_url_domain(item["url"], domain, no_subs)]

def get_urlscan_urls(domain: str, no_subs: bool) -> List[WURL]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    try:
        j = _get(url).json()
    except Exception:
        return []
    return [WURL(date="", url=item["page"]["url"], status=None) for item in j.get("results", []) if valid_url_domain(item["page"]["url"], domain, no_subs)]

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
            if not valid_fqdn(sub, domain, no_subs):
                continue
            out.append(WURL(date="", url=f"https://{sub}", status=None))
    return out

def get_hackertarget_urls(domain: str, no_subs: bool) -> List[WURL]:
    url = f"https://api.hackertarget.com/pagelinks/?q={domain}"
    try:
        resp = _get(url).text
    except Exception:
        return []
    urls = []
    for line in resp.splitlines():
        u = line.strip()
        if u and not u.startswith("error") and valid_url_domain(u, domain, no_subs):
            urls.append(WURL(date="", url=u, status=None))
    return urls

def get_rapiddns_urls(domain: str, no_subs: bool) -> List[WURL]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        resp = _get(url).text
    except Exception:
        return []
    urls = []
    for match in re.findall(r'<td>([a-zA-Z0-9_.-]+\.' + re.escape(domain) + r')</td>', resp):
        sub = match.strip()
        if valid_fqdn(sub, domain, no_subs):
            urls.append(WURL(date="", url=f"https://{sub}", status=None))
    for line in resp.splitlines():
        if ',' in line:
            parts = line.split(',')
            sub = parts[0].strip()
            if sub.endswith(domain) and valid_fqdn(sub, domain, no_subs):
                urls.append(WURL(date="", url=f"https://{sub}", status=None))
    return urls

# ------------------------------------------------------------------
# Helpers

def is_sub(raw_url: str, domain: str) -> bool:
    try:
        host = up.urlparse(raw_url).hostname or ""
        ext = tldextract.extract(host)
        domain_ext = tldextract.extract(domain)
        return (ext.suffix == domain_ext.suffix and
                ext.domain == domain_ext.domain and
                ext.fqdn.lower() != domain_ext.fqdn.lower())
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
    return sorted(set(out), key=lambda x: x.lower())

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

def passes_filters_bulk(urls, filters):
    # Bulk filtering for speed
    if not filters:
        return urls
    result = []
    if "https" in filters:
        result = [u for u in urls if u.url.startswith("https")]
    else:
        result = urls
    if "params" in filters:
        result = [u for u in result if "?" in u.url]
    return result

def passes_extensions_bulk(urls, include, exclude):
    # Bulk filtering for speed
    if include:
        result = []
        for u in urls:
            path = up.urlparse(u.url).path.lower()
            if any(path.endswith(f".{ext.strip().lower()}") for ext in include):
                result.append(u)
        return result
    if exclude:
        result = []
        for u in urls:
            path = up.urlparse(u.url).path.lower()
            if not any(path.endswith(f".{ext.strip().lower()}") for ext in exclude):
                result.append(u)
        return result
    return urls

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
        with open(outfile, "w", encoding="utf-8") as fh:
            json.dump(uniq, fh, indent=2, ensure_ascii=False)
    else:
        with open(outfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(uniq))

# ------------------------------------------------------------------
# Main
def main(argv: List[str] = None):
    argv = argv if argv is not None else sys.argv[1:]
    args = parse_args(argv)

    domains = []
    if args.dl:
        try:
            domains = [ln.strip() for ln in Path(args.dl).read_text(encoding="utf-8").splitlines() if ln.strip()]
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

    domains = sorted(set(domains))  # deterministic input order

    filters = [f.lower().strip() for f in (args.f or "").split(",") if f] if args.f else []
    include_ext = [e.lower().strip() for e in (args.fe or "").split(",") if e] if args.fe else []
    exclude_ext = [e.lower().strip() for e in (args.e or "").split(",") if e] if args.e else []

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

    all_urls: List[str] = []
    subdomains: Set[str] = set()

    if args.get_versions:
        all_versions = []
        for u in domains:
            versions = get_versions(u)
            all_versions.extend(versions)
            for v in versions:
                print(f"{C.BOLD}{C.BLUE}{v}{C.RESET}")
        if args.o:
            write_output(all_versions, "json" if str(args.o).lower().endswith(".json") else "txt", args.o)
            print(f"{C.BOLD}{C.CYAN}[+] Output saved →{C.RESET} {args.o}", file=sys.stderr)
        return

    for domain in domains:
        results: Dict[str, WURL] = {}
        all_fetch_results = []
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            future_to_fetch = {ex.submit(fn, domain, args.ns): fn for fn in fetchers}
            for f in as_completed(future_to_fetch):
                try:
                    urls = f.result()
                    all_fetch_results.extend(urls)
                except Exception:
                    pass

        # Apply fast bulk filters for speed
        filtered = all_fetch_results
        if filters:
            filtered = passes_filters_bulk(filtered, filters)
        if include_ext or exclude_ext:
            filtered = passes_extensions_bulk(filtered, include_ext, exclude_ext)

        # Slow filters (date, subdomain, status)
        for w in filtered:
            if not passes_date(w, args.d):
                continue
            if args.ns and is_sub(w.url, domain):
                continue
            if args.fc_codes is not None and w.status not in args.fc_codes:
                continue
            results[w.url] = w

        for w in results.values():
            host = up.urlparse(w.url).hostname or ""
            ext = tldextract.extract(host)
            domain_ext = tldextract.extract(domain)
            if ext.suffix == domain_ext.suffix and ext.domain == domain_ext.domain:
                subdomains.add(ext.fqdn.lower())

        if args.ss:
            continue

        for w in sorted(results.values(), key=lambda w: w.url.lower()):
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
            val = date_str + prefix + w.url
            all_urls.append(val)
            print(val)

    if args.ss:
        uniq_subs = sorted({s for s in subdomains if valid_fqdn(s, domains[0], args.ns)})
        for sub in uniq_subs:
            print(f"{C.BOLD}{C.GREEN}[SUB] →{C.RESET} {sub}")
        print(f"\n{C.BOLD}{C.GREEN}[+] Total unique subdomains found:{C.RESET} {len(uniq_subs)}", file=sys.stderr)
        if args.o:
            write_output(uniq_subs, "json" if str(args.o).lower().endswith(".json") else "txt", args.o)
            print(f"{C.BOLD}{C.CYAN}[+] Output saved →{C.RESET} {args.o}", file=sys.stderr)
        return
    else:
        print(f"\n{C.BOLD}{C.GREEN}[+] Total unique URLs found:{C.RESET} {len(set(all_urls))}", file=sys.stderr)
        if args.o:
            write_output(all_urls, "json" if str(args.o).lower().endswith(".json") else "txt", args.o)
            print(f"{C.BOLD}{C.CYAN}[+] Output saved →{C.RESET} {args.o}", file=sys.stderr)

if __name__ == "__main__":
    main()
