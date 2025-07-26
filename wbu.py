#!/usr/bin/env python3
import argparse, requests, re, json
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, Counter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import sys
import hashlib

console = Console()
WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"

SENSITIVE_EXTS = ['.bak', '.old', '.config', '.env', '.sql', '.zip', '.tar.gz', '.backup', '.rar', '.db', '.git', '.svn']
ADMIN_WORDS = ['admin', 'dashboard', 'cpanel', 'panel', 'manage', 'moderator', 'root']
BACKUP_WORDS = ['backup', 'dump', 'db', 'database', 'archive', 'bak', 'copy']
API_WORDS = ['api', 'secret', 'token', 'key', 'auth', 'login', 'logout', 'session']
DOC_WORDS = ['readme', 'docs', 'documentation', 'manual', 'guide', 'help']

def banner():
    console.print(
        Panel.fit(
            "[bold magenta]ArchiveReconX+ (MAX)[/bold magenta]\n"
            "[bold cyan]The Ultimate Archive.org Recon Tool for Hunters & Pentesters[/bold cyan]\n"
            "[dim]By [bold]Copilot[/bold]"
        )
    )

def fetch_wayback(domain, filters):
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,length",
        "collapse": "original"
    }
    params.update(filters)
    try:
        r = requests.get(WAYBACK_CDX, params=params, timeout=60)
        r.raise_for_status()
        data = r.json()
        return data[1:] if len(data) > 1 else []
    except Exception as e:
        console.print(f"[red]Error fetching CDX: {e}[/red]")
        return []

def find_subdomains(data, domain):
    subdomains = set()
    for row in data:
        try:
            parsed = urlparse(row[1])
            host = parsed.hostname
            if host and host.endswith(domain) and host != domain:
                subdomains.add(host.lower())
        except Exception:
            continue
    return sorted(subdomains)

def find_sensitive_files(data):
    flagged = [row for row in data if any(row[1].lower().endswith(ext) for ext in SENSITIVE_EXTS)]
    return flagged

def find_admin_panels(data):
    flagged = [row for row in data if any(w in row[1].lower() for w in ADMIN_WORDS)]
    return flagged

def find_backup_files(data):
    flagged = [row for row in data if any(w in row[1].lower() for w in BACKUP_WORDS)]
    return flagged

def find_api_endpoints(data):
    flagged = [row for row in data if any(w in row[1].lower() for w in API_WORDS)]
    return flagged

def find_documents(data):
    flagged = [row for row in data if any(w in row[1].lower() for w in DOC_WORDS)]
    return flagged

def param_wordlist(data):
    params = set()
    for row in data:
        parsed = urlparse(row[1])
        qs = parse_qs(parsed.query)
        for p in qs:
            params.add(p)
    return sorted(params)

def removed_content(data):
    gone = [row for row in data if row[2] == '404']
    return gone

def status_code_diff(data):
    url_status = defaultdict(list)
    for row in data:
        url_status[row[1]].append(row[2])
    return {url: list(set(statuses)) for url, statuses in url_status.items() if len(set(statuses)) > 1}

def extract_js_endpoints(js_text):
    endpoints = re.findall(r'["\'](https?://[^\s"\'<>]+|/[^"\'<>]+)["\']', js_text)
    return set([e for e in endpoints if not e.endswith(('.png','.jpg','.css','.gif','.svg','.woff'))])

def enumerate_js(data):
    js_urls = [row[1] for row in data if row[1].endswith('.js')]
    endpoints = set()
    def fetch(url):
        try:
            ts = re.search(r'/web/(\d{14})/', url)
            if ts:
                clean_url = url.split('/', 5)[-1]
                wa_url = f'https://web.archive.org/web/{ts.group(1)}/{clean_url}'
            else:
                wa_url = f'https://web.archive.org/web/{url}'
            r = requests.get(wa_url, timeout=10)
            if r.status_code == 200:
                return extract_js_endpoints(r.text)
        except: return set()
        return set()
    with ThreadPoolExecutor(max_workers=8) as ex:
        for found in ex.map(fetch, js_urls):
            endpoints.update(found)
    return endpoints

def robots_and_sitemap(data):
    robots = [row for row in data if row[1].endswith('robots.txt')]
    sitemaps = [row for row in data if 'sitemap' in row[1]]
    return robots, sitemaps

def timeline_changes(data, target_url):
    history = [row for row in data if row[1] == target_url]
    return sorted(history, key=lambda x: x[0])

def find_emails(data):
    emails = set()
    for row in data:
        matches = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', row[1])
        for m in matches:
            emails.add(m)
    return sorted(emails)

def find_urls_by_regex(data, regex):
    found = []
    try:
        pattern = re.compile(regex)
        for row in data:
            if pattern.search(row[1]):
                found.append(row)
    except Exception as e:
        console.print(f"[red]Regex error: {e}[/red]")
    return found

def find_uncommon_extensions(data, common_exts=None):
    if common_exts is None:
        common_exts = ['.html', '.php', '.asp', '.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.json', '.xml']
    ext_counts = Counter()
    for row in data:
        ext = '.' + row[1].split('.')[-1] if '.' in row[1].split('/')[-1] else ''
        if ext and ext.lower() not in common_exts:
            ext_counts[ext.lower()] += 1
    return ext_counts.most_common()

def find_large_files(data, size_threshold=1000000):
    flagged = [row for row in data if row[4].isdigit() and int(row[4]) > size_threshold]
    return flagged

def find_dir_traversal(data):
    flagged = [row for row in data if '../' in row[1] or '%2e%2e' in row[1].lower()]
    return flagged

def find_sqlinjection(data):
    flagged = [row for row in data if any(s in row[1].lower() for s in ["'", '"', "select", "union", "from", "where", "--", " or ", " and "])]
    return flagged

def find_open_redirect(data):
    flagged = [row for row in data if any(q in row[1].lower() for q in ['redirect=', 'next=', 'url=', 'dest='])]
    return flagged

def find_exposed_keys(data):
    flagged = [row for row in data if "api_key" in row[1].lower() or "access_token" in row[1].lower()]
    return flagged

def find_hashes_in_urls(data):
    flagged = []
    for row in data:
        found = re.findall(r'\b[a-fA-F0-9]{32,64}\b', row[1])
        if found:
            flagged.append([row[0], row[1], ','.join(found)])
    return flagged

def find_jwt_tokens(data):
    flagged = []
    for row in data:
        found = re.findall(r'eyJ[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+', row[1])
        if found:
            flagged.append([row[0], row[1], ','.join(found)])
    return flagged

def find_base64_strings(data):
    flagged = []
    for row in data:
        found = re.findall(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', row[1])
        for f in found:
            if len(f) > 16:
                flagged.append([row[0], row[1], f])
    return flagged

def find_duplicate_urls(data):
    seen = set()
    duplicates = []
    for row in data:
        if row[1] in seen:
            duplicates.append(row)
        else:
            seen.add(row[1])
    return duplicates

def find_commented_out_files(data):
    flagged = [row for row in data if re.search(r'/\*.*\*/', row[1])]
    return flagged

def find_debug_files(data):
    debug_exts = ['.log', '.stacktrace', '.debug', '.trace', '.tmp']
    flagged = [row for row in data if any(row[1].lower().endswith(ext) for ext in debug_exts)]
    return flagged

def print_table(title, columns, rows, style="bold cyan"):
    table = Table(title=title, header_style=style)
    for col in columns:
        table.add_column(col, style="bold yellow")
    for row in rows:
        table.add_row(*[str(r) for r in row])
    console.print(table)

def help_table():
    rows = [
        ["-d", "--domain", "Target domain (e.g. example.com)"],
        ["-s", "--subdomains", "Enumerate subdomains from historical data"],
        ["-p", "--params", "Extract all parameters for fuzzing"],
        ["-S", "--sensitive", "Find sensitive file types"],
        ["-a", "--admin", "Find admin panel URLs"],
        ["-b", "--backup", "Find backup file URLs"],
        ["-A", "--api", "Find API/auth endpoints"],
        ["-D", "--docs", "Find documents/readme/help"],
        ["-r", "--removed", "Show removed (404) resources"],
        ["-j", "--js-endpoints", "Extract endpoints from all archived JS"],
        ["-t", "--timeline", "Show change timeline for a specific full URL"],
        ["-c", "--status-diff", "Show status code changes over time"],
        ["-R", "--robots", "Show historical robots.txt and sitemaps"],
        ["-e", "--emails", "Extract email addresses from historical URLs"],
        ["-x", "--regex", "Find URLs matching custom regex"],
        ["-u", "--uncommon-ext", "Find uncommon file extensions"],
        ["-l", "--large", "Find large archived files (>1MB)"],
        ["-E", "--export", "Export all fetched archive URLs as JSON/TXT/CSV"],
        ["-f", "--filter-status", "Filter by HTTP status code (e.g. 200,404)"],
        ["-F", "--from-date", "Start date (YYYYMMDDhhmmss)"],
        ["-T", "--to-date", "End date (YYYYMMDDhhmmss)"],
        ["-dt", "--dir-traversal", "Find possible directory traversal in URLs"],
        ["-si", "--sqlinj", "Find possible SQLi patterns in URLs"],
        ["-or", "--open-redirect", "Find possible open redirects in URLs"],
        ["-k", "--exposed-keys", "Find API/access keys in URLs"],
        ["-H", "--hashes", "Find hashes in URLs"],
        ["-J", "--jwt", "Find JWT tokens in URLs"],
        ["-B", "--base64", "Find base64 strings in URLs"],
        ["-du", "--duplicates", "Find duplicate URLs"],
        ["-C", "--commented", "Find commented-out files"],
        ["-dbg", "--debug", "Find debug/log files"],
        ["-h", "--help", "Show this help menu"],
    ]
    print_table("ArchiveReconX+ (MAX) Help Menu", ["Short", "Long", "Description"], rows)

def main():
    banner()
    parser = argparse.ArgumentParser(add_help=False, description="ArchiveReconX+ (MAX) - All-in-one Archive.org Recon Tool")
    parser.add_argument("-d", "--domain", help="Domain to scan (e.g. example.com)")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Enumerate subdomains from historical data")
    parser.add_argument("-p", "--params", action="store_true", help="Extract all parameters for fuzzing")
    parser.add_argument("-S", "--sensitive", action="store_true", help="Find sensitive file types")
    parser.add_argument("-a", "--admin", action="store_true", help="Find admin panel URLs")
    parser.add_argument("-b", "--backup", action="store_true", help="Find backup file URLs")
    parser.add_argument("-A", "--api", action="store_true", help="Find API/auth endpoints")
    parser.add_argument("-D", "--docs", action="store_true", help="Find documents/readme/help")
    parser.add_argument("-r", "--removed", action="store_true", help="Show removed (404) resources")
    parser.add_argument("-j", "--js-endpoints", action="store_true", help="Extract endpoints from all archived JS")
    parser.add_argument("-t", "--timeline", help="Show change timeline for a specific full URL")
    parser.add_argument("-c", "--status-diff", action="store_true", help="Show status code changes over time")
    parser.add_argument("-R", "--robots", action="store_true", help="Show historical robots.txt and sitemaps")
    parser.add_argument("-e", "--emails", action="store_true", help="Extract email addresses from historical URLs")
    parser.add_argument("-x", "--regex", help="Find URLs matching custom regex")
    parser.add_argument("-u", "--uncommon-ext", action="store_true", help="Find uncommon file extensions")
    parser.add_argument("-l", "--large", action="store_true", help="Find large archived files (>1MB)")
    parser.add_argument("-E", "--export", help="Export all fetched archive URLs as JSON/TXT/CSV")
    parser.add_argument("-f", "--filter-status", help="Filter by HTTP status code (e.g. 200,404)")
    parser.add_argument("-F", "--from-date", help="Start date (YYYYMMDDhhmmss)")
    parser.add_argument("-T", "--to-date", help="End date (YYYYMMDDhhmmss)")
    parser.add_argument("-dt", "--dir-traversal", action="store_true", help="Find possible directory traversal in URLs")
    parser.add_argument("-si", "--sqlinj", action="store_true", help="Find possible SQLi patterns in URLs")
    parser.add_argument("-or", "--open-redirect", action="store_true", help="Find possible open redirects in URLs")
    parser.add_argument("-k", "--exposed-keys", action="store_true", help="Find API/access keys in URLs")
    parser.add_argument("-H", "--hashes", action="store_true", help="Find hashes in URLs")
    parser.add_argument("-J", "--jwt", action="store_true", help="Find JWT tokens in URLs")
    parser.add_argument("-B", "--base64", action="store_true", help="Find base64 strings in URLs")
    parser.add_argument("-du", "--duplicates", action="store_true", help="Find duplicate URLs")
    parser.add_argument("-C", "--commented", action="store_true", help="Find commented-out files")
    parser.add_argument("-dbg", "--debug", action="store_true", help="Find debug/log files")
    parser.add_argument("-h", "--help", action="store_true", help="Show help menu")

    args = parser.parse_args()

    if args.help or not any(vars(args).values()) or not args.domain:
        help_table()
        sys.exit(0)

    filters = {}
    if args.filter_status: filters['filter'] = f"statuscode:{args.filter_status}"
    if args.from_date: filters['from'] = args.from_date
    if args.to_date: filters['to'] = args.to_date

    data = fetch_wayback(args.domain, filters)
    if not data:
        console.print("[red]No archive data found.[/red]")
        return

    if args.subdomains:
        subs = find_subdomains(data, args.domain)
        subs_unique = sorted(set(subs))
        print_table("Historical Subdomains", ["Subdomain"], [[s] for s in subs_unique])

    if args.params:
        params = param_wordlist(data)
        print_table("Parameter Wordlist", ["Parameter"], [[p] for p in params])

    if args.sensitive:
        flagged = find_sensitive_files(data)
        print_table("Sensitive Files", ["Timestamp", "URL", "Status", "Type", "Length"], flagged)

    if args.admin:
        flagged = find_admin_panels(data)
        print_table("Admin Panels", ["Timestamp", "URL", "Status", "Type", "Length"], flagged)

    if args.backup:
        flagged = find_backup_files(data)
        print_table("Backup Files", ["Timestamp", "URL", "Status", "Type", "Length"], flagged)

    if args.api:
        flagged = find_api_endpoints(data)
        print_table("API/Auth Endpoints", ["Timestamp", "URL", "Status", "Type", "Length"], flagged)

    if args.docs:
        flagged = find_documents(data)
        print_table("Documentation Files", ["Timestamp", "URL", "Status", "Type", "Length"], flagged)

    if args.removed:
        gone = removed_content(data)
        print_table("Removed/404 Content", ["Timestamp", "URL", "Status", "Type", "Length"], gone)

    if args.js_endpoints:
        js_endpoints = enumerate_js(data)
        js_unique = sorted(set(js_endpoints))
        print_table("Historical JS Endpoints", ["Endpoint"], [[e] for e in js_unique])

    if args.timeline:
        timeline = timeline_changes(data, args.timeline)
        print_table("Change Timeline", ["Timestamp", "URL", "Status", "Type", "Length"], timeline)

    if args.status_diff:
        diffs = status_code_diff(data)
        rows = [[url, ','.join(codes)] for url, codes in diffs.items()]
        print_table("Status Code Changes", ["URL", "Codes"], rows)

    if args.robots:
        robots, sitemaps = robots_and_sitemap(data)
        print_table("Historical robots.txt", ["Timestamp", "URL", "Status", "Type", "Length"], robots)
        print_table("Historical Sitemaps", ["Timestamp", "URL", "Status", "Type", "Length"], sitemaps)

    if args.emails:
        emails = find_emails(data)
        print_table("Email Addresses", ["Email"], [[e] for e in emails])

    if args.regex:
        found = find_urls_by_regex(data, args.regex)
        print_table(f"URLs matching Regex: {args.regex}", ["Timestamp", "URL", "Status", "Type", "Length"], found)

    if args.uncommon_ext:
        uncommon = find_uncommon_extensions(data)
        print_table("Uncommon File Extensions", ["Extension", "Count"], [[k, v] for k, v in uncommon])

    if args.large:
        largefiles = find_large_files(data)
        print_table("Large Files (>1MB)", ["Timestamp", "URL", "Status", "Type", "Length"], largefiles)

    if args.dir_traversal:
        traversal = find_dir_traversal(data)
        print_table("Directory Traversal Patterns", ["Timestamp", "URL", "Status", "Type", "Length"], traversal)

    if args.sqlinj:
        sqlis = find_sqlinjection(data)
        print_table("Possible SQL Injection Patterns", ["Timestamp", "URL", "Status", "Type", "Length"], sqlis)

    if args.open_redirect:
        orrows = find_open_redirect(data)
        print_table("Possible Open Redirects", ["Timestamp", "URL", "Status", "Type", "Length"], orrows)

    if args.exposed_keys:
        keysrows = find_exposed_keys(data)
        print_table("Exposed Keys in URLs", ["Timestamp", "URL", "Status", "Type", "Length"], keysrows)

    if args.hashes:
        hashes = find_hashes_in_urls(data)
        print_table("Hashes in URLs", ["Timestamp", "URL", "Hashes"], hashes)

    if args.jwt:
        jwts = find_jwt_tokens(data)
        print_table("JWT Tokens in URLs", ["Timestamp", "URL", "JWTs"], jwts)

    if args.base64:
        b64s = find_base64_strings(data)
        print_table("Base64 Strings in URLs", ["Timestamp", "URL", "Base64"], b64s)

    if args.duplicates:
        duplicates = find_duplicate_urls(data)
        print_table("Duplicate URLs", ["Timestamp", "URL", "Status", "Type", "Length"], duplicates)

    if args.commented:
        commented = find_commented_out_files(data)
        print_table("Commented-out Files", ["Timestamp", "URL", "Status", "Type", "Length"], commented)

    if args.debug:
        debugfiles = find_debug_files(data)
        print_table("Debug/Log Files", ["Timestamp", "URL", "Status", "Type", "Length"], debugfiles)

    if args.export:
        ext = args.export.split('.')[-1].lower()
        with open(args.export, 'w', encoding='utf8') as f:
            if ext == 'json':
                f.write(json.dumps(data, indent=2))
            elif ext == 'csv':
                import csv
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "URL", "Status", "Type", "Length"])
                for row in data:
                    writer.writerow(row)
            else:
                for row in data:
                    f.write(row[1] + '\n')
        console.print(f"[green]Exported data to {args.export}[/green]")

if __name__ == "__main__":
    main()
