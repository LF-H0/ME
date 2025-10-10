#!/bin/bash


# this tool takes a file of urls as an input and then it creates folders, each folder represent a subdomain and inside each subdomain folder it organize urls in categories (E.g: patams.txt , json.txt , js.txt , css.txt ...etc )

# Author: LF-H0
# Last Updated: 2025-10-10 13:00:00 UTC

set -euo pipefail

# --- Definitions ---
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
NC='\033[0m'

# --- Configuration ---
INTERESTING_KEYWORDS="admin|root|login|signin|register|config|setup|dev|backup|database|db|shell|api|env|secret|key|auth|account|profile|dashboard|panel|console|upload|phpinfo|wp-admin|administrator|cpanel|phpmyadmin|wp-login|users|userinfo|password|passwords|passwd|email|reset|reset_password|web|nodeinfo|emails|well-known|v1|v2|v3|v4|v5|v6"

EXT_CATEGORIES="js json html htm php phtml asp aspx jsp py rb pl sh sql conf ini cfg log yml yaml toml ts tsx jsx vue css txt xml"
CATEGORIES="params $EXT_CATEGORIES images docs archives media fonts interesting others"

IMAGE_EXTENSIONS="jpg|jpeg|png|gif|bmp|svg|ico|webp|tiff|tif"
DOC_EXTENSIONS="pdf|doc|docx|xls|xlsx|ppt|pptx|odt|ods|odp|rtf|tex|csv"
ARCHIVE_EXTENSIONS="zip|tar|gz|tgz|rar|7z|bz2|xz|deb|rpm|dmg|pkg"
MEDIA_EXTENSIONS="mp3|mp4|avi|mov|wmv|flv|webm|mkv|m4v|3gp|wav|ogg"
FONT_EXTENSIONS="woff|woff2|ttf|otf|eot"

# --- Input Validation ---
if [ $# -ne 1 ] || [ ! -f "$1" ]; then
    echo -e "${RED}Usage: $0 <url_file>${NC}"
    exit 1
fi
input_file="$1"

if ! command -v gawk >/dev/null 2>&1; then
    echo -e "${RED}Error: gawk is not installed.${NC}"
    echo -e "${YELLOW}On Termux, install it with: pkg install gawk${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Starting...${NC}"

# --- Setup: Main Domain Extraction ---
first_url=$(head -n1 "$input_file")
case "$first_url" in
    *://*) ;;
    *) first_url="http://$first_url" ;;
esac
domain=$(echo "$first_url" | gawk -F/ '{print $3}')
domain="${domain%%:*}"

IFS='.' read -r -a domain_parts <<< "$domain"
parts_count=${#domain_parts[@]}
if [ $parts_count -ge 2 ]; then
    main_domain="${domain_parts[$((parts_count-2))]}.${domain_parts[$((parts_count-1))]}"
    main_folder="${domain_parts[$((parts_count-2))]}"
else
    main_domain="$domain"
    main_folder="$domain"
fi

# main folder
if [ "$main_folder" = "www" ] && [ $parts_count -ge 3 ]; then
    main_folder="${domain_parts[$((parts_count-3))]}"
fi

if [ -z "$main_folder" ] || [ "$main_folder" = "/" ] || [ "$main_folder" = "." ]; then
    echo -e "${RED}Error: Invalid folder name derived from domain ($main_folder)${NC}"
    exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

rm -rf "$main_folder"
mkdir -p "$main_folder/all"

# --- Subdomain Extraction ---
echo -e "${BLUE}[*] Collecting subdomains...${NC}"
gawk -v tmp_dir="$tmp_dir" -v main_domain="$main_domain" '
function extract_domain(url,   domain, arr) {
    if (match(url, /^[a-zA-Z]+:\/\//)) url = substr(url, RSTART+RLENGTH)
    split(url, arr, /[\/:?#]/)
    domain = arr[1]
    if (domain == "" || domain ~ /[^a-zA-Z0-9.-]/) return ""
    domain = tolower(domain)
    return domain
}
function valid_subdomain(d, m) {
    # Must end with ".main_domain", not equal, not empty, no trailing dot, has at least one label before main_domain
    return (d != "" && d !~ /\.$/ && d != m && d ~ ("\\." m "$") && d ~ /[a-zA-Z0-9-]+\./ && d !~ /^http[s]?:?$/ && d !~ /^www\.?$/ && d !~ /^\./ && d !~ /[^a-zA-Z0-9.-]/)
}
{
    url = $0
    d = extract_domain(url)
    if (valid_subdomain(d, main_domain)) print d > (tmp_dir "/subdomains_raw.list")
}
END {
    print main_domain > (tmp_dir "/subdomains_raw.list")  # Always include main domain
}
' "$input_file"

sort -u "$tmp_dir/subdomains_raw.list" > "$tmp_dir/subdomains.list"

# --- Directory Structure: main_folder/{all,main_domain,subdomains...} ---
echo -e "${BLUE}[*] Creating folders...${NC}"
mkdir -p "$main_folder/all"
while IFS= read -r subdomain || [ -n "$subdomain" ]; do
    [ -n "$subdomain" ] && mkdir -p "$main_folder/$subdomain"
done < "$tmp_dir/subdomains.list"

# --- Categorization ---
echo -e "${BLUE}[*] Processing URLs...${NC}"
gawk -v tmp_dir="$tmp_dir" \
    -v main_domain="$main_domain" \
    -v keywords="$INTERESTING_KEYWORDS" \
    -v img_ext="$IMAGE_EXTENSIONS" \
    -v doc_ext="$DOC_EXTENSIONS" \
    -v arch_ext="$ARCHIVE_EXTENSIONS" \
    -v med_ext="$MEDIA_EXTENSIONS" \
    -v font_ext="$FONT_EXTENSIONS" \
    -v ext_list="$EXT_CATEGORIES" '
BEGIN {
    n = split(ext_list, code_exts, " ")
    for (i = 1; i <= n; i++) code_map[code_exts[i]] = code_exts[i]
    image_re = "\\.(" img_ext ")($|[?#/])"
    doc_re = "\\.(" doc_ext ")($|[?#/])"
    archive_re = "\\.(" arch_ext ")($|[?#/])"
    media_re = "\\.(" med_ext ")($|[?#/])"
    font_re = "\\.(" font_ext ")($|[?#/])"
    interesting_re = keywords
    while ((getline line < (tmp_dir "/subdomains.list")) > 0) {
        valid_subdomains[line] = 1
    }
    close(tmp_dir "/subdomains.list")
}
function extract_domain(url,   domain, arr) {
    if (match(url, /^[a-zA-Z]+:\/\//)) url = substr(url, RSTART+RLENGTH)
    split(url, arr, /[\/:?#]/)
    domain = arr[1]
    if (domain == "" || domain ~ /[^a-zA-Z0-9.-]/) return ""
    domain = tolower(domain)
    return domain
}
function ext_category(url, path, params_found, ext_lc, m, arr, domain, qidx, fragidx, param_part, path_part, lastseg) {
    # Extract domain and path
    # Remove schema
    domain = ""; path = url
    if (match(path, /^[a-zA-Z]+:\/\//)) {
        path = substr(path, RSTART+RLENGTH)
    }
    # Remove domain part
    qidx = index(path, "/")
    if (qidx > 0) path = substr(path, qidx)
    else path = "/"
    # Extract path before ? or #
    fragidx = index(path, "#")
    qidx = index(path, "?")
    if (qidx > 0 && (fragidx == 0 || qidx < fragidx)) path_part = substr(path, 1, qidx-1)
    else if (fragidx > 0) path_part = substr(path, 1, fragidx-1)
    else path_part = path
    # Remove trailing slash for file extension checks
    while (length(path_part) > 1 && substr(path_part, length(path_part), 1) == "/") path_part = substr(path_part, 1, length(path_part)-1)
    # Check for parameters: present if ? or &key=val exists after domain
    params_found = (match(url, /[?&][^?#=]+=[^&#]/) ? 1 : 0)
    if (params_found) return "params"
    # Extension check: get last non-empty segment of path, check extension
    n = split(path_part, arr, "/")
    lastseg = arr[n]
    if (match(lastseg, /\.([a-zA-Z0-9]+)$/ , m)) {
        ext_lc = tolower(m[1])
        if (ext_lc in code_map) return code_map[ext_lc]
        # Images, docs, archives, media, fonts
        if (lastseg ~ image_re) return "images"
        if (lastseg ~ doc_re) return "docs"
        if (lastseg ~ archive_re) return "archives"
        if (lastseg ~ media_re) return "media"
        if (lastseg ~ font_re) return "fonts"
    } else {
        # Also check for image, doc, archive, media, font by regex (for e.g. og-img.png/)
        if (lastseg ~ image_re) return "images"
        if (lastseg ~ doc_re) return "docs"
        if (lastseg ~ archive_re) return "archives"
        if (lastseg ~ media_re) return "media"
        if (lastseg ~ font_re) return "fonts"
    }
    # Interesting
    if (url ~ interesting_re) return "interesting"
    return "others"
}
{
    url = $0
    d = extract_domain(url)
    if (!(d in valid_subdomains)) next
    cat = ext_category(url)
    print url >> (tmp_dir "/" d "_" cat ".tmp")
    print url >> (tmp_dir "/all_" cat ".tmp")
    print url >> (tmp_dir "/all_urls.tmp")
}
' "$input_file"

# --- Write categorized files ---
while IFS= read -r subdomain || [ -n "$subdomain" ]; do
    for cat in $CATEGORIES; do
        tmp_file="$tmp_dir/${subdomain}_${cat}.tmp"
        if [ -s "$tmp_file" ]; then
            sort -u "$tmp_file" > "$main_folder/$subdomain/${cat}.txt"
        fi
    done
done < "$tmp_dir/subdomains.list"

for cat in $CATEGORIES; do
    tmp_file="$tmp_dir/all_${cat}.tmp"
    if [ -s "$tmp_file" ]; then
        sort -u "$tmp_file" > "$main_folder/all/all-${cat}.txt"
    fi
done

# --- All URLs ---
if [ -s "$tmp_dir/all_urls.tmp" ]; then
    sort -u "$tmp_dir/all_urls.tmp" > "$main_folder/all/all-urls.txt"
fi

# --- Statistics: Only for files that exist in "all" folder ---
echo -e "${BLUE}[*] Generating stats...${NC}"
total_urls=$( [ -f "$main_folder/all/all-urls.txt" ] && wc -l < "$main_folder/all/all-urls.txt" | xargs || echo 0 )
total_subdomains=$(grep -v "^$main_domain$" "$tmp_dir/subdomains.list" | wc -l | xargs)

{
    echo "====== STATISTICS ======="
    echo "Target Domain: $main_domain"
    echo "Total Unique URLs: $total_urls"
    echo "Total Subdomains Found: $total_subdomains"
    for f in "$main_folder/all"/all-*.txt; do
        [ -e "$f" ] || continue
        fname=$(basename "$f")
        catname=${fname#all-}
        catname=${catname%.txt}
        if [ "$catname" = "urls" ]; then continue; fi
        count=$(wc -l < "$f" | xargs)
        # Pretty-label for stats
        label="$catname"
        case "$catname" in
            params) label="Parameter URLs" ;;
            js) label="JS Files" ;;
            json) label="JSON Files" ;;
            html) label="HTML Files" ;;
            htm) label="HTM Files" ;;
            php) label="PHP Files" ;;
            phtml) label="PHTML Files" ;;
            asp) label="ASP Files" ;;
            aspx) label="ASPX Files" ;;
            jsp) label="JSP Files" ;;
            py) label="PY Files" ;;
            rb) label="RB Files" ;;
            pl) label="PL Files" ;;
            sh) label="SH Files" ;;
            sql) label="SQL Files" ;;
            conf) label="CONF Files" ;;
            ini) label="INI Files" ;;
            cfg) label="CFG Files" ;;
            log) label="LOG Files" ;;
            yml) label="YML Files" ;;
            yaml) label="YAML Files" ;;
            toml) label="TOML Files" ;;
            ts) label="TS Files" ;;
            tsx) label="TSX Files" ;;
            jsx) label="JSX Files" ;;
            vue) label="VUE Files" ;;
            css) label="CSS Files" ;;
            txt) label="TXT Files" ;;
            xml) label="XML Files" ;;
            images) label="Image Files" ;;
            docs) label="Document Files" ;;
            archives) label="Archive Files" ;;
            media) label="Media Files" ;;
            fonts) label="Font Files" ;;
            interesting) label="Interesting URLs" ;;
            others) label="Other URLs" ;;
        esac
        printf "Total %s: %s\n" "$label" "$count"
    done
    echo "=========================="
} > "$main_folder/all/statistics.txt"

echo -e "${MAGENTA}[+] Done.${NC}"