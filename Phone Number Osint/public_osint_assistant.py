#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Public OSINT Search Assistant
coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Uses ONLY publicly available information sources:
  - Search-engine query (dork) generation for manual review
  - Username presence check on public profile URLs
  - RDAP (public WHOIS replacement) and DNS lookups
  - HTTP header / security header review
  - Wayback Machine availability lookup
  - Certificate Transparency (crt.sh) subdomain listing

Standard library only. For lawful, authorized, ethical research.
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⢀⣠⠴⢞⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⣲⣿⡄⢀⡴⠋⣠⣾⣿⣿⣿⣿⣄⣀⣀⡀⠀⠀⠀⠀⠈⠓⠲⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠎⣼⣿⣿⣿⡟⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣶⣦⣄⡀⠀⠀⠙⠻⣦⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠊⠉⠀⠀⠈⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣄⡉⠛⢿⣷⣄⠀⠀⠈⢷⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⡀⠤⠐⠒⡁⢴⣤⣤⡀⠀⠀⠀⣠⣼⣿⣿⣏⣀⣀⠀⠉⠛⢿⣿⣿⣿⣿⣿⣷⣄⠙⢿⣷⣄⠀⠀⠹⡄⠀⠀⠀⠀⠀
⢰⣦⣍⣁⠀⠀⠀⠀⠀⠀⢾⡉⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⢸⣿⣿⣿⣿⣿⣿⣷⡄⢻⣿⣆⠀⠀⠑⠀⠀⠀⠀⠀
⠈⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠁⠁⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⡿⠋⢀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⢻⣿⡄⠀⠀⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢱⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⡻⢿⣿⣷⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣎⣿⣷⠀⠀⠀⠀⠀⠀⠀
⢀⠀⠀⠀⠀⠀⠀⠀⢸⠾⠀⢀⣠⣶⠀⣠⣾⣿⣿⣿⣿⣦⡉⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣇⠀⠀⠀⠀⠀⠀
⠀⢹⠁⠰⠉⠉⠒⢄⣸⡷⠿⠛⠉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⢿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀
⠀⠀⢇⡇⠀⠀⠀⠘⠁⣿⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠈⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀
⠀⠀⠀⠁⠀⠀⠀⠀⠀⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣯⠻⢿⣿⣿⣿⣷⣶⡆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⢀⣿⣿⣿⣷⣶⣶⣾⣿⡿⠟⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⡏⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⣼⣿⣿⣿⣿⣿⡍⠁⠀⠀⠀⠀
⠀⠀⢀⠞⡄⠀⠀⢠⣿⣣⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⠏⣼⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀
⠀⠀⢸⣀⣇⠠⠔⢫⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢫⣾⣿⣿⣿⡿⢣⣿⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠰⡀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⠟⢁⣾⣿⣿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠑⡄⢸⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⢁⣴⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠚⠉⠉⠁⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⢛⣉⣤⣶⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⠟⡇⠈⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⣿⣿⣿⣿⣿⡿⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⠀⠹⣿⣿⣿⣿⣿⡏⠀⣿⡀⢻⣿⣿⣿⣿⣿⣿⠟⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⡀⠈⠻⣿⣿⣿⡇⠀⠸⣷⡀⢿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⣄⠀⠈⠙⠿⣿⡄⠀⠘⢿⣦⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣤⡀⠀⠀⠀⠀⠀⠀⠈⠛⠿⢿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠳⠦⠄⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

CREDIT = "coded by Mr Sabaz Ali Khan"
TITLE = "PUBLIC OSINT SEARCH ASSISTANT"
UA = "Mozilla/5.0 (PublicOSINTAssistant; +research)"
TIMEOUT = 10

RESULTS = {}  # collected data for the report


# ----------------------------------------------------------------- helpers
def banner():
    print(BANNER)
    print(f"  [ {TITLE} ]")
    print(f"  [ {CREDIT} ]")
    print("  Public sources only. Use lawfully and with authorization.\n")


def http_get(url, headers=None, timeout=TIMEOUT, method="GET"):
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": UA, **(headers or {})})
    ctx = ssl.create_default_context()
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def get_json(url):
    try:
        with http_get(url) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return {"error": str(e)}


def clean_domain(d):
    d = d.strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    return d.split("/")[0]


def section(title):
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)


# ------------------------------------------------- 1. search query builder
def build_queries(kind, value):
    """Return (label, url) pairs for public search engines. Nothing is
    fetched automatically; the analyst opens and reviews results manually."""
    q = urllib.parse.quote_plus
    out = []

    def add(label, query):
        out.append((label, "https://www.google.com/search?q=" + q(query)))

    if kind == "domain":
        d = value
        add("Indexed pages", f"site:{d}")
        add("Login / admin pages", f"site:{d} inurl:login OR inurl:admin")
        add("Public documents", f"site:{d} filetype:pdf OR filetype:docx OR filetype:xlsx")
        add("Directory listings", f"site:{d} intitle:\"index of\"")
        add("Subdomains", f"site:*.{d} -www")
        add("Mentions elsewhere", f"\"{d}\" -site:{d}")
        out.append(("Wayback Machine", f"https://web.archive.org/web/*/{d}"))
        out.append(("crt.sh certificates", f"https://crt.sh/?q=%25.{d}"))
    elif kind == "username":
        u = value
        add("Exact username", f"\"{u}\"")
        add("Profiles", f"\"{u}\" site:github.com OR site:twitter.com OR site:reddit.com")
        add("Forums", f"inurl:{u} (forum OR profile OR user)")
        out.append(("GitHub", f"https://github.com/{u}"))
        out.append(("Reddit", f"https://www.reddit.com/user/{u}"))
    elif kind == "email":
        e = value
        add("Exact email", f"\"{e}\"")
        add("Pastes / code", f"\"{e}\" site:pastebin.com OR site:github.com")
        add("Email local part", f"\"{e.split('@')[0]}\"")
    elif kind == "name":
        n = value
        add("Exact name", f"\"{n}\"")
        add("Professional", f"\"{n}\" site:linkedin.com")
        add("Publications", f"\"{n}\" filetype:pdf")
        add("News", f"\"{n}\" news")
    elif kind == "phone":
        p = value
        add("Exact number", f"\"{p}\"")
        add("Public listings", f"\"{p}\" (contact OR whatsapp OR call)")
    elif kind == "ip":
        i = value
        add("Mentions", f"\"{i}\"")
        out.append(("Shodan host page", f"https://www.shodan.io/host/{i}"))
        out.append(("AbuseIPDB", f"https://www.abuseipdb.com/check/{i}"))
        out.append(("BGP / ASN info", f"https://bgp.he.net/ip/{i}"))
    return out


def do_queries(kind, value):
    section(f"Search query builder: {kind} = {value}")
    items = build_queries(kind, value)
    if not items:
        print("Unknown target type.")
        return
    for label, url in items:
        print(f" - {label}\n     {url}")
    RESULTS.setdefault("queries", []).append(
        {"type": kind, "value": value, "links": items})


# ------------------------------------------------------ 2. username check
SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Medium": "https://medium.com/@{}",
    "DEV.to": "https://dev.to/{}",
    "HackerOne": "https://hackerone.com/{}",
    "Keybase": "https://keybase.io/{}",
    "Docker Hub": "https://hub.docker.com/u/{}",
    "PyPI": "https://pypi.org/user/{}/",
    "npm": "https://www.npmjs.com/~{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "SoundCloud": "https://soundcloud.com/{}",
    "Telegram": "https://t.me/{}",
}


def check_site(item):
    name, tpl = item
    url = tpl.format(user_g)
    try:
        with http_get(url, timeout=8) as r:
            return name, url, r.status
    except urllib.error.HTTPError as e:
        return name, url, e.code
    except Exception:
        return name, url, None


def do_username(username):
    global user_g
    user_g = urllib.parse.quote(username)
    section(f"Public username presence check: {username}")
    with ThreadPoolExecutor(max_workers=8) as ex:
        rows = list(ex.map(check_site, SITES.items()))
    found = []
    for name, url, status in rows:
        if status == 200:
            tag = "FOUND   "
            found.append(url)
        elif status == 404:
            tag = "absent  "
        else:
            tag = f"unknown ({status})"
        print(f" [{tag}] {name:<11} {url}")
    print("\n Note: a 200 response may be a false positive. Verify manually.")
    RESULTS["username"] = {"value": username, "possible_profiles": found}


user_g = ""


# ------------------------------------------------------ 3. RDAP + DNS
def do_rdap(domain):
    section(f"RDAP (public registration data): {domain}")
    data = get_json(f"https://rdap.org/domain/{urllib.parse.quote(domain)}")
    if "error" in data:
        print(" RDAP lookup failed:", data["error"])
        return
    print(" Name   :", data.get("ldhName"))
    print(" Status :", ", ".join(data.get("status", [])) or "n/a")
    for ev in data.get("events", []):
        print(f" Event  : {ev.get('eventAction'):<18} {ev.get('eventDate')}")
    ns = [n.get("ldhName") for n in data.get("nameservers", [])]
    if ns:
        print(" NS     :", ", ".join(ns))
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vc = ent.get("vcardArray", [None, []])[1]
            for item in vc:
                if item[0] == "fn":
                    print(" Registrar:", item[3])
    RESULTS["rdap"] = {"domain": domain, "status": data.get("status"),
                       "nameservers": ns}


def do_dns(domain):
    section(f"DNS resolution: {domain}")
    info = {}
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        info["A"] = ips
        print(" A records :", ", ".join(ips))
        for ip in ips:
            try:
                print(f" PTR {ip} :", socket.gethostbyaddr(ip)[0])
            except Exception:
                pass
    except Exception as e:
        print(" Resolution failed:", e)
    # DNS-over-HTTPS (public Google resolver) for more record types
    for rtype in ("MX", "TXT", "NS"):
        data = get_json(f"https://dns.google/resolve?name={domain}&type={rtype}")
        answers = data.get("Answer", []) if isinstance(data, dict) else []
        vals = [a.get("data") for a in answers]
        if vals:
            info[rtype] = vals
            print(f" {rtype:<4} records:")
            for v in vals:
                print("     ", v)
    RESULTS["dns"] = info


# ------------------------------------------------ 4. HTTP header review
SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
               "X-Frame-Options", "X-Content-Type-Options",
               "Referrer-Policy", "Permissions-Policy"]


def do_headers(domain):
    section(f"HTTP headers (single request): {domain}")
    url = "https://" + domain
    try:
        with http_get(url) as r:
            hdrs = dict(r.headers)
            print(" Status :", r.status, "| Final URL:", r.geturl())
    except urllib.error.HTTPError as e:
        hdrs = dict(e.headers)
        print(" Status :", e.code)
    except Exception as e:
        print(" Request failed:", e)
        return
    for h in ("Server", "X-Powered-By", "Content-Type"):
        if h in hdrs:
            print(f" {h}: {hdrs[h]}")
    missing = [h for h in SEC_HEADERS if h not in hdrs]
    print(" Security headers present :",
          [h for h in SEC_HEADERS if h in hdrs] or "none")
    print(" Security headers missing :", missing or "none")
    RESULTS["headers"] = {"missing_security_headers": missing}


# ------------------------------------------- 5. Wayback + CT subdomains
def do_wayback(domain):
    section(f"Wayback Machine: {domain}")
    data = get_json("https://archive.org/wayback/available?url=" +
                    urllib.parse.quote(domain))
    snap = data.get("archived_snapshots", {}).get("closest")
    if snap:
        print(" Closest snapshot:", snap.get("url"), "|", snap.get("timestamp"))
        RESULTS["wayback"] = snap
    else:
        print(" No snapshot found (or lookup failed).")


def do_ct(domain):
    section(f"Certificate Transparency subdomains: {domain}")
    data = get_json(f"https://crt.sh/?q=%25.{domain}&output=json")
    if isinstance(data, dict):
        print(" crt.sh lookup failed:", data.get("error"))
        return
    names = set()
    for row in data:
        for n in row.get("name_value", "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain):
                names.add(n)
    for n in sorted(names)[:100]:
        print("  ", n)
    print(f" Total unique names: {len(names)} (showing up to 100)")
    RESULTS["ct_subdomains"] = sorted(names)


# ------------------------------------------------------------- reporting
def save_report(path=None):
    if not RESULTS:
        print(" Nothing to save yet.")
        return
    path = path or f"osint_report_{datetime.now():%Y%m%d_%H%M%S}.json"
    payload = {"tool": TITLE, "credit": CREDIT,
               "generated": datetime.now().isoformat(), "results": RESULTS}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    print(f" Report saved: {os.path.abspath(path)}")


def full_domain(domain):
    do_queries("domain", domain)
    do_rdap(domain)
    do_dns(domain)
    do_headers(domain)
    do_wayback(domain)
    do_ct(domain)


# ------------------------------------------------------------------ menu
MENU = """
 [1] Domain full public profile
 [2] Username presence check
 [3] Search queries: email
 [4] Search queries: person name
 [5] Search queries: phone number
 [6] Search queries: IP address
 [7] RDAP + DNS only
 [8] Save report (JSON)
 [0] Exit
"""


def interactive():
    banner()
    while True:
        print(MENU)
        try:
            c = input(" osint> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if c == "0":
            break
        elif c == "1":
            full_domain(clean_domain(input(" Domain: ")))
        elif c == "2":
            do_username(input(" Username: ").strip())
        elif c == "3":
            do_queries("email", input(" Email: ").strip())
        elif c == "4":
            do_queries("name", input(" Full name: ").strip())
        elif c == "5":
            do_queries("phone", input(" Phone: ").strip())
        elif c == "6":
            do_queries("ip", input(" IP: ").strip())
        elif c == "7":
            d = clean_domain(input(" Domain: "))
            do_rdap(d)
            do_dns(d)
        elif c == "8":
            save_report()
        else:
            print(" Invalid choice.")
    print(f"\n {CREDIT}")


def main():
    ap = argparse.ArgumentParser(description=f"{TITLE} - {CREDIT}")
    ap.add_argument("-d", "--domain", help="domain to profile")
    ap.add_argument("-u", "--username", help="username to check")
    ap.add_argument("-e", "--email", help="build search queries for an email")
    ap.add_argument("-n", "--name", help="build search queries for a name")
    ap.add_argument("-p", "--phone", help="build search queries for a phone")
    ap.add_argument("-i", "--ip", help="build search queries for an IP")
    ap.add_argument("-o", "--output", help="save JSON report to this path")
    args = ap.parse_args()

    if not any([args.domain, args.username, args.email, args.name,
                args.phone, args.ip]):
        interactive()
        return

    banner()
    if args.domain:
        full_domain(clean_domain(args.domain))
    if args.username:
        do_username(args.username)
    if args.email:
        do_queries("email", args.email)
    if args.name:
        do_queries("name", args.name)
    if args.phone:
        do_queries("phone", args.phone)
    if args.ip:
        do_queries("ip", args.ip)
    if args.output:
        save_report(args.output)
    print(f"\n {CREDIT}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n Interrupted.")
        sys.exit(130)
