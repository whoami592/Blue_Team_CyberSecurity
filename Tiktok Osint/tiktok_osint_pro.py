#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TikTok OSINT Investigator Pro
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Collects and analyses PUBLICLY available TikTok profile data only.
No login, no scraping of private content, no bypassing of access controls.
Use only for lawful, authorised investigations and in line with TikTok's ToS.

Features
  - Public profile lookup (id, nickname, bio, verified/private flags, region, stats)
  - Account creation time derived from the public user ID (snowflake timestamp)
  - Bio intelligence: emails, URLs, @handles, phone-like strings, keywords
  - Engagement metrics (likes/follower, likes/video, follow ratio)
  - Username variant generator + TikTok existence check
  - Cross-platform username presence check (HTTP status based, indicative only)
  - Batch mode, JSON / TXT / HTML reports with SHA-256 evidence hash
  - stdlib only (no pip installs)

Usage
  python3 tiktok_osint_pro.py -u someuser
  python3 tiktok_osint_pro.py -u someuser --variants --crosscheck --format all
  python3 tiktok_osint_pro.py -f users.txt --out reports --delay 3
"""

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠶⢛⡉⠉⠀⠀⠀⠉⠉⠛⠲⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⢋⣴⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⠋⣴⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⡤⠤⣤⡀⠀⠀⠀⡾⢁⣾⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢢⠘⣷⡀⠀⠀⠀⢀⣶⠶⣄⠀⠀⠀⠀
⠀⠀⠀⠀⢸⡆⢀⣸⡇⠀⠀⢸⠃⣼⣿⣿⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣧⠘⣧⠀⠀⣠⡾⠁⠀⠸⡧⣤⣠⣄
⢀⣠⠤⠶⠿⠃⠀⠙⢿⣄⣠⡟⢠⣿⣿⣿⡜⣆⠀⠀⢸⣿⡶⠖⠒⠒⠻⡇⠀⡀⠀⠀⠀⠀⣿⡇⢹⣆⣠⣿⡷⠀⠀⠀⠙⠀⠀⣿
⢸⣇⠀⢀⣠⣤⣴⣤⣀⣹⠏⣠⣿⣿⣿⣿⣿⣾⣦⡀⢌⠻⣀⠀⠀⣠⠜⣡⠊⠀⠀⠀⣠⣾⡿⠗⠀⠹⣿⠋⠀⢀⣀⠀⠀⢀⣼⠇
⠀⠛⠷⠟⠋⠉⠉⠉⠻⣿⠀⠾⣿⠓⡶⣬⣉⡙⠛⠿⠷⠷⠦⠉⣉⠤⠞⠀⠀⠤⠐⣚⣩⣴⢾⡿⢿⡄⣻⡶⠾⠿⣷⣀⣤⠞⠃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣆⠀⢻⣤⡇⣿⣿⣿⣿⣶⣶⠶⣶⠶⠶⡶⢲⣶⣶⣿⣿⣿⣷⣱⢸⡇⠊⣠⡿⠀⠀⠀⠀⠉⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣼⡟⠀⣻⣿⣿⣿⣿⣿⣿⡿⣷⡻⣿⣿⣿⣿⣿⣿⣿⣿⠈⢿⣥⠞⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡃⠀⠀⠉⠛⠛⠛⠛⠙⡟⣰⣿⣷⠘⡿⢿⡿⠿⠿⠟⠋⠀⠀⢘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⢈⣷⣦⡶⣾⠻⡿⠑⠦⠀⠠⠋⠈⠉⢧⠀⠀⠠⢺⡏⣹⣷⣶⡤⠾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⡴⠋⠉⠙⠓⣤⡤⠶⠾⠛⣋⠥⣺⣿⡷⡅⠦⢀⡀⠀⠀⠀⠀⢀⣀⡤⠲⡎⣇⣿⣤⡉⠛⢦⣄⡀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀
⠀⢸⡇⠀⣀⡀⠉⠀⠀⢀⡤⢊⣵⠞⢡⡞⠉⢸⣧⢈⠁⠹⠁⢹⠁⢹⠁⣡⣰⢻⠉⠙⣿⠿⣦⡀⠈⠙⠷⣖⠛⠛⠛⠛⠷⣦⠀⠀
⠀⠀⠙⠓⠾⣿⡆⠀⠀⠎⣸⠟⠁⢰⡏⠀⠀⠘⠻⣏⡷⠤⡤⢤⠤⢴⠒⣏⠿⠋⠃⠀⠈⣷⠈⢻⣇⡀⠀⠀⠉⠀⠀⢀⡼⠋⠀⠀
⠀⠀⠀⠀⠀⣼⠁⠠⠚⢠⡿⠀⠀⠈⠛⠲⣤⣀⠀⠀⠙⠒⠣⠸⠂⠛⠚⠀⠀⠀⢀⣴⠿⠋⠀⠀⢻⠉⠀⢴⣶⠗⠶⠞⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠻⣦⣤⡴⠟⠁⠀⠀⠀⠀⠀⠸⣿⡇⠀⣀⣤⣶⣶⣾⣯⡁⠀⣠⣶⠟⠀⠀⠀⠀⠀⠈⠷⣤⣨⡏⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠿⠿⠟⠋⠀⠀⠈⠛⠿⠿⠿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠂⠒⠒⠒⠒⠶⠆⠀⠀⠀⠀⠀⠀⠒⠒⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

TITLE = "TikTok OSINT Investigator Pro"
CREDIT = "coded by Mr Sabaz Ali Khan"
VERSION = "1.0"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

PLATFORMS = {
    "Instagram": "https://www.instagram.com/{u}/",
    "X/Twitter": "https://x.com/{u}",
    "GitHub": "https://github.com/{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Reddit": "https://www.reddit.com/user/{u}/",
    "Snapchat": "https://www.snapchat.com/add/{u}",
    "Telegram": "https://t.me/{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
}

KEYWORDS = {
    "contact/business": ["dm", "business", "collab", "inquiries", "enquiries", "booking", "email", "contact"],
    "commerce": ["shop", "store", "order", "discount", "promo", "link in bio", "whatsapp"],
    "financial-risk": ["crypto", "forex", "investment", "giveaway", "profit", "signals", "airdrop"],
    "other-platforms": ["insta", "ig:", "snap", "youtube", "yt:", "telegram", "tg:", "twitter", "discord"],
}

RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RE_URL = re.compile(r"https?://[^\s<>\"']+|(?:www\.)[^\s<>\"']+", re.I)
RE_HANDLE = re.compile(r"(?<![\w@])@([A-Za-z0-9._]{2,30})")
RE_PHONE = re.compile(r"(?<!\d)(?:\+?\d[\d\s\-().]{7,16}\d)(?!\d)")

TIKTOK_USER = re.compile(r"^[A-Za-z0-9._]{2,24}$")


def col(txt, c):
    if not sys.stdout.isatty():
        return txt
    codes = {"g": "32", "r": "31", "y": "33", "c": "36", "b": "1"}
    return f"\033[{codes.get(c, '0')}m{txt}\033[0m"


def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:  # network errors
        return 0, str(e)


def snowflake_time(user_id):
    """TikTok IDs embed a unix timestamp in the high 32 bits (public OSINT technique)."""
    try:
        ts = int(user_id) >> 32
        d = dt.datetime.fromtimestamp(ts, dt.timezone.utc)
        if 2014 <= d.year <= dt.datetime.now().year + 1:
            return d.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OverflowError, OSError):
        pass
    return None


def fetch_profile(username):
    username = username.lstrip("@").strip()
    out = {"queried": username, "url": f"https://www.tiktok.com/@{username}",
           "found": False, "error": None}
    if not TIKTOK_USER.match(username):
        out["error"] = "invalid username format"
        return out
    status, body = http_get(out["url"])
    out["http_status"] = status
    if status == 404:
        out["error"] = "profile not found (404)"
        return out
    if status != 200:
        out["error"] = f"request failed (status {status}) {body[:120] if status == 0 else ''}".strip()
        return out
    m = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', body, re.S)
    if not m:
        m = re.search(r'<script id="SIGI_STATE"[^>]*>(.*?)</script>', body, re.S)
        if not m:
            out["error"] = "profile data block not found (page layout changed, captcha or geo-block)"
            return out
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        out["error"] = "could not parse profile JSON"
        return out
    scope = data.get("__DEFAULT_SCOPE__", {})
    detail = scope.get("webapp.user-detail", {})
    info = detail.get("userInfo")
    if not info:
        code = detail.get("statusCode")
        out["error"] = f"no user info (statusCode={code})" if code else "no user info in page"
        return out
    u, s = info.get("user", {}), info.get("stats", {})
    out["found"] = True
    out["profile"] = {
        "id": u.get("id"),
        "unique_id": u.get("uniqueId"),
        "nickname": u.get("nickname"),
        "bio": u.get("signature", ""),
        "verified": u.get("verified"),
        "private": u.get("privateAccount"),
        "region": u.get("region"),
        "language": u.get("language"),
        "bio_link": (u.get("bioLink") or {}).get("link"),
        "avatar_url": u.get("avatarLarger"),
        "commerce_user": bool((u.get("commerceUserInfo") or {}).get("commerceUser")),
        "nickname_modified": u.get("nickNameModifyTime"),
        "username_modified": u.get("uniqueIdModifyTime"),
        "created_from_id": snowflake_time(u.get("id")),
        "created_field": (dt.datetime.fromtimestamp(u["createTime"], dt.timezone.utc)
                          .strftime("%Y-%m-%d %H:%M:%S UTC") if u.get("createTime") else None),
    }
    out["stats"] = {
        "followers": s.get("followerCount"),
        "following": s.get("followingCount"),
        "likes": s.get("heartCount", s.get("heart")),
        "videos": s.get("videoCount"),
        "friends": s.get("friendCount"),
    }
    return out


def analyse(result):
    """Bio intelligence + engagement metrics from public fields."""
    p, s = result["profile"], result["stats"]
    text = " ".join(filter(None, [p.get("bio"), p.get("nickname"), p.get("bio_link")]))
    intel = {
        "emails": sorted(set(RE_EMAIL.findall(text))),
        "urls": sorted(set(RE_URL.findall(text))),
        "handles": sorted(set(RE_HANDLE.findall(p.get("bio") or ""))),
        "phone_like": sorted(set(x.strip() for x in RE_PHONE.findall(p.get("bio") or ""))),
        "keyword_hits": {},
    }
    low = text.lower()
    for cat, words in KEYWORDS.items():
        hits = [w for w in words if w in low]
        if hits:
            intel["keyword_hits"][cat] = hits
    metrics = {}
    f, fg, lk, v = (s.get("followers") or 0), (s.get("following") or 0), (s.get("likes") or 0), (s.get("videos") or 0)
    metrics["likes_per_video"] = round(lk / v, 1) if v else None
    metrics["likes_per_follower"] = round(lk / f, 2) if f else None
    metrics["follower_following_ratio"] = round(f / fg, 2) if fg else None
    flags = []
    if p.get("verified"):
        flags.append("Verified account")
    if p.get("private"):
        flags.append("Private account (content not publicly visible)")
    if f and fg and fg > 20 * f and fg > 1000:
        flags.append("Follows far more accounts than follow it (possible follow-spam pattern)")
    if v == 0 and f > 5000:
        flags.append("Large audience with zero public videos (worth manual review)")
    if v and lk / max(v, 1) < 2 and f > 10000:
        flags.append("Very low likes/video relative to audience (possible purchased followers)")
    if p.get("username_modified"):
        try:
            flags.append("Username was changed (last change: %s UTC)" % dt.datetime.fromtimestamp(
                int(p["username_modified"]), dt.timezone.utc).strftime("%Y-%m-%d"))
        except (ValueError, OverflowError, OSError):
            pass
    if "financial-risk" in intel["keyword_hits"]:
        flags.append("Bio contains finance/giveaway keywords (scam-pattern indicator, not proof)")
    return intel, metrics, flags


def variants(u):
    u = u.lower().lstrip("@")
    base = re.sub(r"[._]", "", u)
    v = {u, base, u.replace(".", "_"), u.replace("_", "."), u + "official", u + "_official",
         "the" + base, base + "tt", base + "1", base + "_", "_" + base, "real" + base,
         base + "hq", base + "x"}
    return sorted(x for x in v if TIKTOK_USER.match(x) and x != u)


def check_variants(u, delay):
    found = []
    for vname in variants(u):
        r = fetch_profile(vname)
        if r["found"]:
            found.append({"username": vname, "url": r["url"],
                          "nickname": r["profile"]["nickname"],
                          "followers": r["stats"]["followers"]})
        time.sleep(delay)
    return found


def crosscheck(u, delay):
    res = {}
    for name, tmpl in PLATFORMS.items():
        status, _ = http_get(tmpl.format(u=u), timeout=10)
        if status == 200:
            res[name] = {"url": tmpl.format(u=u), "status": "possible match (200)"}
        elif status == 404:
            res[name] = {"url": tmpl.format(u=u), "status": "not found (404)"}
        else:
            res[name] = {"url": tmpl.format(u=u), "status": f"inconclusive ({status or 'network error'})"}
        time.sleep(delay)
    return res


def investigate(username, args):
    r = fetch_profile(username)
    r["generated_utc"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    r["tool"] = f"{TITLE} v{VERSION} - {CREDIT}"
    if r["found"]:
        r["intel"], r["metrics"], r["flags"] = analyse(r)
        if args.variants:
            r["variants_found"] = check_variants(r["profile"]["unique_id"] or username, args.delay)
        if args.crosscheck:
            r["crosscheck"] = crosscheck(r["profile"]["unique_id"] or username, args.delay)
    return r


def to_text(r):
    L = [f"{TITLE} v{VERSION}  |  {CREDIT}", "=" * 64,
         f"Target   : @{r['queried']}", f"URL      : {r['url']}",
         f"Generated: {r['generated_utc']}", ""]
    if not r["found"]:
        L.append(f"RESULT: not retrieved - {r['error']}")
        return "\n".join(L)
    p, s = r["profile"], r["stats"]
    L += ["[PROFILE]"]
    for k in ("id", "unique_id", "nickname", "verified", "private", "region", "language",
              "commerce_user", "created_from_id", "created_field", "bio_link"):
        L.append(f"  {k:<16}: {p.get(k)}")
    L.append(f"  bio             : {(p.get('bio') or '').replace(chr(10), ' | ')}")
    L += ["", "[STATS]"] + [f"  {k:<16}: {v}" for k, v in s.items()]
    L += ["", "[METRICS]"] + [f"  {k:<26}: {v}" for k, v in r["metrics"].items()]
    L += ["", "[BIO INTELLIGENCE]"]
    for k, v in r["intel"].items():
        L.append(f"  {k:<16}: {v if v else '-'}")
    L += ["", "[FLAGS]"] + ([f"  - {f}" for f in r["flags"]] or ["  none"])
    if "variants_found" in r:
        L += ["", "[USERNAME VARIANTS ON TIKTOK]"] + (
            [f"  @{x['username']}  ({x['nickname']}, {x['followers']} followers)" for x in r["variants_found"]]
            or ["  none found"])
    if "crosscheck" in r:
        L += ["", "[CROSS-PLATFORM (indicative only - verify manually)]"]
        L += [f"  {n:<10}: {d['status']}  {d['url']}" for n, d in r["crosscheck"].items()]
    L += ["", "Note: data is public-profile only; a matching username is not proof of the same person."]
    return "\n".join(L)


def to_html(r):
    body = html.escape(to_text(r))
    return ("<!doctype html><html><head><meta charset='utf-8'><title>%s - @%s</title>"
            "<style>body{background:#0b0f14;color:#d7e3f0;font-family:monospace;padding:24px}"
            "pre{white-space:pre-wrap;line-height:1.5}h1{color:#25f4ee}</style></head><body>"
            "<h1>%s</h1><pre>%s</pre></body></html>") % (
        TITLE, html.escape(r["queried"]), TITLE, body)


def save(r, outdir, fmt):
    os.makedirs(outdir, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(outdir, f"tiktok_{re.sub(r'[^A-Za-z0-9._-]', '_', r['queried'])}_{stamp}")
    paths = []
    fmts = ["json", "txt", "html"] if fmt == "all" else [fmt]
    for f in fmts:
        data = {"json": lambda: json.dumps(r, indent=2, ensure_ascii=False),
                "txt": lambda: to_text(r), "html": lambda: to_html(r)}[f]()
        path = f"{base}.{f}"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data)
        digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
        paths.append((path, digest))
    return paths


def main():
    ap = argparse.ArgumentParser(description=f"{TITLE} - {CREDIT}")
    ap.add_argument("-u", "--user", help="TikTok username (with or without @)")
    ap.add_argument("-f", "--file", help="file with one username per line (batch mode)")
    ap.add_argument("--variants", action="store_true", help="check username variants on TikTok")
    ap.add_argument("--crosscheck", action="store_true", help="check username on other platforms")
    ap.add_argument("--format", choices=["json", "txt", "html", "all"], default="txt")
    ap.add_argument("--out", default="tiktok_reports", help="report output directory")
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between requests (be polite)")
    ap.add_argument("--no-save", action="store_true", help="print only, do not write reports")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    if not args.no_banner:
        print(col(BANNER, "c"))
    print(col(f"  {TITLE} v{VERSION}  |  {CREDIT}", "b"))
    print(col("  Public data only. Use for lawful, authorised investigations.\n", "y"))

    targets = []
    if args.user:
        targets.append(args.user)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            sys.exit(f"cannot read {args.file}: {e}")
    if not targets:
        t = input("Enter TikTok username: ").strip()
        if not t:
            sys.exit("no username given")
        targets.append(t)

    for i, t in enumerate(targets):
        print(col(f"[*] Investigating @{t.lstrip('@')} ...", "c"))
        r = investigate(t, args)
        print(to_text(r))
        if not args.no_save and r["found"]:
            for path, digest in save(r, args.out, args.format):
                print(col(f"[+] saved {path}", "g"))
                print(f"    sha256: {digest}")
        elif not r["found"]:
            print(col(f"[!] {r['error']}", "r"))
        if i < len(targets) - 1:
            time.sleep(args.delay)
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted")
