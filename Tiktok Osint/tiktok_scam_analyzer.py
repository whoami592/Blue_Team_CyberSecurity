#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TikTok Scam & Fraud Analyzer
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Defensive, offline, stdlib-only tool. It analyzes content YOU supply
(DM / comment / caption / bio text, links, and basic profile details)
and scores it for common TikTok scam and fraud patterns:
giveaway & prize scams, crypto/investment fraud, romance scams,
fake job/"task" scams, phishing & fake login pages, fake verification
(blue badge) offers, TikTok Shop refund scams, support impersonation,
and lookalike (typosquatted) domains.

No network requests are made and no TikTok data is scraped.

Usage:
  python3 tiktok_scam_analyzer.py                      # interactive menu
  python3 tiktok_scam_analyzer.py -t "message text"    # analyze text
  python3 tiktok_scam_analyzer.py -u "https://..."     # analyze URL(s)
  python3 tiktok_scam_analyzer.py -f messages.txt      # batch (one item/line)
  python3 tiktok_scam_analyzer.py --profile            # profile check (prompted)
  Add -o report.json (or .txt) to save a report.
"""

import argparse
import difflib
import json
import re
import sys
from datetime import datetime
from urllib.parse import urlparse, unquote

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⠉⠀⠀⢀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⣀⣴⣿⣿⣭⣭⣭⣭⣿⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣴⣯⣧⣀⣀⣀⣀⣀⣤
⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠟⠉⠉⠉⠉⠉⠉⠉⠉
⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣹⣿⣿⡟⠋⢁⣴⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⡿⠿⢀⣴⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣤⣤⣶⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⡀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣙⣿⣿⣿⣿⣿⣿⣿⡿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣼⣿⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠁⠀⢸⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠉⠀⠀⠀⠀⠀⠀⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣆⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠿⢿⣿⣿⣦⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠸⢿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⠛⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

TITLE = "TikTok Scam & Fraud Analyzer"
CREDIT = "coded by Mr Sabaz Ali Khan"
VERSION = "1.0"

# ----------------------------------------------------------------------
# Detection rules
# category: (weight, description, [regex patterns])
# ----------------------------------------------------------------------
RULES = {
    "Giveaway / Prize Scam": (
        20, "Fake giveaway or 'you won' prize bait asking for action or fees.",
        [r"\byou(?:'ve| have)? (?:have )?won\b", r"\bcongratulations?\b.{0,40}\b(?:winner|won|selected)\b",
         r"\bgiveaway\b", r"\bfree (?:iphone|robux|v-?bucks|gift ?card|coins?|followers|likes)\b",
         r"\bclaim (?:your )?(?:prize|reward|gift|bonus)\b", r"\blucky (?:winner|draw)\b",
         r"\bpay (?:a )?(?:small )?(?:shipping|delivery|processing|claim) fee\b"]),
    "Crypto / Investment Fraud": (
        25, "Guaranteed returns, 'signals', trading bots, or crypto doubling schemes.",
        [r"\bguaranteed (?:profit|returns?|income)\b", r"\bdouble your (?:money|bitcoin|btc|crypto|investment)\b",
         r"\b(?:forex|crypto|binary|bitcoin|usdt|btc) (?:trading|signals?|mentor|investment|bot)\b",
         r"\b\d{2,4}\s?% (?:daily|weekly|monthly|roi|returns?)\b", r"\bpassive income\b",
         r"\b(?:send|deposit|invest).{0,30}\b(?:usdt|btc|bitcoin|eth|crypto)\b",
         r"\bhigh[- ]yield\b", r"\bno risk\b", r"\bfinancial freedom\b"]),
    "Fake Job / Task Scam": (
        25, "Easy-money 'like & earn', 'task' or 'review' jobs that later demand deposits.",
        [r"\b(?:earn|make) \$?\d{2,5}\s?(?:/|per|a)\s?(?:day|hour|week)\b",
         r"\b(?:like|rate|review|watch|boost)\b.{0,30}\b(?:earn|paid|commission)\b",
         r"\b(?:part[- ]time|work from home|remote)\b.{0,40}\b(?:\$|usd|daily pay|per day)\b",
         r"\b(?:task|order) (?:commission|rebate|bonus)\b", r"\bno experience (?:needed|required)\b",
         r"\bdaily (?:salary|pay|payment)\b", r"\bhiring\b.{0,30}\b(?:tiktok|assistant|promoter)\b"]),
    "Romance / Trust Scam": (
        15, "Rapid affection, overseas/military/oil-rig stories, then money requests.",
        [r"\b(?:my )?(?:love|dear|darling|sweetheart|honey)\b.{0,60}\b(?:money|help|gift|send|transfer)\b",
         r"\b(?:soldier|army|navy|oil rig|overseas|deployed|engineer abroad)\b.{0,60}\b(?:send|money|gift card|fund)\b",
         r"\bi (?:need|want) your (?:help|trust)\b", r"\bi(?:'m| am) (?:stuck|stranded)\b",
         r"\bcustoms (?:fee|clearance)\b"]),
    "Phishing / Fake Login": (
        30, "Pushes you to log in, verify, or enter credentials on a link.",
        [r"\b(?:verify|confirm|secure|restore|reactivate) your (?:account|login|password|identity|tiktok)\b",
         r"\b(?:log ?in|sign ?in) (?:here|now|below|via)\b", r"\bpassword\b.{0,30}\b(?:expired|reset|compromised)\b",
         r"\baccount (?:will be|has been|is) (?:suspended|banned|deleted|disabled|restricted|locked)\b",
         r"\bsuspicious (?:activity|login)\b", r"\b(?:otp|verification code|2fa code)\b.{0,30}\b(?:send|share|give|reply)\b",
         r"\bsend (?:me )?(?:the )?(?:code|otp)\b"]),
    "Fake Verification / Badge Offer": (
        20, "Offers to get you a verified badge, monetization, or fan boost for a fee/credentials.",
        [r"\b(?:blue|verified) (?:tick|badge|check(?:mark)?)\b", r"\bget verified\b",
         r"\b(?:creator fund|monetization|live access)\b.{0,40}\b(?:unlock|activate|fee|pay)\b",
         r"\b(?:buy|get|boost).{0,15}\b(?:followers|likes|views|coins)\b", r"\bcopyright (?:violation|strike|notice)\b"]),
    "TikTok Shop / Refund Scam": (
        20, "Fake order, refund, or delivery issues used to harvest payment or card data.",
        [r"\b(?:refund|chargeback)\b.{0,40}\b(?:card|bank|link|app|screenshot)\b",
         r"\b(?:order|parcel|package)\b.{0,40}\b(?:failed|held|pending|undelivered)\b.{0,40}\b(?:pay|link|fee|update)\b",
         r"\b(?:overpaid|overpayment)\b", r"\bpay (?:outside|off)[- ]?(?:the )?(?:app|platform|tiktok)\b",
         r"\bseller (?:verification|deposit)\b"]),
    "Support / Brand Impersonation": (
        20, "Claims to be TikTok Support, Trust & Safety, or an official team.",
        [r"\btiktok (?:support|team|security|official|trust (?:&|and) safety|help ?desk|admin)\b",
         r"\b(?:official|authorized) (?:tiktok|account|agent|representative)\b",
         r"\bcommunity guidelines (?:violation|team)\b", r"\bpolicy violation\b"]),
    "Off-Platform Move": (
        15, "Pushes the chat to WhatsApp/Telegram/Signal where reporting is harder.",
        [r"\b(?:whats ?app|telegram|signal|wechat|line|viber|imo)\b.{0,30}(?:\+?\d[\d\s\-]{6,}|@\w+|t\.me/|wa\.me/)",
         r"\b(?:text|message|contact|add) me (?:on|at|via) (?:whats ?app|telegram|signal)\b",
         r"\bt\.me/\w+", r"\bwa\.me/\d+", r"\bmove (?:to|this to) (?:whats ?app|telegram)\b"]),
    "Payment Red Flags": (
        20, "Untraceable or unusual payment methods.",
        [r"\b(?:gift ?cards?|itunes|google play|steam card|amazon card)\b", r"\b(?:western union|moneygram)\b",
         r"\b(?:cash ?app|zelle|venmo|paypal friends and family|crypto wallet)\b",
         r"\b(?:wire|bank) transfer\b", r"\b(?:usdt|trc20|erc20)\b", r"\bupfront (?:fee|payment|deposit)\b",
         r"\bregistration fee\b"]),
    "Urgency / Pressure": (
        10, "Artificial deadlines and secrecy to stop you from thinking or asking others.",
        [r"\b(?:act|reply|respond|claim) (?:now|immediately|fast|today)\b", r"\bwithin (?:\d+|24|48) ?(?:hours?|hrs?|minutes?|mins?)\b",
         r"\blast chance\b", r"\burgent(?:ly)?\b", r"\blimited (?:time|slots|spots|offer)\b",
         r"\bdon'?t tell (?:anyone|anybody)\b", r"\bkeep (?:this|it) (?:secret|private|confidential)\b",
         r"\bonly \d+ (?:slots?|spots?) left\b"]),
}

# ----------------------------------------------------------------------
# URL analysis data
# ----------------------------------------------------------------------
LEGIT_DOMAINS = {"tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokshop.com"}
BRAND_LABELS = ["tiktok", "tiktokshop", "tiktokv", "tiktokcdn"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at",
              "ow.ly", "buff.ly", "tiny.cc", "rebrand.ly", "s.id", "v.gd", "t.ly", "linktr.ee", "bio.link"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "link", "online", "site", "shop", "icu", "cfd", "sbs", "live",
                   "work", "rest", "gq", "tk", "ml", "ga", "cf", "buzz", "monster", "vip", "cyou", "zip", "mov"}
PHISH_WORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "wallet", "claim",
               "reward", "bonus", "gift", "support", "helpdesk", "recover", "unlock", "badge", "creator-fund"]
IMPERSONATION_WORDS = ["official", "support", "verified", "team", "admin", "security", "help", "tiktok", "tik_tok", "tlktok"]

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'()]+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>\"'()]*")
BARE_RE = re.compile(r"(?i)\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|t\.me|wa\.me)/[^\s<>\"'()]+")

LEVELS = [(0, "LOW", "No strong scam indicators found."),
          (25, "MODERATE", "Some suspicious signals. Verify before interacting."),
          (50, "HIGH", "Multiple scam indicators. Do NOT click, pay, or share details."),
          (75, "CRITICAL", "Very likely a scam/fraud attempt. Block, report, and do not engage.")]


def colorize(text, code, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled and sys.stdout.isatty() else text


def level_for(score):
    lvl = LEVELS[0]
    for item in LEVELS:
        if score >= item[0]:
            lvl = item
    return lvl


def registered_domain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if parts[-2] in {"co", "com", "org", "net", "gov", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def extract_urls(text):
    found = [m.group(0).rstrip(".,;:!?") for m in URL_RE.finditer(text)]
    found += [m.group(0).rstrip(".,;:!?") for m in BARE_RE.finditer(text)]
    seen, out = set(), []
    for u in found:
        if u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out


# ----------------------------------------------------------------------
# Analyzers
# ----------------------------------------------------------------------
def analyze_text(text):
    findings, score = [], 0
    lowered = text.lower()
    for cat, (weight, desc, patterns) in RULES.items():
        hits = []
        for p in patterns:
            for m in re.finditer(p, lowered, re.I | re.S):
                snippet = m.group(0).strip()
                if snippet and snippet not in hits:
                    hits.append(snippet[:80])
        if hits:
            add = weight + min(len(hits) - 1, 3) * 3
            score += add
            findings.append({"category": cat, "points": add, "description": desc, "evidence": hits[:5]})

    # Stylistic red flags
    letters = [c for c in text if c.isalpha()]
    if len(letters) > 20 and sum(c.isupper() for c in letters) / len(letters) > 0.5:
        score += 5
        findings.append({"category": "Style: Excessive CAPS", "points": 5,
                         "description": "Shouting/pressure style common in bulk scam messages.", "evidence": []})
    if text.count("!") >= 4:
        score += 3
        findings.append({"category": "Style: Excessive exclamation", "points": 3,
                         "description": "Hype punctuation often used to create urgency.", "evidence": []})
    emoji_count = len(re.findall(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]", text))
    if emoji_count >= 8:
        score += 3
        findings.append({"category": "Style: Emoji flooding", "points": 3,
                         "description": "Heavy emoji use is common in mass-sent promotional scams.", "evidence": []})
    if re.search(r"[\u200b\u200c\u200d\u2060\ufeff]", text):
        score += 8
        findings.append({"category": "Hidden characters", "points": 8,
                         "description": "Zero-width characters can evade keyword filters.", "evidence": []})
    if re.search(r"[A-Za-z][\u0400-\u04FF\u0370-\u03FF]|[\u0400-\u04FF\u0370-\u03FF][A-Za-z]", text):
        score += 8
        findings.append({"category": "Mixed-script lookalike letters", "points": 8,
                         "description": "Mixing Latin with Cyrillic/Greek letters can disguise words or names.", "evidence": []})

    # Contacts / phone numbers
    phones = re.findall(r"(?<!\d)\+?\d[\d\s\-]{9,15}\d(?!\d)", text)
    if phones and any(f["category"] == "Off-Platform Move" for f in findings) is False and len(phones) >= 1:
        score += 4
        findings.append({"category": "Phone number shared", "points": 4,
                         "description": "Unsolicited phone numbers often lead off-platform.",
                         "evidence": [p.strip() for p in phones[:3]]})
    return min(score, 100), findings


def analyze_url(raw):
    url = raw.strip()
    findings, score = [], 0
    to_parse = url if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", url) else "http://" + url
    try:
        p = urlparse(to_parse)
    except ValueError:
        return 40, [{"category": "Malformed URL", "points": 40, "description": "URL could not be parsed.", "evidence": [url]}]
    host = (p.hostname or "").lower()
    path = unquote(p.path + ("?" + p.query if p.query else "")).lower()
    reg = registered_domain(host) if host else ""
    label = reg.split(".")[0] if reg else ""
    tld = reg.split(".")[-1] if reg else ""

    def add(cat, pts, desc, ev=None):
        nonlocal score
        score += pts
        findings.append({"category": cat, "points": pts, "description": desc, "evidence": ev or [host or url]})

    is_legit = reg in LEGIT_DOMAINS
    if not host:
        add("Missing host", 30, "No valid hostname found.")
        return min(score, 100), findings

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        add("IP address host", 30, "Links using raw IPs hide the real brand/domain.")
    if "xn--" in host:
        add("Punycode / IDN domain", 30, "Internationalized domain may be a homograph lookalike.")
    if "@" in (p.netloc or ""):
        add("Credentials in URL", 25, "'user@host' trick hides the real destination.", [p.netloc])
    if p.scheme == "http":
        add("No HTTPS", 8, "Unencrypted link. Legitimate login/payment pages use HTTPS.")
    if reg in SHORTENERS or host in SHORTENERS:
        add("URL shortener", 15, "Destination is hidden. Expand with a safe previewer before opening.")
    if tld in SUSPICIOUS_TLDS and not is_legit:
        add("Suspicious TLD", 12, f".{tld} is heavily abused by scam campaigns.", [reg])
    if host.count(".") >= 4:
        add("Excessive subdomains", 12, "Deep subdomains often mimic trusted brands.", [host])

    # Brand abuse / typosquatting
    if not is_legit:
        norm_host = host.replace("-", "").replace("_", "").replace("0", "o").replace("1", "l").replace("!", "i")
        brand_in_host = any(b in norm_host for b in BRAND_LABELS)
        if brand_in_host:
            add("TikTok brand in non-TikTok domain", 35,
                f"'{host}' contains TikTok branding but is not an official TikTok domain.", [reg])
        else:
            best = max((difflib.SequenceMatcher(None, label.replace("-", ""), b).ratio() for b in BRAND_LABELS), default=0)
            leet = label.replace("0", "o").replace("1", "l").replace("!", "i").replace("5", "s")
            if best >= 0.78 or any(difflib.SequenceMatcher(None, leet, b).ratio() >= 0.8 for b in BRAND_LABELS):
                add("Lookalike (typosquat) domain", 35, "Domain is very similar to a TikTok domain.", [reg])
    elif host != reg and host.endswith("." + reg):
        pass  # legit subdomain e.g. vm.tiktok.com
    # "tiktok.com" inside subdomain or path of a different site
    if not is_legit and re.search(r"tiktok\.com", host + path):
        add("Fake TikTok path/subdomain", 25, "'tiktok.com' appears in a non-TikTok URL to fool readers.")

    hits = [w for w in PHISH_WORDS if w in host or w in path]
    if hits and not is_legit:
        add("Phishing keywords in URL", min(8 + 3 * len(hits), 22), "Login/verify/claim-style wording on a non-official domain.", hits[:6])
    if len(url) > 120:
        add("Very long URL", 6, "Long URLs are often used to hide the destination.", [url[:60] + "..."])
    if re.search(r"[?&](?:redirect|url|next|goto|continue|return)=https?", url, re.I):
        add("Open-redirect parameter", 15, "URL passes another link as a parameter, a redirect-abuse pattern.")
    if re.search(r"\.(?:apk|exe|scr|bat|msi|zip|rar|jar)(?:$|\?)", path):
        add("Risky file download", 30, "Link points to an installer/archive. Never install apps from DMs.")
    if is_legit and not findings:
        findings.append({"category": "Official TikTok domain", "points": 0,
                         "description": "Domain matches known TikTok domains. (Content on it can still be user-generated.)",
                         "evidence": [reg]})
    return min(score, 100), findings


def analyze_profile(username, bio, followers, following, videos, age_days, link, verified_claim):
    findings, score = [], 0

    def add(cat, pts, desc, ev=None):
        nonlocal score
        score += pts
        findings.append({"category": cat, "points": pts, "description": desc, "evidence": ev or []})

    u = (username or "").lstrip("@").lower()
    if u:
        if any(w in u for w in IMPERSONATION_WORDS):
            add("Impersonation-style username", 20, "Username uses official/support/verified wording.", [u])
        if re.search(r"\d{4,}$", u):
            add("Auto-generated username pattern", 8, "Long trailing digit strings are common on bulk fake accounts.", [u])
        if re.search(r"[il1o0]{4,}", u) or re.search(r"(.)\1{3,}", u):
            add("Confusable username", 6, "Look-alike characters or repeats used to mimic other accounts.", [u])
        sim = max((difflib.SequenceMatcher(None, u.replace("_", "").replace(".", ""), b).ratio() for b in BRAND_LABELS), default=0)
        if sim >= 0.75 and "tiktok" not in u:
            add("Username mimics TikTok brand", 20, "Handle is a near-copy of the TikTok name.", [u])

    if followers is not None and following is not None:
        if following > 0 and followers / max(following, 1) < 0.05 and following > 500:
            add("Mass-follow behaviour", 12, "Following far more accounts than followers (bulk outreach pattern).",
                [f"followers={followers}, following={following}"])
        if followers > 50000 and videos is not None and videos <= 2:
            add("Followers/videos mismatch", 15, "Huge following but almost no content suggests bought followers.",
                [f"followers={followers}, videos={videos}"])
    if age_days is not None and age_days < 30:
        add("Very new account", 15, "Accounts under 30 days old are commonly used for scam campaigns.", [f"{age_days} days"])
    if videos is not None and videos == 0:
        add("No posted videos", 8, "Account with no content contacting people is higher risk.")
    if verified_claim:
        add("Claims verified/official status", 6, "Verify the badge inside the app; bios and names can fake it.")

    if bio:
        s, f = analyze_text(bio)
        if s:
            score += min(s, 40)
            findings.append({"category": "Bio content indicators", "points": min(s, 40),
                             "description": "Scam-style wording detected in bio.",
                             "evidence": [x["category"] for x in f][:5]})
    if link:
        s, f = analyze_url(link)
        if s:
            score += min(s, 40)
            findings.append({"category": "Bio link risk", "points": min(s, 40),
                             "description": "Link in bio shows risk indicators.",
                             "evidence": [x["category"] for x in f][:5]})
    return min(score, 100), findings


def analyze_item(text):
    """Full analysis of a blob of text: wording + every URL inside it."""
    t_score, t_find = analyze_text(text)
    urls = extract_urls(text)
    url_results, u_max = [], 0
    for u in urls:
        s, f = analyze_url(u)
        url_results.append({"url": u, "score": s, "findings": f})
        u_max = max(u_max, s)
    combined = min(100, t_score + int(u_max * 0.6))
    if urls and t_score >= 20 and u_max >= 20:
        combined = min(100, combined + 10)  # corroboration bonus
    lvl = level_for(combined)
    return {"timestamp": datetime.now().isoformat(timespec="seconds"), "score": combined,
            "risk": lvl[1], "verdict": lvl[2], "text_score": t_score, "text_findings": t_find,
            "urls": url_results, "input": text[:500]}


# ----------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------
RECOMMENDATIONS = {
    "Phishing / Fake Login": "Never enter your TikTok login via a link. Open the app directly and check Inbox > System notifications.",
    "Crypto / Investment Fraud": "Guaranteed returns do not exist. Do not send crypto; report the account.",
    "Fake Job / Task Scam": "Real employers never ask you to pay or 'deposit' to earn. Stop and report.",
    "Giveaway / Prize Scam": "Real giveaways never require fees or card details. Check the host's official profile.",
    "Fake Verification / Badge Offer": "TikTok verifies accounts itself and never sells badges through DMs.",
    "TikTok Shop / Refund Scam": "Handle orders and refunds only inside the TikTok app / official TikTok Shop pages.",
    "Support / Brand Impersonation": "TikTok does not contact users through personal accounts asking for passwords or codes.",
    "Off-Platform Move": "Keep conversations in-app where reporting works. Be wary of moving to WhatsApp/Telegram.",
    "Payment Red Flags": "Gift cards, crypto and wire transfers are irreversible. Do not pay strangers this way.",
    "Romance / Trust Scam": "Never send money to someone you haven't met. Reverse-image-search their photos.",
    "Urgency / Pressure": "Pressure is a tactic. Pause, and talk to a trusted person before acting.",
}


def print_result(res, color=True):
    score, risk = res["score"], res["risk"]
    c = {"LOW": "92", "MODERATE": "93", "HIGH": "91", "CRITICAL": "95;1"}[risk]
    bar = "█" * (score // 5) + "░" * (20 - score // 5)
    print("\n" + "=" * 70)
    print(f" RISK SCORE : {score:>3}/100  [{bar}]")
    print(" RISK LEVEL : " + colorize(risk, c, color))
    print(f" VERDICT    : {res['verdict']}")
    print("=" * 70)
    if res["text_findings"]:
        print("\n[ Content Indicators ]")
        for f in res["text_findings"]:
            print(f"  [+{f['points']:>2}] {f['category']}")
            print(f"        {f['description']}")
            if f["evidence"]:
                print("        evidence: " + " | ".join(f["evidence"]))
    for u in res["urls"]:
        print(f"\n[ URL ] {u['url']}  (score {u['score']})")
        for f in u["findings"]:
            print(f"  [+{f['points']:>2}] {f['category']}: {f['description']}")
    cats = {f["category"] for f in res["text_findings"]}
    recs = [RECOMMENDATIONS[k] for k in RECOMMENDATIONS if k in cats]
    if res["urls"] and any(u["score"] >= 25 for u in res["urls"]):
        recs.append("Do not open the link. If curious, inspect it with a URL scanner in an isolated environment.")
    if risk in ("HIGH", "CRITICAL"):
        recs += ["Report the account/message in TikTok (Profile > ... > Report) and block the sender.",
                 "If you already shared a password: change it, enable 2-step verification, and log out other devices.",
                 "If you already paid: contact your bank/payment provider immediately and file a report with local cybercrime authorities."]
    if recs:
        print("\n[ Recommendations ]")
        for r in dict.fromkeys(recs):
            print("  • " + r)
    print()


def print_profile_result(score, findings, username, color=True):
    lvl = level_for(score)
    c = {"LOW": "92", "MODERATE": "93", "HIGH": "91", "CRITICAL": "95;1"}[lvl[1]]
    print("\n" + "=" * 70)
    print(f" PROFILE    : @{(username or 'unknown').lstrip('@')}")
    print(f" RISK SCORE : {score}/100   LEVEL: " + colorize(lvl[1], c, color))
    print(f" VERDICT    : {lvl[2]}")
    print("=" * 70)
    for f in findings:
        print(f"  [+{f['points']:>2}] {f['category']}: {f['description']}")
        if f["evidence"]:
            print("        " + " | ".join(map(str, f["evidence"])))
    print()


def save_report(path, results):
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"tool": TITLE, "author": CREDIT, "version": VERSION,
                       "generated": datetime.now().isoformat(timespec="seconds"), "results": results},
                      fh, indent=2, ensure_ascii=False)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"{TITLE} v{VERSION} - {CREDIT}\nGenerated: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")
            for i, r in enumerate(results, 1):
                fh.write(f"#{i}  score={r.get('score')}  risk={r.get('risk', level_for(r.get('score', 0))[1])}\n")
                fh.write(f"    input: {str(r.get('input', r.get('username', '')))[:200]}\n")
                for f in r.get("text_findings", r.get("findings", [])):
                    fh.write(f"      [+{f['points']}] {f['category']}\n")
                for u in r.get("urls", []):
                    fh.write(f"      URL {u['url']} -> {u['score']}\n")
                fh.write("\n")
    print(f"[+] Report saved to {path}")


# ----------------------------------------------------------------------
# Interactive / CLI
# ----------------------------------------------------------------------
def read_multiline(prompt):
    print(prompt + " (finish with an empty line)")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            break
        lines.append(line)
    return "\n".join(lines)


def ask_int(prompt):
    v = input(prompt).strip()
    return int(v) if v.isdigit() else None


def profile_flow():
    username = input("TikTok username (e.g. @name): ").strip()
    bio = input("Bio text (optional): ").strip()
    link = input("Link in bio (optional): ").strip()
    followers = ask_int("Followers (blank=unknown): ")
    following = ask_int("Following (blank=unknown): ")
    videos = ask_int("Number of videos (blank=unknown): ")
    age = ask_int("Account age in days (blank=unknown): ")
    claim = input("Does it claim to be verified/official? (y/N): ").strip().lower() == "y"
    score, f = analyze_profile(username, bio, followers, following, videos, age, link, claim)
    print_profile_result(score, f, username)
    return {"username": username, "score": score, "risk": level_for(score)[1], "findings": f}


def show_banner():
    print(BANNER)
    print(f"        {TITLE}  v{VERSION}")
    print(f"        {CREDIT}")
    print("        For defensive use: analyze content you receive. Offline & stdlib-only.\n")


def interactive():
    show_banner()
    results = []
    while True:
        print("  [1] Analyze message / comment / caption text")
        print("  [2] Analyze link(s)")
        print("  [3] Analyze account profile details")
        print("  [4] Batch analyze a file (one item per line)")
        print("  [5] Save session report")
        print("  [0] Exit")
        ch = input("\nSelect > ").strip()
        if ch == "1":
            t = read_multiline("Paste the text")
            if t:
                r = analyze_item(t); results.append(r); print_result(r)
        elif ch == "2":
            t = read_multiline("Paste link(s), one per line")
            if t:
                r = analyze_item(t); results.append(r); print_result(r)
        elif ch == "3":
            results.append(profile_flow())
        elif ch == "4":
            batch(input("File path: ").strip(), results)
        elif ch == "5":
            if results:
                save_report(input("Output file (.json/.txt): ").strip() or "tiktok_scam_report.json", results)
            else:
                print("[!] Nothing to save yet.")
        elif ch == "0":
            if results and input("Save a report before exit? (y/N): ").strip().lower() == "y":
                save_report(input("Output file (.json/.txt): ").strip() or "tiktok_scam_report.json", results)
            print(f"\n{CREDIT} - stay safe.")
            break


def batch(path, results):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = [l.strip() for l in fh if l.strip()]
    except OSError as e:
        print(f"[!] Cannot read file: {e}")
        return
    print(f"[*] Analyzing {len(lines)} item(s)...")
    for i, line in enumerate(lines, 1):
        r = analyze_item(line)
        results.append(r)
        print(f"  #{i:<4} {r['score']:>3}/100  {r['risk']:<9} {line[:60]}")
    high = sum(1 for r in results if r["risk"] in ("HIGH", "CRITICAL"))
    print(f"[*] Done. High/critical items: {high}")


def main():
    ap = argparse.ArgumentParser(description=f"{TITLE} - {CREDIT}")
    ap.add_argument("-t", "--text", help="text to analyze")
    ap.add_argument("-u", "--url", nargs="+", help="one or more URLs to analyze")
    ap.add_argument("-f", "--file", help="file with one item per line")
    ap.add_argument("--profile", action="store_true", help="prompted profile analysis")
    ap.add_argument("-o", "--output", help="save report (.json or .txt)")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    if not any([args.text, args.url, args.file, args.profile]):
        interactive()
        return
    if not args.no_banner:
        show_banner()
    results = []
    if args.text:
        r = analyze_item(args.text); results.append(r); print_result(r)
    if args.url:
        r = analyze_item("\n".join(args.url)); results.append(r); print_result(r)
    if args.file:
        batch(args.file, results)
    if args.profile:
        results.append(profile_flow())
    if args.output and results:
        save_report(args.output, results)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted. {CREDIT}")
