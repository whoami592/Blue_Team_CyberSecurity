#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pakistan Phone Metadata Checker
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Offline, stdlib-only tool that parses and validates Pakistani phone numbers
and extracts the metadata that can be derived from the numbering plan itself:
number type, operator range, landline area, formats and pattern analysis.

NOTE: This tool does NOT identify the subscriber/owner of a number.
Operator results are based on the original prefix allocation. Because of
Mobile Number Portability (MNP) the current operator may be different.

Usage:
    python3 pk_phone_metadata.py 03001234567
    python3 pk_phone_metadata.py "+92 321 1234567" 0425551234
    python3 pk_phone_metadata.py -f numbers.txt --csv report.csv
    python3 pk_phone_metadata.py -i                # interactive mode
    python3 pk_phone_metadata.py 03451234567 --json
"""

import argparse
import csv
import json
import re
import sys

CREDIT = "Coded by Mr Sabaz Ali Khan | Cyber Security Engineer"
TOOL_NAME = "PAKISTAN PHONE METADATA CHECKER"
VERSION = "1.0"

BANNER = r"""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡤⠶⠒⠒⠒⠒⠶⢤⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠶⠛⠉⠀⠀⠀⠈⠉⠉⠽⠿⣲⣶⢬⣉⣛⣓⣶⠦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠖⠋⠀⠀⠀⣀⡴⠂⠀⠀⠀⠀⠀⠀⠈⠉⠙⣿⣞⡋⠉⠁⠀⠙⢷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⠿⠁⠀⢀⡶⣷⡿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣦⡉⠛⠶⢄⠀⠀⠹⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⢞⡿⠃⠀⠀⠠⠴⠋⠁⠀⠀⠀⢠⣤⣴⣾⣿⣧⣤⣖⣒⠀⠈⣿⣻⢷⣤⣼⡆⠀⠀⢸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢠⣞⣧⠞⠁⠀⠀⠀⠀⠀⣀⡀⢀⣴⣾⣽⣿⣾⣿⣿⣿⣿⣿⣭⣄⡀⠙⣿⡳⣯⣷⡇⠀⠀⣸⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣰⠏⡾⠃⠀⠀⣠⣴⣶⡿⢋⣽⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⠿⣦⣤⣈⣽⣶⣎⣠⣶⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⢰⡟⡼⠁⠀⣠⣾⣿⠿⣯⢾⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⢿⡍⠛⠛⠻⣷⣯⡭⣿⣛⡻⢿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀
⢸⠇⠇⠀⣴⣿⡿⣣⣾⡁⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠘⣿⣿⡇⢈⣿⣿⣷⠿⡄⠀⠀⠀⠀⠀⠀⠀⠀
⣟⠀⢀⣨⠿⢋⣼⣿⣿⣧⢿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⡇⣾⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠹⣦⣀⣤⡴⠋⣿⢸⣿⡇⣸⣿⡿⠓⠂⠀⢶⣦⣀⠀⠀⠀⠀⠀⣠⣴⠶⠀⠐⠻⣿⣿⣇⢻⣿⡏⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢻⣼⡿⢀⣙⣀⡦⣤⣤⣀⠀⠈⠻⣿⣶⣶⣶⣿⠟⠁⠀⣀⣤⣶⢶⣄⣉⠀⢿⣧⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⡿⠁⣹⣰⣿⣿⣿⣷⣿⣿⣦⣤⢼⡿⠿⣿⣧⣤⣴⣿⣿⣾⣿⣿⣿⡤⣍⠘⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢹⣄⠁⢿⡟⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⢻⡟⠀⣰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣸⣿⡆⠈⢷⣿⣿⣿⣿⣿⣿⠟⢹⣀⣀⣐⣟⣻⣿⣿⣿⣿⣿⣧⡾⠀⣰⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣾⡿⡿⣃⠀⣉⡛⠛⠻⢿⡿⣞⣵⡞⣻⣿⣜⣿⣮⡻⢿⡭⡟⢛⣛⣁⠀⣉⣿⣿⡷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⢷⣷⢭⣭⣈⣥⡶⠖⠀⠈⠛⣽⢻⣿⣿⣿⡘⣏⠋⠃⠀⠺⢶⣄⣩⣭⡵⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢿⣿⣿⡛⠲⣔⡆⢸⡃⣾⣿⢹⣿⣧⢘⡂⢰⣠⠖⢿⣿⣿⡟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⡄⠙⠽⢾⣧⣹⡟⠈⠛⣋⣿⡷⠶⠃⢰⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠹⡿⣿⣤⣀⣬⣀⡈⢁⠀⡀⠀⣀⣀⢠⣴⣿⣿⠻⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣸⣏⣀⣿⣿⢿⣿⣿⣿⣿⣾⣷⣿⣿⣿⣿⡿⡟⣿⣾⣀⣹⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀
⠀⠀⠀⡾⠋⠓⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣽⣸⡈⡽⠉⣿⠙⡏⢩⣇⣧⡗⠉⠉⠉⠉⠈⠉⠓⠒⠒⠒⠒⠒⢒⣲⠖⠊⢹⠟⠋
⠀⠀⠀⣧⣶⣤⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣒⣿⣶⣿⠿⠿⢉⣙⣛⣛⣛⠻⠷⠶⠶⠶⠶⠾⠟⠋⣉⣠⠴⠋⠁⠀⠀
⠀⠀⠀⢹⣿⣿⠟⠛⠛⠛⠛⠛⢻⣿⠛⡿⢻⣟⣟⢻⣿⣟⠉⡍⣽⣽⡟⢿⠉⣹⡟⠓⠒⠒⠒⠒⠒⠚⠛⠉⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠻⣷⡀⠘⡈⠋⠛⢿⡟⠚⠛⠉⠈⠃⢠⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣆⠙⠰⠆⣴⠀⡴⢰⠀⠃⣰⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠧⣄⣠⣽⢤⣧⣄⣤⠾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣠⡀⢀⣀⣀⣀⣀⡀⠀⠀⣤⢠⣤⣤⣀⡄⣠⠠⣄⣀⣠⣤⣠⣠⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠂⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠓⠚⠛⠛⠛⠋⠋⠀⠀⠚⠒⠋⠚⠋⠋⠙⠓⠛⠛⠛⠋⠛⠛⠋⠀⠀⠀⠀⠀⠀"""

# --------------------------------------------------------------------------
# Numbering plan data (national significant numbers, without trunk '0')
# --------------------------------------------------------------------------

# Mobile ranges: (first 3 digits of national number, operator)
MOBILE_RANGES = [
    (300, 309, "Jazz (Mobilink)"),
    (310, 319, "Zong (CMPak)"),
    (320, 329, "Jazz (ex-Warid)"),
    (330, 339, "Ufone (PTML)"),
    (340, 349, "Telenor Pakistan"),
    (355, 355, "SCOM (Special Communications Organization - AJK/GB)"),
]

# Landline area codes (national form, without the leading 0)
AREA_CODES = {
    "21": "Karachi",
    "22": "Hyderabad",
    "41": "Faisalabad",
    "42": "Lahore",
    "51": "Islamabad / Rawalpindi",
    "52": "Sialkot",
    "53": "Gujrat",
    "55": "Gujranwala",
    "61": "Multan",
    "62": "Bahawalpur",
    "71": "Sukkur",
    "81": "Quetta",
    "91": "Peshawar",
    "937": "Mardan",
    "944": "Mingora (Swat)",
    "966": "Dera Ismail Khan",
    "992": "Abbottabad",
    "5811": "Muzaffarabad (AJK)",
    "5822": "Mirpur (AJK)",
}

# --------------------------------------------------------------------------
# Colors
# --------------------------------------------------------------------------


class C:
    ON = sys.stdout.isatty()
    RED = "\033[91m" if ON else ""
    GREEN = "\033[92m" if ON else ""
    YELLOW = "\033[93m" if ON else ""
    CYAN = "\033[96m" if ON else ""
    BOLD = "\033[1m" if ON else ""
    DIM = "\033[2m" if ON else ""
    END = "\033[0m" if ON else ""


def show_banner():
    print(C.CYAN + BANNER + C.END)
    print(C.BOLD + C.GREEN + "  " + TOOL_NAME + "  v" + VERSION + C.END)
    print(C.YELLOW + "  " + CREDIT + C.END)
    print(C.DIM + "  Offline numbering-plan analysis only. No subscriber lookup." + C.END)
    print()


# --------------------------------------------------------------------------
# Core logic
# --------------------------------------------------------------------------


def normalize(raw):
    """Return (national_digits, notes). national digits have no trunk 0 / country code."""
    notes = []
    s = raw.strip()
    had_plus = s.startswith("+")
    digits = re.sub(r"\D", "", s)

    if not digits:
        return "", ["No digits found in input"]

    if had_plus or digits.startswith("00"):
        if digits.startswith("00"):
            digits = digits[2:]
        if digits.startswith("92"):
            notes.append("Country code +92 detected")
            return digits[2:], notes
        notes.append("Non-Pakistan country code or malformed international prefix")
        return digits, notes

    if digits.startswith("92") and len(digits) >= 11:
        notes.append("Country code 92 detected (without +)")
        return digits[2:], notes

    if digits.startswith("0"):
        notes.append("Domestic format with trunk prefix 0")
        return digits[1:], notes

    notes.append("No trunk prefix or country code supplied")
    return digits, notes


def mobile_operator(prefix3):
    p = int(prefix3)
    for lo, hi, name in MOBILE_RANGES:
        if lo <= p <= hi:
            return name
    return None


def match_area(national):
    for length in (4, 3, 2):
        code = national[:length]
        if code in AREA_CODES:
            return code, AREA_CODES[code]
    return None, None


def pattern_analysis(subscriber):
    """Simple pattern / 'vanity' checks on the subscriber digits."""
    flags = []
    d = subscriber
    if len(set(d)) == 1:
        flags.append("All digits identical")
    if len(set(d)) <= 3 and len(d) >= 6:
        flags.append("Very few unique digits (" + str(len(set(d))) + ")")
    diffs = [int(d[i + 1]) - int(d[i]) for i in range(len(d) - 1)]
    if diffs and all(x == 1 for x in diffs):
        flags.append("Fully ascending sequence")
    if diffs and all(x == -1 for x in diffs):
        flags.append("Fully descending sequence")
    if d == d[::-1] and len(d) > 3:
        flags.append("Palindrome")
    if len(d) >= 6 and d[: len(d) // 2] == d[len(d) // 2: len(d) // 2 * 2]:
        flags.append("Repeating half pattern")
    if d.endswith("786"):
        flags.append("Ends with 786 (popular 'lucky' ending)")
    if re.search(r"(\d)\1{3,}", d):
        flags.append("Run of 4+ identical digits")
    if d.endswith("000") or d.endswith("999") or d.endswith("111"):
        flags.append("Round / premium-style ending")
    return flags


def analyze(raw):
    national, notes = normalize(raw)
    result = {
        "input": raw,
        "valid": False,
        "type": None,
        "operator": None,
        "area": None,
        "area_code": None,
        "country": "Pakistan",
        "country_code": "+92",
        "national_number": national,
        "e164": None,
        "international": None,
        "national_format": None,
        "tel_uri": None,
        "pattern_flags": [],
        "notes": notes,
        "errors": [],
    }

    if not national or not national.isdigit():
        result["errors"].append("Input contains no usable digits")
        return result

    # --- Mobile ---
    if national.startswith("3"):
        if len(national) != 10:
            result["errors"].append(
                "Mobile numbers need 10 digits after the trunk 0 (got %d)" % len(national)
            )
            result["type"] = "Mobile (malformed)"
            return result
        op = mobile_operator(national[:3])
        result["type"] = "Mobile"
        result["operator"] = op or "Unallocated / unknown prefix"
        if not op:
            result["errors"].append("Prefix 0%s is not in the known mobile ranges" % national[:3])
            return result
        result["valid"] = True
        result["e164"] = "+92" + national
        result["international"] = "+92 %s %s" % (national[:3], national[3:])
        result["national_format"] = "0%s-%s" % (national[:3], national[3:])
        result["tel_uri"] = "tel:+92" + national
        result["pattern_flags"] = pattern_analysis(national[3:])
        result["notes"].append(
            "Operator reflects original prefix allocation; MNP may have moved the number."
        )
        return result

    # --- Toll free ---
    if national.startswith("800"):
        result["type"] = "Toll-free (0800)"
        if len(national) == 8:
            result["valid"] = True
            result["e164"] = "+92" + national
            result["international"] = "+92 %s %s" % (national[:3], national[3:])
            result["national_format"] = "0%s-%s" % (national[:3], national[3:])
            result["tel_uri"] = "tel:+92" + national
        else:
            result["errors"].append("Toll-free numbers are normally 0800 + 5 digits")
        return result

    # --- UAN ---
    if national.startswith("111"):
        result["type"] = "UAN (Universal Access Number, 111)"
        if len(national) == 9:
            result["valid"] = True
            result["e164"] = "+92" + national
            result["international"] = "+92 %s %s %s" % (national[:3], national[3:6], national[6:])
            result["national_format"] = "%s-%s-%s" % (national[:3], national[3:6], national[6:])
            result["tel_uri"] = "tel:+92" + national
            result["notes"].append("UAN numbers are shared business lines, not tied to one city.")
        else:
            result["errors"].append("UAN numbers are normally 111-XXX-XXX (9 digits)")
        return result

    # --- Landline ---
    code, area = match_area(national)
    if code:
        sub = national[len(code):]
        result["type"] = "Landline (PTCL / fixed line)"
        result["area_code"] = "0" + code
        result["area"] = area
        if 9 <= len(national) <= 10 and 5 <= len(sub) <= 8:
            result["valid"] = True
            result["e164"] = "+92" + national
            result["international"] = "+92 %s %s" % (code, sub)
            result["national_format"] = "0%s-%s" % (code, sub)
            result["tel_uri"] = "tel:+92" + national
            result["pattern_flags"] = pattern_analysis(sub)
        else:
            result["errors"].append(
                "Unexpected length for area 0%s (subscriber part is %d digits)" % (code, len(sub))
            )
        return result

    result["type"] = "Unknown"
    result["errors"].append(
        "Does not match Pakistani mobile ranges, 0800, 111 or known landline area codes"
    )
    return result


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def print_result(r):
    status = (C.GREEN + "VALID" + C.END) if r["valid"] else (C.RED + "INVALID" + C.END)
    print(C.BOLD + "-" * 62 + C.END)
    print("%s %s   [%s]" % (C.BOLD + "Input:" + C.END, r["input"], status))
    print(C.BOLD + "-" * 62 + C.END)

    def row(label, value):
        if value:
            print("  %-16s %s" % (label, value))

    row("Type", r["type"])
    row("Operator", r["operator"])
    row("Area", ("%s (%s)" % (r["area"], r["area_code"])) if r["area"] else None)
    row("Country", "%s (%s)" % (r["country"], r["country_code"]))
    row("E.164", r["e164"])
    row("International", r["international"])
    row("National", r["national_format"])
    row("Tel URI", r["tel_uri"])
    if r["pattern_flags"]:
        row("Pattern", "; ".join(r["pattern_flags"]))
    for n in r["notes"]:
        print("  " + C.DIM + "note: " + n + C.END)
    for e in r["errors"]:
        print("  " + C.RED + "error: " + e + C.END)
    print()


def write_csv(path, results):
    fields = [
        "input", "valid", "type", "operator", "area", "area_code", "e164",
        "international", "national_format", "pattern_flags", "errors",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = {k: r.get(k) for k in fields}
            row["pattern_flags"] = "; ".join(r["pattern_flags"])
            row["errors"] = "; ".join(r["errors"])
            w.writerow(row)


def print_summary(results):
    total = len(results)
    valid = sum(1 for r in results if r["valid"])
    ops = {}
    for r in results:
        if r["valid"] and r["operator"]:
            ops[r["operator"]] = ops.get(r["operator"], 0) + 1
    print(C.BOLD + "=" * 62 + C.END)
    print("  Total: %d   Valid: %d   Invalid: %d" % (total, valid, total - valid))
    for name, count in sorted(ops.items(), key=lambda x: -x[1]):
        print("    %-45s %d" % (name, count))
    print(C.BOLD + "=" * 62 + C.END)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def interactive():
    print("Interactive mode. Enter a number (or 'q' to quit).\n")
    while True:
        try:
            raw = input(C.CYAN + "number> " + C.END).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if raw.lower() in ("q", "quit", "exit"):
            break
        if raw:
            print_result(analyze(raw))


def main():
    ap = argparse.ArgumentParser(
        description="Pakistan Phone Metadata Checker - coded by Mr Sabaz Ali Khan"
    )
    ap.add_argument("numbers", nargs="*", help="Phone number(s) to analyze")
    ap.add_argument("-f", "--file", help="Text file with one number per line")
    ap.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    ap.add_argument("--csv", metavar="OUT.csv", help="Write results to CSV")
    ap.add_argument("--no-banner", action="store_true", help="Hide the banner")
    args = ap.parse_args()

    if not args.no_banner and not args.json:
        show_banner()

    inputs = list(args.numbers)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                inputs += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            print(C.RED + "Cannot read file: %s" % exc + C.END)
            sys.exit(1)

    if args.interactive or not inputs:
        interactive()
        return

    results = [analyze(n) for n in inputs]

    if args.json:
        print(json.dumps({"tool": TOOL_NAME, "credit": CREDIT, "results": results},
                         indent=2, ensure_ascii=False))
    else:
        for r in results:
            print_result(r)
        if len(results) > 1:
            print_summary(results)

    if args.csv:
        write_csv(args.csv, results)
        if not args.json:
            print("CSV report saved to %s" % args.csv)


if __name__ == "__main__":
    main()
