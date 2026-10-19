#!/usr/bin/env python3
"""
Scam Number Report Manager
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

A local, stdlib-only tool to record, search, verify and export reports
about scam / fraud phone numbers. Data is stored in a SQLite database.

Usage:
    python3 scam_report_manager.py            # interactive menu
    python3 scam_report_manager.py check +923001234567
    python3 scam_report_manager.py stats
"""

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
from datetime import datetime

BANNER = """
⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣤⢾⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡔⠋⣀⣼⡏⣼⣏⣹⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣶⣿⣿⣿⣡⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡤⢾⣿⣿⣿⣿⣟⠋⣉⣉⠙⢻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠴⠚⠁⣀⣴⣿⣿⣿⠿⢿⣿⠿⣿⣿⠟⢸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⣤⣤⠜⠚⠛⣇⣀⣠⣴⣿⠿⠋⠹⣿⣤⣾⣿⡦⣽⠇⠀⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣤⣶⣿⠋⠀⢸⣿⣿⣿⣾⡟⠋⠉⠁⠀⠀⠀⢹⣿⣿⠛⠛⠂⢀⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⣴⡟⢹⣿⠇⠀⣠⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣶⣿⣴⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣾⠋⠠⡿⠋⣠⣾⣿⣿⣿⣿⣡⣤⣤⣄⡤⣊⣭⣿⣿⣿⣮⣍⣿⡿⠛⠉⢀⣸⣧⠤⣄⣀⠀⠀⠀⠀⠀⠀⠀
⢻⣷⡆⠀⠀⣈⠁⠀⠴⠿⠿⠿⠿⣿⢿⣿⣿⣿⡿⠛⠛⠛⢿⣿⣿⣷⠴⣾⣿⣿⣿⣷⣦⡄⠑⢤⡀⠀⠀⠀⠀
⠈⠻⣿⣿⣿⣿⣿⣗⣀⣠⣤⣤⡀⠀⢀⣿⣿⣯⣀⣠⡆⠀⠈⢿⠋⠀⠾⠿⠿⠿⣿⣿⣿⣿⣶⣾⡿⠳⡀⠀⠀
⠀⠀⠈⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣶⣤⣼⠀⢰⠀⠀⠀⠉⢁⡀⠀⠘⣿⡿⣁⠴⢳⣄⠀
⠀⠀⠀⠀⠀⠀⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿⡦⢬⡛⠿⠿⣿⣿⣿⡄⢾⣶⣶⣾⣯⣿⡆⠀⠀⡉⠁⠹⣷⣿⢿⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣿⣿⣿⡇⢸⣷⣄⣐⣠⣼⣿⠃⣰⣿⣿⣿⣿⣿⣷⡀⢠⣇⠀⢰⣿⣿⣌⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣧⣾⣿⣿⣿⣿⣿⡿⡄⢻⣿⣿⣿⡉⢻⣿⣷⣸⣿⢠⡟⠀⠙⢿⡄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⡿⢀⣷⢸⣿⣿⣿⣷⣾⣿⣿⣿⣿⡿⠀⣤⠀⠘⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⠟⣠⣾⣇⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⣾⣿⠀⠀⣇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣏⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⡴⢀⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠏⠙⠖⠒⠛⠿⢿⣿⣿⣿⣿⣟⡛⠛⠿⠿⣿⣿⣿⣿⣿⡿⣡⣿⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣷⣶⣤⣤⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⠟⢿⣿⣿⣿⠟⢻⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣴⣼⣿⣿⣿⠀⣋⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⣀⢀⡀⢀⢀⣀⣀⠀⠀⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠞⠛⠻⠛⠛⠛⠟⠻⠛⠐⠛⠛⠛⠃⠀⠀⠈⠋⠋⠛⠚⠀⠙⠉⠜⠓⠏⠀⠀⠀⠀
"""

TITLE = "SCAM NUMBER REPORT MANAGER"
CREDIT = "coded by Mr Sabaz Ali Khan  |  Cyber Security Engineer"

DB_PATH = os.environ.get(
    "SCAM_DB", os.path.join(os.path.expanduser("~"), ".scam_report_manager.db")
)

CATEGORIES = [
    "Phishing / Smishing",
    "Fake Prize / Lottery",
    "Bank / Card Fraud",
    "Investment / Crypto Scam",
    "Tech Support Scam",
    "Impersonation (Govt / Police / Courier)",
    "Job / Loan Scam",
    "Romance / Blackmail",
    "Robocall / Spam",
    "Other",
]
STATUSES = ["pending", "verified", "dismissed"]


def show_banner():
    print(BANNER)
    print(f"  {TITLE}")
    print(f"  {CREDIT}")
    print("  " + "=" * 58)


# ----------------------------------------------------------------- database
def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT NOT NULL,
            category TEXT NOT NULL,
            severity INTEGER NOT NULL DEFAULT 3,
            description TEXT,
            reporter TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_number ON reports(number)")
    conn.commit()
    return conn


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_number(raw):
    """Strip formatting; keep a leading + and digits. Returns None if invalid."""
    raw = (raw or "").strip()
    plus = raw.startswith("+")
    digits = re.sub(r"\D", "", raw)
    if not 6 <= len(digits) <= 15:
        return None
    return ("+" if plus else "") + digits


def risk_score(conn, number):
    rows = conn.execute(
        "SELECT severity, status FROM reports WHERE number=? AND status!='dismissed'",
        (number,),
    ).fetchall()
    if not rows:
        return 0, "NO REPORTS"
    score = 0
    for r in rows:
        score += r["severity"] * (3 if r["status"] == "verified" else 1)
    score = min(100, score * 4)
    label = (
        "CRITICAL" if score >= 75 else
        "HIGH" if score >= 50 else
        "MEDIUM" if score >= 25 else
        "LOW"
    )
    return score, label


# ------------------------------------------------------------------ helpers
def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"  {prompt}{suffix}: ").strip()
    return val if val else (default if default is not None else "")


def pick(title, options):
    print(f"\n  {title}")
    for i, o in enumerate(options, 1):
        print(f"    {i}. {o}")
    while True:
        c = input("  Choose: ").strip()
        if c.isdigit() and 1 <= int(c) <= len(options):
            return options[int(c) - 1]
        print("  Invalid choice.")


def print_rows(rows):
    if not rows:
        print("\n  No records found.")
        return
    print(f"\n  {'ID':<5}{'NUMBER':<18}{'CATEGORY':<30}{'SEV':<5}{'STATUS':<10}DATE")
    print("  " + "-" * 82)
    for r in rows:
        print(
            f"  {r['id']:<5}{r['number']:<18}{r['category'][:28]:<30}"
            f"{r['severity']:<5}{r['status']:<10}{r['created_at'][:10]}"
        )
    print(f"\n  {len(rows)} record(s).")


def print_detail(r):
    print("\n  " + "-" * 58)
    for k in ("id", "number", "category", "severity", "status",
              "reporter", "created_at", "updated_at"):
        print(f"  {k.replace('_', ' ').title():<12}: {r[k]}")
    print(f"  {'Description':<12}: {r['description'] or '-'}")
    print("  " + "-" * 58)


# ------------------------------------------------------------------ actions
def add_report(conn):
    number = normalize_number(ask("Scam number (e.g. +923001234567)"))
    if not number:
        print("  Invalid number (need 6-15 digits).")
        return
    category = pick("Category:", CATEGORIES)
    sev = ask("Severity 1 (nuisance) - 5 (severe loss/threat)", "3")
    severity = int(sev) if sev.isdigit() and 1 <= int(sev) <= 5 else 3
    description = ask("What happened (script used, amount asked, etc.)")
    reporter = ask("Reporter name / ID (optional, Enter to skip)", "anonymous")
    ts = now()
    conn.execute(
        "INSERT INTO reports(number,category,severity,description,reporter,"
        "status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        (number, category, severity, description, reporter, "pending", ts, ts),
    )
    conn.commit()
    count = conn.execute(
        "SELECT COUNT(*) FROM reports WHERE number=?", (number,)
    ).fetchone()[0]
    print(f"\n  Report saved. {number} now has {count} report(s).")


def list_reports(conn, status=None):
    if status:
        rows = conn.execute(
            "SELECT * FROM reports WHERE status=? ORDER BY id DESC", (status,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()
    print_rows(rows)


def search_reports(conn):
    term = ask("Search (number fragment, category or keyword)")
    like = f"%{term}%"
    rows = conn.execute(
        "SELECT * FROM reports WHERE number LIKE ? OR category LIKE ? "
        "OR description LIKE ? OR reporter LIKE ? ORDER BY id DESC",
        (like, like, like, like),
    ).fetchall()
    print_rows(rows)


def check_number(conn, raw=None):
    number = normalize_number(raw or ask("Number to check"))
    if not number:
        print("  Invalid number.")
        return
    rows = conn.execute(
        "SELECT * FROM reports WHERE number=? ORDER BY id DESC", (number,)
    ).fetchall()
    score, label = risk_score(conn, number)
    print(f"\n  Number     : {number}")
    print(f"  Reports    : {len(rows)}")
    print(f"  Risk score : {score}/100  [{label}]")
    if rows:
        cats = {}
        for r in rows:
            cats[r["category"]] = cats.get(r["category"], 0) + 1
        print("  Categories : " + ", ".join(f"{c} x{n}" for c, n in cats.items()))
        print_rows(rows)
    else:
        print("  No reports on file. (Not being listed does not mean it is safe.)")


def view_report(conn):
    rid = ask("Report ID")
    r = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
    print_detail(r) if r else print("  Not found.")


def set_status(conn):
    rid = ask("Report ID")
    r = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
    if not r:
        print("  Not found.")
        return
    print_detail(r)
    status = pick("New status:", STATUSES)
    conn.execute(
        "UPDATE reports SET status=?, updated_at=? WHERE id=?", (status, now(), rid)
    )
    conn.commit()
    print("  Status updated.")


def edit_report(conn):
    rid = ask("Report ID")
    r = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
    if not r:
        print("  Not found.")
        return
    print_detail(r)
    print("  Press Enter to keep the current value.")
    category = r["category"]
    if ask("Change category? (y/n)", "n").lower() == "y":
        category = pick("Category:", CATEGORIES)
    sev = ask("Severity 1-5", str(r["severity"]))
    severity = int(sev) if sev.isdigit() and 1 <= int(sev) <= 5 else r["severity"]
    desc = ask("Description", r["description"] or "")
    conn.execute(
        "UPDATE reports SET category=?, severity=?, description=?, updated_at=? "
        "WHERE id=?",
        (category, severity, desc, now(), rid),
    )
    conn.commit()
    print("  Report updated.")


def delete_report(conn):
    rid = ask("Report ID to delete")
    r = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
    if not r:
        print("  Not found.")
        return
    print_detail(r)
    if ask("Delete permanently? (yes/no)", "no").lower() == "yes":
        conn.execute("DELETE FROM reports WHERE id=?", (rid,))
        conn.commit()
        print("  Deleted.")
    else:
        print("  Cancelled.")


def top_numbers(conn, limit=10):
    rows = conn.execute(
        "SELECT number, COUNT(*) c FROM reports WHERE status!='dismissed' "
        "GROUP BY number ORDER BY c DESC LIMIT ?", (limit,),
    ).fetchall()
    return rows


def stats(conn):
    total = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    uniq = conn.execute("SELECT COUNT(DISTINCT number) FROM reports").fetchone()[0]
    print(f"\n  Total reports  : {total}")
    print(f"  Unique numbers : {uniq}")
    print("\n  By status:")
    for s in STATUSES:
        n = conn.execute("SELECT COUNT(*) FROM reports WHERE status=?", (s,)).fetchone()[0]
        print(f"    {s:<10} {n}")
    print("\n  By category:")
    for r in conn.execute(
        "SELECT category, COUNT(*) c FROM reports GROUP BY category ORDER BY c DESC"
    ):
        print(f"    {r['category']:<42} {r['c']}")
    print("\n  Most reported numbers:")
    for r in top_numbers(conn):
        score, label = risk_score(conn, r["number"])
        print(f"    {r['number']:<18} {r['c']:>3} report(s)  risk {score:>3} [{label}]")


def export_data(conn):
    fmt = pick("Export format:", ["csv", "json"])
    path = ask("Output file", f"scam_reports_{datetime.now():%Y%m%d_%H%M%S}.{fmt}")
    rows = [dict(r) for r in conn.execute("SELECT * FROM reports ORDER BY id")]
    if fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["id"])
            w.writeheader()
            w.writerows(rows)
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
    print(f"  Exported {len(rows)} record(s) to {path}")


def import_csv(conn):
    path = ask("CSV file path (columns: number,category,severity,description,reporter)")
    if not os.path.isfile(path):
        print("  File not found.")
        return
    added = skipped = 0
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            number = normalize_number(row.get("number"))
            if not number:
                skipped += 1
                continue
            sev = str(row.get("severity", "3"))
            severity = int(sev) if sev.isdigit() and 1 <= int(sev) <= 5 else 3
            ts = now()
            conn.execute(
                "INSERT INTO reports(number,category,severity,description,reporter,"
                "status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (number, row.get("category") or "Other", severity,
                 row.get("description", ""), row.get("reporter") or "import",
                 "pending", ts, ts),
            )
            added += 1
    conn.commit()
    print(f"  Imported {added} record(s), skipped {skipped} invalid row(s).")


# --------------------------------------------------------------------- main
MENU = """
  [1] Add scam report            [6] Update report status
  [2] List all reports           [7] Edit report
  [3] Search reports             [8] Delete report
  [4] Check a number (risk)      [9] Statistics
  [5] View report details        [10] Export (CSV/JSON)
  [11] Import from CSV           [12] List pending reports
  [0] Exit
"""


def interactive(conn):
    show_banner()
    actions = {
        "1": add_report, "2": list_reports, "3": search_reports,
        "4": check_number, "5": view_report, "6": set_status,
        "7": edit_report, "8": delete_report, "9": stats,
        "10": export_data, "11": import_csv,
        "12": lambda c: list_reports(c, "pending"),
    }
    while True:
        print(MENU)
        choice = input("  Select option: ").strip()
        if choice == "0":
            print(f"\n  Stay safe. {CREDIT}\n")
            break
        action = actions.get(choice)
        if not action:
            print("  Invalid option.")
            continue
        try:
            action(conn)
        except (KeyboardInterrupt, EOFError):
            print("\n  Cancelled.")
        except sqlite3.Error as e:
            print(f"  Database error: {e}")


def main():
    parser = argparse.ArgumentParser(description=TITLE + " - " + CREDIT)
    sub = parser.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="check a number's reports and risk score")
    c.add_argument("number")
    sub.add_parser("stats", help="show statistics")
    sub.add_parser("list", help="list all reports")
    args = parser.parse_args()

    conn = connect()
    if args.cmd == "check":
        show_banner()
        check_number(conn, args.number)
    elif args.cmd == "stats":
        show_banner()
        stats(conn)
    elif args.cmd == "list":
        show_banner()
        list_reports(conn)
    else:
        interactive(conn)
    conn.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Interrupted.")
        sys.exit(0)
