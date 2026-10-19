#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phone Number Intelligence Analyzer
Coded by Mr Sabaz Ali Khan  |  Cyber Security Engineer

Offline analysis of phone numbers: validity, formats, country/region,
carrier (original allocation), timezones, line type and a heuristic
risk score. Uses only Google's libphonenumber metadata (no network calls).

Install : pip install phonenumbers
Usage   : python3 phone_intel_analyzer.py +923001234567
          python3 phone_intel_analyzer.py 03001234567 -r PK
          python3 phone_intel_analyzer.py -f numbers.txt --json out.json --csv out.csv

Use only on numbers you are authorized to analyze.
"""

import argparse
import csv
import json
import re
import sys
from datetime import datetime

try:
    import phonenumbers
    from phonenumbers import (
        NumberParseException,
        PhoneNumberFormat,
        PhoneNumberType,
        carrier,
        geocoder,
        timezone,
    )
except ImportError:
    print("[!] Missing dependency. Install it with: pip install phonenumbers")
    sys.exit(1)

BANNER = r"""
⠀⠀⠀⠀⠀⠀⢠⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡴⠞⠛⠛⠒⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣤⣤⡤⠶⠚⠁⠀⠀⠀⠀⠀⠀⠉⠙⠉⠓⠲⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢠⣿⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠴⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢈⣿⣧⢹⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣴⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣼⡿⢱⣿⣿⡟⣿⠀⠀⠀⠀⠀⠀⠀⣾⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣧⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢰⣿⢃⣿⣿⣿⣱⡿⠀⠀⠀⠀⠀⠀⢠⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⡀⠀⠀⠀⠀⠀⠀
⠀⠀⢸⣿⡾⣽⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⣾⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⠀⠀⠀⠀⠀⠀
⠀⠀⣿⣿⣿⣿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⣿⡀⠀⠀⠀⠀⠀⠀⢀⡤⠖⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡇⠀⠀⠀⠀⠀
⠀⢀⡿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡧⠀⠀⠀⠀⢀⡶⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⠀⠀⠀⠀⠀
⠀⡼⢀⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡼⠋⠀⠀⠀⠀⣴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀
⢠⠃⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠋⠀⡀⠀⠀⣀⠴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠀⠀⠀⠀⠀
⡸⠀⡏⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠁⠀⠀⠓⠖⠊⣁⠀⢀⣠⡄⠀⠀⠀⢀⣠⣤⣤⣤⣤⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠀⠀⠀⠀⠀
⡇⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⡾⠁⠀⣀⣤⣤⣤⣾⣿⣿⣟⢿⣷⡄⠀⢀⣾⣿⣿⢛⣭⣤⣤⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣧⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀
⡇⠀⡇⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠈⣟⣛⠿⣿⣿⣿⣿⣿⣦⢻⣷⡀⣾⣿⣿⢣⢋⣾⣿⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡄⠀⠀⢸⡃⠀⠀⠀⠀⠀
⢹⠀⠸⡀⠀⠀⠀⠀⠀⣠⣿⣠⣤⣾⣿⣿⣿⣮⡻⣿⣿⣿⣿⣿⣿⣷⢻⣿⢏⣷⣿⣿⣿⣿⡿⣫⣵⣿⣿⣿⣶⣤⣤⣤⣄⡀⠀⠀⠀⠘⣿⠀⠀⢸⠇⠀⠀⠀⠀⠀
⠀⢣⡀⠈⠒⠤⠤⠖⠊⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣮⡻⣿⣿⣿⣿⣿⣿⣿⣼⣿⢻⣿⣿⢏⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠹⡧⠀⣾⠀⠀⠀⠀⠀⠀
⠀⠀⠑⠦⣀⣀⣀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⢇⣮⢏⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⣿⣸⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⡿⣛⣯⣽⣛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣏⣾⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⢤⣠⣿⡟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣮⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣹⣿⣿⣿⣿⣿⣿⣿⣯⣷⣶⣶⣶⣿⣿⣿⣿⣿⠀⠙⢿⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⣿⣿⣿⣽⣿⣟⣿⣿⣿⣿⣿⣟⣿⣿⣿⣿⣿⣿⣿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠙⠦⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⢻⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⣠⣤⡄⠈⠿⠛⠛⢿⣿⣾⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⣀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠈⠳⣶⣦⣀⠀
⠀⠀⠀⠀⣾⢸⣿⣿⣿⣿⣿⣿⣿⣿⣷⠈⢹⢛⣷⠀⠀⠀⠀⠀⠁⠈⠻⣿⣏⣿⡏⣿⣿⣿⠭⠤⢄⠀⣾⠟⠑⢸⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠈⢻⣮⠁
⠀⠀⠀⠀⢻⣾⣿⣿⣿⣿⡿⢛⣥⣶⣿⡄⠈⠀⠀⠀⠊⠉⠉⠀⠠⠄⠀⠀⣹⠙⠃⠉⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⢿⣿⣿⣿⣿⣿⡇⠀⠀⠀⢠⡀⠀⠀⣿⡇
⠀⠀⠀⠀⠀⣿⣿⣿⣿⢟⣴⣿⣿⣿⣿⣿⣦⠀⠀⠄⣀⣀⡀⠀⠀⠀⠈⢳⠈⢦⠐⠀⠀⠀⠀⣠⡜⠀⠀⠻⣿⣿⣿⣿⣷⡙⣿⣿⣿⣿⡇⠀⠀⠀⢸⡷⠀⠀⣿⠇
⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠈⢿⣿⣷⣄⡀⠀⢀⣀⠘⣄⣀⣀⣴⣿⡿⠁⠀⠀⠀⠹⣿⣿⣿⣿⣿⡸⣿⣿⣿⠃⠀⠀⠀⢸⠇⠀⠀⣿⠀
⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⠃⠀⠀⠀⢣⣀⣉⠙⣿⣿⡏⠛⠋⠉⠩⢽⣿⣟⠋⢁⡜⠀⠀⠀⠀⣿⣿⣿⣿⣿⣧⣿⣿⣿⠀⠀⠀⠀⠈⠀⠀⣸⠏⠀
⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⢣⣾⠀⠀⠀⠀⠀⠈⠉⠀⢠⡏⠀⠀⠀⠀⠀⠀⠹⡍⠉⡉⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⣰⠃⠀⠀
⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⢣⣿⣿⣆⠀⠀⠀⠀⠀⠈⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⠸⣄⠀⠀⢀⣾⣷⣻⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⣼⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⡏⣿⣿⣿⣿⣷⣄⠀⠀⡌⠀⠀⠈⠄⣀⠀⠀⠀⠀⠀⣠⡾⠀⠀⠸⡄⣠⣿⣿⣿⡇⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⡼⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡇⣿⣿⣿⣿⣿⣿⣷⣤⣇⠀⠀⠀⣢⠭⠤⣀⣀⣀⡠⠽⠧⡀⠉⢠⣿⣯⡹⣷⣻⣿⢸⣿⣿⣿⡿⠁⠀⠀⠀⢀⡞⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡟⢿⣿⣿⡇⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⢳⠶⣶⣤⣤⣴⣶⠶⡶⠃⠀⢸⣿⣯⢻⣽⣿⣿⣼⣿⣿⠏⠀⠀⠀⠀⠀⡾⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢻⡿⣷⢹⣿⣿⣿⣿⢸⣿⣿⣧⡀⠀⠀⠀⠀⠙⢿⣿⡿⠟⠁⠀⠀⣀⣼⣝⢿⣧⣿⣿⣿⢿⡿⠃⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣧⡠⠚⠁⠙⣇⣻⣿⣿⣿⣼⣿⣿⣿⣿⣦⣀⣀⡀⢀⣀⣠⣦⣀⣠⠔⡊⢹⣿⣿⣧⣻⣿⢿⣿⠼⠁⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⠓⡄⠀⠀⠙⢿⣿⣿⣷⣋⣿⣿⣿⣿⣿⣿⡍⠫⣹⠿⠿⠿⠛⠙⠜⠀⣼⣿⣿⣿⣿⣿⠻⠀⠀⠀⡐⠀⠀⠀⠀⠀⢀⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢻⢸⠁⠀⠀⠀⠀⠹⢿⣿⣿⡜⣿⣏⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⣠⡿⣟⣿⣿⣿⠋⠀⠀⠀⡸⢡⠀⠀⠀⠀⢠⡞⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢻⣼⠀⠀⡀⠀⠀⠀⠀⠈⠉⠻⣿⣿⣿⣿⣿⣿⣷⣦⣄⣀⣤⣤⣴⣾⣿⣿⣼⣾⣿⡟⠀⠀⠀⢸⡃⠁⠀⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⠀⠀⢹⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣯⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠊⠀⠀⠀⠀⢰⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣆⠀⠸⣆⠀⠀⠀⠀⢀⣀⣸⣿⣿⣿⣿⣿⡼⡟⣿⣿⣽⣿⡇⣿⣿⣿⣿⠛⠃⠀⠀⡎⠀⠀⠀⠀⠀⢰⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣦⡀⠹⣧⠀⠀⣀⣀⣉⣙⣻⣿⣿⣿⣿⣷⣽⣿⡿⣿⣿⣷⢹⣿⣧⡇⢠⠴⠲⡄⡇⢀⠔⢆⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡷⡄⢹⡇⠀⠀⠀⠀⠈⣹⣿⣿⡿⠛⠛⠻⢿⣿⣮⣿⣿⣷⣝⢿⢧⣯⠀⢠⡇⣹⢾⠀⢸⠴⠖⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⣹⣿⣤⠖⠛⠻⢶⡿⠋⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣯⣿⡞⠀⠙⣆⣸⠛⠉⠀⠳⠾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠛⣡⡞⠁⠀⠀⠐⠉⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠈⡿⣿⣿⣆⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠀⢸⡟⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠇⠀⢀⡀⠀⠀⠀⠀⡇⠸⡇⠻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡿⠒⢪⣧⢀⣠⢄⠀⣇⠀⡠⡶⢦⠀⢸⡞⠈⠹⡄⠀⠀⢠⡇⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢀⣾⣾⡏⢃⢸⣇⠸⣶⠁⡇⣼⣄⣸⣧⡀⣼⣷⣦⡴⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣼⠉⠙⠻⡌⢸⣿⡤⠞⢇⡇⡏⠉⠉⠙⣷⠏⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢮⡇⠀⠀⠈⠓⠃⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

C = {
    "r": "\033[91m", "g": "\033[92m", "y": "\033[93m",
    "b": "\033[94m", "m": "\033[95m", "c": "\033[96m",
    "w": "\033[97m", "d": "\033[2m", "x": "\033[0m", "B": "\033[1m",
}

TYPE_NAMES = {
    PhoneNumberType.FIXED_LINE: "Fixed line",
    PhoneNumberType.MOBILE: "Mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile",
    PhoneNumberType.TOLL_FREE: "Toll free",
    PhoneNumberType.PREMIUM_RATE: "Premium rate",
    PhoneNumberType.SHARED_COST: "Shared cost",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "Personal number",
    PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "Universal access number",
    PhoneNumberType.VOICEMAIL: "Voicemail",
    PhoneNumberType.UNKNOWN: "Unknown",
}

# Points added to the heuristic risk score per line type
TYPE_RISK = {
    PhoneNumberType.VOIP: 25,
    PhoneNumberType.PREMIUM_RATE: 40,
    PhoneNumberType.SHARED_COST: 15,
    PhoneNumberType.UAN: 10,
    PhoneNumberType.PAGER: 10,
    PhoneNumberType.VOICEMAIL: 10,
    PhoneNumberType.PERSONAL_NUMBER: 10,
}


def show_banner(color=True):
    if color:
        print(C["c"] + BANNER + C["x"])
        print(C["B"] + C["g"] + "    ╔══════════════════════════════════════════════════╗" + C["x"])
        print(C["B"] + C["g"] + "    ║   PHONE NUMBER INTELLIGENCE ANALYZER  v1.0       ║" + C["x"])
        print(C["B"] + C["y"] + "    ║   Coded by Mr Sabaz Ali Khan                     ║" + C["x"])
        print(C["B"] + C["m"] + "    ║   Cyber Security Engineer                        ║" + C["x"])
        print(C["B"] + C["g"] + "    ╚══════════════════════════════════════════════════╝" + C["x"])
    else:
        print(BANNER)
        print("    PHONE NUMBER INTELLIGENCE ANALYZER v1.0")
        print("    Coded by Mr Sabaz Ali Khan | Cyber Security Engineer")
    print()


def digit_patterns(national_digits):
    """Detect repeated and sequential digit runs (common in fake/test numbers)."""
    flags = []
    if re.search(r"(\d)\1{5,}", national_digits):
        flags.append("6+ repeated identical digits")
    run_up = run_dn = 1
    best_up = best_dn = 1
    for a, b in zip(national_digits, national_digits[1:]):
        run_up = run_up + 1 if int(b) - int(a) == 1 else 1
        run_dn = run_dn + 1 if int(a) - int(b) == 1 else 1
        best_up, best_dn = max(best_up, run_up), max(best_dn, run_dn)
    if best_up >= 5:
        flags.append("ascending digit sequence (%d)" % best_up)
    if best_dn >= 5:
        flags.append("descending digit sequence (%d)" % best_dn)
    return flags


def analyze(raw, default_region=None, lang="en"):
    result = {"input": raw, "parsed": False}
    try:
        num = phonenumbers.parse(raw, default_region)
    except NumberParseException as exc:
        result["error"] = "Parse error: %s" % exc
        return result

    result["parsed"] = True
    valid = phonenumbers.is_valid_number(num)
    possible = phonenumbers.is_possible_number(num)
    ntype = phonenumbers.number_type(num)
    national = phonenumbers.national_significant_number(num)

    result.update({
        "valid": valid,
        "possible": possible,
        "country_code": num.country_code,
        "region_code": phonenumbers.region_code_for_number(num),
        "national_number": national,
        "e164": phonenumbers.format_number(num, PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(num, PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(num, PhoneNumberFormat.NATIONAL),
        "rfc3966": phonenumbers.format_number(num, PhoneNumberFormat.RFC3966),
        "line_type": TYPE_NAMES.get(ntype, "Unknown"),
        "location": geocoder.description_for_number(num, lang) or "Unknown",
        "country_name": geocoder.country_name_for_number(num, lang) or "Unknown",
        "carrier": carrier.name_for_number(num, lang) or "Unknown",
        "timezones": list(timezone.time_zones_for_number(num)),
    })

    # Heuristic risk scoring (informational only)
    score, reasons = 0, []
    if not valid:
        score += 50
        reasons.append("Number is not valid for its region")
    if not possible:
        score += 20
        reasons.append("Number length is not possible")
    if ntype in TYPE_RISK:
        score += TYPE_RISK[ntype]
        reasons.append("Line type: %s" % result["line_type"])
    for flag in digit_patterns(national):
        score += 15
        reasons.append("Pattern: " + flag)
    if ntype == PhoneNumberType.MOBILE and result["carrier"] == "Unknown":
        score += 5
        reasons.append("No carrier allocation data")

    score = min(score, 100)
    result["risk_score"] = score
    result["risk_level"] = "LOW" if score < 20 else "MEDIUM" if score < 50 else "HIGH"
    result["risk_reasons"] = reasons
    result["note"] = ("Carrier and location reflect the original number allocation. "
                      "Ported numbers and mobile subscribers may differ; this tool does "
                      "not determine a live location or subscriber identity.")
    return result


def print_report(r, color=True):
    col = (lambda k: C[k]) if color else (lambda k: "")
    x = col("x")
    print(col("B") + col("c") + "━" * 60 + x)
    print(col("B") + col("w") + " Target : " + x + str(r["input"]))
    print(col("B") + col("c") + "━" * 60 + x)

    if not r["parsed"]:
        print(col("r") + " [!] " + r["error"] + x + "\n")
        return

    def row(label, value, c="w"):
        print(" %s%-16s%s : %s%s%s" % (col("y"), label, x, col(c), value, x))

    row("Valid", "YES" if r["valid"] else "NO", "g" if r["valid"] else "r")
    row("Possible", "YES" if r["possible"] else "NO", "g" if r["possible"] else "r")
    row("E.164", r["e164"])
    row("International", r["international"])
    row("National", r["national"])
    row("RFC3966", r["rfc3966"])
    row("Country code", "+%s" % r["country_code"])
    row("Region", r["region_code"] or "Unknown")
    row("Country", r["country_name"])
    row("Location", r["location"])
    row("Carrier", r["carrier"])
    row("Line type", r["line_type"])
    row("Timezones", ", ".join(r["timezones"]) or "Unknown")

    lvl_col = {"LOW": "g", "MEDIUM": "y", "HIGH": "r"}[r["risk_level"]]
    row("Risk score", "%d/100 (%s)" % (r["risk_score"], r["risk_level"]), lvl_col)
    for reason in r["risk_reasons"]:
        print("   %s- %s%s" % (col("d"), reason, x))
    print(" %sNote: %s%s\n" % (col("d"), r["note"], x))


def load_numbers(args):
    nums = list(args.numbers)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                nums += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as exc:
            print("[!] Cannot read %s: %s" % (args.file, exc))
            sys.exit(1)
    return nums


def export_json(results, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"generated": datetime.now().isoformat(timespec="seconds"),
                   "tool": "Phone Number Intelligence Analyzer - Coded by Mr Sabaz Ali Khan",
                   "results": results}, fh, indent=2, ensure_ascii=False)
    print("[+] JSON report saved: " + path)


def export_csv(results, path):
    fields = ["input", "valid", "possible", "e164", "international", "country_code",
              "region_code", "country_name", "location", "carrier", "line_type",
              "timezones", "risk_score", "risk_level", "risk_reasons", "error"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in results:
            row = dict(r)
            row["timezones"] = ";".join(r.get("timezones", []))
            row["risk_reasons"] = ";".join(r.get("risk_reasons", []))
            w.writerow(row)
    print("[+] CSV report saved: " + path)


def main():
    ap = argparse.ArgumentParser(
        description="Phone Number Intelligence Analyzer - Coded by Mr Sabaz Ali Khan")
    ap.add_argument("numbers", nargs="*", help="phone number(s), ideally with +country code")
    ap.add_argument("-f", "--file", help="file with one number per line")
    ap.add_argument("-r", "--region", help="default region (ISO code, e.g. PK, US, GB) "
                                           "for numbers without a + prefix")
    ap.add_argument("-l", "--lang", default="en", help="language for location/carrier names")
    ap.add_argument("--json", metavar="FILE", help="export results to JSON")
    ap.add_argument("--csv", metavar="FILE", help="export results to CSV")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    ap.add_argument("--no-banner", action="store_true", help="hide the banner")
    args = ap.parse_args()

    color = not args.no_color and sys.stdout.isatty()
    if not args.no_banner:
        show_banner(color)

    numbers = load_numbers(args)
    if not numbers:
        try:
            raw = input("Enter phone number (with +country code): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        numbers = [raw] if raw else []
    if not numbers:
        ap.print_help()
        sys.exit(1)

    region = args.region.upper() if args.region else None
    results = []
    for n in numbers:
        r = analyze(n, region, args.lang)
        results.append(r)
        print_report(r, color)

    ok = sum(1 for r in results if r.get("valid"))
    print("[*] Analyzed %d number(s): %d valid, %d invalid/unparsed\n"
          % (len(results), ok, len(results) - ok))

    if args.json:
        export_json(results, args.json)
    if args.csv:
        export_csv(results, args.csv)


if __name__ == "__main__":
    main()
