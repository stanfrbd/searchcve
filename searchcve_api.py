#!/usr/bin/env python3

# Stanislas M. 2021 09 28

"""
usage: searchcve_api.py [-h] [-c CVE] [-k KEYWORD] [-u URL] [-i INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -c CVE, --cve CVE     Choose CVE e.g. CVE-2020-1472
  -k KEYWORD, --keyword KEYWORD
                        Choose keyword e.g. microsoft
  -u URL, --url URL     Choose URL e.g. https://nvd.nist.gov/
  -i INPUT_FILE, --input-file INPUT_FILE
                        Choose the path to input file e.g. test.csv
"""

import json
import argparse
import re
from os.path import exists
from pathlib import Path
import subprocess



# Checks

def action_cve(txt):
    match = re.search("(CVE|cve)-[0-9]{4}-[0-9]{4,}", txt)
    if match:
        print(txt)
        print("Will perform: https://services.nvd.nist.gov/rest/json/cve/1.0/" + txt)
    else:
        print("\"" + txt + "\" is not a valid CVE, aborting.")
        quit()

def action_keyword(txt):
    if txt != "":
        print(txt)
        print("Will perform: https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=" + txt)
    else:
        print("\"" + txt + "\" is not a valid keyword, aborting.")
        quit()

def action_url(txt):
    if "http" in txt:
        print(txt)
        subprocess.call(["python3", "searchcve.py", txt])
    else:
        print("\"" + txt + "\" is not a valid URL, aborting.")
        quit()

def action_file(txt):
    if Path(txt).is_file():
        print(txt)
    else:
        print("\"" + txt + "\" is not a valid file, aborting.")
        quit()

parser = argparse.ArgumentParser()
parser.add_argument('-c','--cve', help='Choose CVE e.g. CVE-2020-1472')
parser.add_argument('-k','--keyword', help='Choose keyword e.g. microsoft')
parser.add_argument('-u','--url', help='Choose URL e.g. https://nvd.nist.gov/')
parser.add_argument('-i','--input-file', help='Choose the path to input file e.g. test.csv')

args = parser.parse_args()

if args.cve:
    action_cve(args.cve)
    
if args.keyword:
    action_keyword(args.keyword)

if args.url:
    action_url(args.url)

if args.input_file:
    action_file(args.input_file)
