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
import requests
from os.path import exists
from pathlib import Path
import subprocess



# CHECKS

def is_cve(txt):
    match = re.search("(CVE|cve)-[0-9]{4}-[0-9]{4,}$", txt)
    if match:
        return True
    else:
        return False

def is_url(txt):
    if "http" in txt:
        return True
    else:
        return False

# CVE -c / --cve

def action_cve(txt):
    if is_cve(txt):
        cve_info(txt)
    else:
        print("\"" + txt + "\" is not a valid CVE, aborting.")

def cve_info(txt):
    nist_api_url = "https://services.nvd.nist.gov/rest/json/cve/1.0/" + txt
    base_request = requests.get(nist_api_url)
    if base_request.status_code == 200:
        todos = json.loads(base_request.text)
        print("cve: ", todos["result"]["CVE_Items"][0]["cve"]["CVE_data_meta"]["ID"])
        print("publishedDate: ", todos["result"]["CVE_Items"][0]["publishedDate"].split("T")[0])
        print("lastModifiedDate: ", todos["result"]["CVE_Items"][0]["lastModifiedDate"].split("T")[0])
        print("assigner: ", todos["result"]["CVE_Items"][0]["cve"]["CVE_data_meta"]["ASSIGNER"])
        print("description: ", todos["result"]["CVE_Items"][0]["cve"]["description"]["description_data"][0]["value"])
        print("baseScore: ",todos["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"])
        print("baseSeverity: ",todos["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"])
        print("More info: https://nvd.nist.gov/vuln/detail/" + txt + "\n")
    else:
        print('"', txt, "\" not found in database.")

# KEYWORD -k / --keyword

def action_keyword(txt):
    if txt != "":
        print(txt)
        print("Will perform: https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=" + txt)
    else:
        print("\"" + txt + "\" is not a valid keyword, aborting.")

# URL -u / --url

def action_url(txt):
    if is_url(txt):
        print(txt)
        subprocess.call(["python3", "searchcve.py", txt])
    else:
        print("\"" + txt + "\" is not a valid URL, aborting.")

# INPUT_FILE -i / --input-file

def action_file(txt):
    if Path(txt).is_file():
        print(txt)
    else:
        print("\"" + txt + "\" is not a valid file, aborting.")

# PARSER

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
