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
from datetime import datetime

# Current date

now = datetime.now()
today = now.strftime("%Y-%m-%d-%H_%M_%S")

# CSV

csv = "cve,cvss,source,url\n"

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

def find_urls(string):
    # Credit https://www.geeksforgeeks.org/python-check-url-string/
    # findall() has been used 
    # with valid conditions for urls in string
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex,string)      
    return [x[0] for x in url]

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
        cve = todos["result"]["CVE_Items"][0]["cve"]["CVE_data_meta"]["ID"]
        source = todos["result"]["CVE_Items"][0]["cve"]["CVE_data_meta"]["ASSIGNER"]
        print("cve: ", cve)
        print("publishedDate: ", todos["result"]["CVE_Items"][0]["publishedDate"].split("T")[0])
        print("lastModifiedDate: ", todos["result"]["CVE_Items"][0]["lastModifiedDate"].split("T")[0])
        print("assigner: ", source)
        print("description: ", todos["result"]["CVE_Items"][0]["cve"]["description"]["description_data"][0]["value"])
        
        try:
            cvss = todos["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            print("baseScore: ", cvss)

        except KeyError:
            print("baseScore: Unknown or too old")
            cvss = "0.0"
        nist_url = "https://nvd.nist.gov/vuln/detail/" + txt
        print("More info: " + nist_url + "\n")

        if args.input_file:
            global csv
            csv += cve + "," + str(cvss) + "," + source + "," + nist_url + "\n"
    else:
        print('"', txt, "\" not found in database.")

# KEYWORD -k / --keyword

def action_keyword(txt):
    if txt != "":
        # print(txt)
        # print("Will perform: https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=" + txt)
        action_url("https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=" + txt)
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
        input_file = open(txt, "r")
        data = input_file.read()
        input_file.close()
        cves_list_file = re.findall("CVE-[0-9]{4}-[0-9]{4,}", data, flags=re.IGNORECASE)
        urls_list_file = find_urls(data)
        if cves_list_file != []:
            sorted_cves_file = sorted(set(cves_list_file))
            for i in range (0, len(sorted_cves_file)):
                action_cve(sorted_cves_file[i])
            # To redirect into a file
            print("\nGenerated CSV: ./" + today + "-export.csv\n")
            # print(csv)
            f = open(today + "-export.csv", "w")
            f.write(csv)
            f.close()
        if urls_list_file != []:
            for i in range (0, len(urls_list_file)):
                action_url(urls_list_file[i])
    else:
        print("\"" + txt + "\" is not a valid file, aborting.")

# PARSER

parser = argparse.ArgumentParser()
parser.add_argument('-c','--cve', help='Choose CVE e.g. "CVE-2020-1472"')
parser.add_argument('-k','--keyword', help='Choose keyword e.g. "microsoft" -- it will give the 20 latest vulnerabilities and export to csv in the current directory')
parser.add_argument('-u','--url', help='Choose URL e.g. "https://nvd.nist.gov/" -- it will export to csv in the current directory')
parser.add_argument('-i','--input-file', help='Choose the path to input file containing CVEs or URLs e.g. "test.csv" -- it will export to csv in the current directory')

args = parser.parse_args()

if args.cve:
    action_cve(args.cve)
        
if args.keyword:
    action_keyword(args.keyword)

if args.url:
    action_url(args.url)

if args.input_file:
    action_file(args.input_file)    
