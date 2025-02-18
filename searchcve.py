#!/usr/bin/env python3

# Stanislas M. 2021-09-28

"""
usage: searchcve.py [-h] [-c CVE] [-k KEYWORD] [-u URL] [-i INPUT_FILE] [-p PROXY]

options:
  -h, --help            show this help message and exit
  -c CVE, --cve CVE     Choose CVE e.g. "CVE-2020-1472"
  -k KEYWORD, --keyword KEYWORD
                        Choose keyword e.g. "microsoft" -- it will give the 20 latest vulnerabilities and export to
                        csv in the current directory
  -u URL, --url URL     Choose URL e.g. "https://nvd.nist.gov/" -- it will export to csv in the current directory
  -i INPUT_FILE, --input-file INPUT_FILE
                        Choose the path to input file containing CVEs or URLs e.g. "test.csv" -- it will export to csv
                        in the current directory
  -p PROXY, --proxy PROXY
                        Choose proxy e.g. "http://127.0.0.1:9000"
"""

import json
import argparse
import re
import requests
from bs4 import BeautifulSoup
from pathlib import Path
from datetime import datetime
import time
from prettytable import PrettyTable

# disable ssl warning in case of proxy like Zscaler which breaks ssl...
requests.packages.urllib3.disable_warnings()

# Your proxy here...
proxy = ""

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

def export_to_csv():
    filename = "{}-export.csv".format(today)
    print("\nGenerated CSV: ./{}\n".format(filename))
    f = open(filename, "a")
    f.write(csv)
    f.close()

# Core function

def searchcve(url):
    cvss_list = []
    cves_list = []
    sources_list = []
    url_list = []
    global csv
    
    proxy_servers = { 'http': proxy, 'https': proxy }
    base_request = requests.get(url, timeout=10, proxies=proxy_servers, verify=False)

    if base_request.status_code == 200:
        base_text = base_request.text
        cve_search = re.findall("CVE-[0-9]{4}-[0-9]{4,}", base_text)

        if cve_search == []:
            print("[i] No CVE found, aborting.")
            return

        # Get unique CVEs
        cves_list = sorted(set(cve_search))

        table = PrettyTable()
        table.field_names = ["CVE", "CVSS", "Source", "URL"]
        
        for i in range (0, len(cves_list)):

            # URL
            nist_url = "https://nvd.nist.gov/vuln/detail/{}".format(cves_list[i])

            nist_request = requests.get(nist_url, timeout=10, proxies=proxy_servers, verify=False) 

            soup = BeautifulSoup(nist_request.text, "html.parser")

            # CVSS
            try:
                cvss_element = soup.find("a", attrs={ "data-testid": "vuln-cvss3-cna-panel-score" })
                if not cvss_element:
                    cvss_element = soup.find("a", attrs={ "data-testid": "vuln-cvss3-panel-score" })
                cvss = cvss_element.text.split()[0]  # Extract the base score
            except Exception as err:
                print("[!] Error: {}".format(str(err)))
                cvss = "0.0"
            
            # Source
            try: 
                source = soup.find_all(
                    "span", 
                    attrs={ 
                        "data-testid": "vuln-current-description-source" 
                    } 
               )[0].string.strip().replace(",", "") 
            except Exception: 
                source = "Unknown"

            cvssf = float(cvss)
            cvss_list.append(cvssf)

            url_list.append(nist_url)

            sources_list.append(source)
            
            # CSV text
            csv += cves_list[i] + "," + cvss + "," + source + "," + nist_url + "\n"
            
            table.add_row([cves_list[i], cvss, source, nist_url])
        
            # Printing during the loop, erasing
            print("\033[2J\033[H" + str(table))

        # Max CVSS
        print("\n[i] Max CVSS: {}".format(str(max(cvss_list))))

        # Export
        export_to_csv()
        csv = ""

    else:
        raise Exception("[!] HTTP error: {}".format(str(base_request.status_code))) 

# CVE -c / --cve

def action_cve(txt):
    if is_cve(txt):
        cve_info(txt)
    else:
        print('[!] "{}" is not a valid CVE, aborting.'.format(txt))

def cve_info(txt):
    proxy_servers = { 'http': proxy, 'https': proxy }
    nist_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}".format(txt)
    base_request = requests.get(nist_api_url, timeout=10, proxies=proxy_servers, verify=False)
    if base_request.status_code == 200:
        todos = json.loads(base_request.text)
        cve = todos["vulnerabilities"][0]["cve"]["id"]
        source = todos["vulnerabilities"][0]["cve"]["sourceIdentifier"]
        published_date = todos["vulnerabilities"][0]["cve"]["published"].split("T")[0]
        last_modified_date = todos["vulnerabilities"][0]["cve"]["lastModified"].split("T")[0]
        english_description = todos["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]
        print("CVE: {}".format(cve))
        print("Published date: {}".format(published_date))
        print("Last modified date: {}".format(last_modified_date))
        print("Source: {}".format(source))
        print("Description: {}".format(english_description))
        
        try:
            cvss = todos["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            severity = todos["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            print("CVSS 3.1 (Base Score): {} ({})".format(cvss, severity))

        except KeyError:
            print("CVSS 3.1 (Base Score): Unknown or too old")
            cvss = "0.0"
        nist_url = "https://nvd.nist.gov/vuln/detail/{}".format(txt)
        print("More info: {} \n".format(nist_url))

        if args.input_file:
            global csv
            csv += cve + "," + str(cvss) + "," + source + "," + nist_url + "\n"
            # Add delay to avoid blocking
            delay = 30
            print("[i] Waiting {} seconds to avoid API limitations...".format(delay))
            time.sleep(delay)
    else:
        print('[!] "{}" not found in database.'.format(txt))

# KEYWORD -k / --keyword

def action_keyword(txt):
    if txt != "":
        action_url("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}".format(txt))
    else:
        print('[!] "{}" is not a valid keyword, aborting.'.format(txt))

# URL -u / --url

def action_url(txt):
    if is_url(txt):
        print(txt)
        searchcve(txt)
    else:
        print('[!] "{}" is not a valid URL, aborting.'.format(txt))

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
            # Export
            export_to_csv()
        if urls_list_file != []:
            for i in range (0, len(urls_list_file)):
                action_url(urls_list_file[i])
    else:
        print('[!] "{}" is not a valid file, aborting.'.format(txt))

# MAIN

def main(): 
    parser = argparse.ArgumentParser()
    parser.add_argument('-c','--cve', help='Choose CVE e.g. "CVE-2020-1472"')
    parser.add_argument('-k','--keyword', help='Choose keyword e.g. "microsoft" -- it will give the 20 latest vulnerabilities and export to csv in the current directory')
    parser.add_argument('-u','--url', help='Choose URL e.g. "https://nvd.nist.gov/" -- it will export to csv in the current directory')
    parser.add_argument('-i','--input-file', help='Choose the path to input file containing CVEs or URLs e.g. "test.csv" -- it will export to csv in the current directory')
    parser.add_argument('-p', '--proxy', help='Choose proxy e.g. "http://127.0.0.1:9000"')

    global args
    args = parser.parse_args()

    if args.cve:
        action_cve(args.cve)

    if args.keyword:
        action_keyword(args.keyword)

    if args.url:
        action_url(args.url)

    if args.input_file:
        action_file(args.input_file)

    if args.proxy:
        global proxy
        proxy = args.proxy    

if __name__ == "__main__":
    try: 
        main()
    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt Detected.")
        print("[i] Exiting...")
        exit(0)
    except Exception as err: 
        print("[!] General error: {}".format(str(err)))
        exit(1)
    
