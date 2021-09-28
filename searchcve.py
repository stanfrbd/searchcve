#!/usr/bin/env python3

# Stanislas M. 2021 09 27

import sys
import requests
import re
from datetime import datetime

# Example of usage

# python3 searchcve.py https://us-cert.cisa.gov/ncas/alerts/aa21-209a
# python3 searchcve.py https://www.kennasecurity.com/blog/top-vulnerabilities-of-the-decade/
# python3 searchcve.py https://arstechnica.com/gadgets/2021/07/feds-list-the-top-30-most-exploited-vulnerabilities-many-are-years-old/
# python3 searchcve.py https://nvd.nist.gov/ 

# On linux
# ./searchcve.py https://us-cert.cisa.gov/ncas/alerts/aa21-209a
# ./searchcve.py https://nvd.nist.gov/ 

# Current date
now = datetime.now()
today = now.strftime("%Y-%m-%d-%H:%M:%S")

# Lists

cvss_list = []
cves_list = []
sources_list = []
url_list = []
csv = "cve,cvss,source,url\n"

# Argument #1

if len(sys.argv) != 2:
    print("Usage: python3 searchcve.py <URL>")
    quit()

url = str(sys.argv[1])

if "http" not in url:
    print('"' + url + '"' + " is not an URL, aborting")
    quit()

base_request = requests.get(url)

if base_request.status_code == 200:
    base_text = base_request.text
    cve_search = re.findall("CVE-[0-9]{4}-[0-9]{4,}", base_text)

    if cve_search == []:
        print("No CVE found, aborting.")
        quit()

    cves_list = sorted(set(cve_search))

    print("\nFound CVEs:\n")
    print("----------------------------------------------------------------------------------------------------------")
    print("CVE              | CVSS | Source                     | URL                                               |")
    print("----------------------------------------------------------------------------------------------------------")
    for i in range (0, len(cves_list)):
        nist_url = "https://nvd.nist.gov/vuln/detail/" + cves_list[i]
        nist_request = requests.get(nist_url)
        nist_text = nist_request.text
        cvss_search = re.search("&lt;span data-testid=&#39;vuln-cvssv3-base-score&#39;&gt;[0-9][0-9]?\.[0-9]", nist_text)
        if cvss_search is not None:
            cvss = cvss_search.group().split(";").pop()
        elif cvss_search is None:
            cvss = "0.0"

        potential_source = re.search("\"vuln-current-description-source\">[0-9A-Za-z, \./@]+</span>", nist_text)
        if potential_source is not None:
            potential_source = potential_source.group()
            potential_source = potential_source.replace("<", ";")
            potential_source = potential_source.replace(">", ";")
            # Avoid CSV error
            potential_source = potential_source.replace(",", "")
            source = potential_source.split(";")[1]
        elif potential_source is None:
            source = "Unknown"

        cvssf = float(cvss)
        cvss_list.append(cvssf)

        url_list.append(nist_url)

        sources_list.append(source)
        # CSV text
        csv += cves_list[i] + "," + cvss + "," + source + "," + nist_url + "\n"
        # Pretty print
        pretty_cve = cves_list[i]
        if len(cves_list[i]) != 16:
            for i in range (16 - len(cves_list[i])):
                pretty_cve += " "
        if len(cvss) != 4:
            cvss += " "
        if len(source) != 26:
            for i in range (26 - len(source)):
                source += " "
        nist_url = nist_url
        if len(nist_url) != 49:
            for i in range (49 - len(nist_url)):
                nist_url += " "
        print(pretty_cve + " | " + cvss + " | " + source + " | " + nist_url + " |")
        print("----------------------------------------------------------------------------------------------------------")

    # Max CVSS
    print("\nMax CVSS: " + str(max(cvss_list)))

    # List of URLs
    # print("\nList of URLs:\n")
    # print(*url_list, sep='\n')

    # To redirect into a file
    print("\nGenerated CSV: ./" + today + "-export.csv\n")
    # print(csv)
    f = open(today + "-export.csv", "w")
    f.write(csv)
    f.close()

else:
    print("HTTP error: " + str(base_request.status_code))
    print("Aborting.")
    quit()