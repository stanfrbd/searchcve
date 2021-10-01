# searchcve
> Web scrapping tool written in python3, using regex, to get CVEs, Source and URLs.

> Generates a CSV file in the current directory.

> Uses the NIST API to get info.

### Dependencies

* `requests` must be installed.

`pip install requests` should do this job :)

### Example of usage

```sh
python3 searchcve.py -u https://us-cert.cisa.gov/ncas/alerts/aa21-209a
python3 searchcve.py -u https://www.kennasecurity.com/blog/top-vulnerabilities-of-the-decade/
python3 searchcve.py --url https://arstechnica.com/gadgets/2021/07/feds-list-the-top-30-most-exploited-vulnerabilities-many-are-years-old/
python3 searchcve.py --url https://nvd.nist.gov/ 
```

### Developpement on Linux 

Just in Bash (Ubuntu 18+) : 
```sh
./developper.sh
```

### On Linux
```sh
./searchcve.py -u https://us-cert.cisa.gov/ncas/alerts/aa21-209a
./searchcve.py --url https://nvd.nist.gov/ 
```

![image](https://user-images.githubusercontent.com/44167150/135639477-16e946a9-93e3-414d-9213-ededd32139e0.png)

# Other arguments

> Command line tool that uses the NIST API to get resources.
```sh
usage: searchcve_api.py [-h] [-c CVE] [-k KEYWORD] [-u URL] [-i INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -c CVE, --cve CVE     Choose CVE e.g. "CVE-2020-1472"
  -k KEYWORD, --keyword KEYWORD
                        Choose keyword e.g. "microsoft" -- it will give the 20 latest vulnerabilities and export to csv in the current directory
  -u URL, --url URL     Choose URL e.g. "https://nvd.nist.gov/" -- it will export to csv in the current directory
  -i INPUT_FILE, --input-file INPUT_FILE
                        Choose the path to input file containing CVEs or URLs e.g. "test.csv" -- it will export to csv in the current directory
```

```sh
python3 searchcve.py -c CVE-2020-1472
```

![image](https://user-images.githubusercontent.com/44167150/135640415-7479a252-751d-45d1-bec0-9f50a7245a67.png)


```sh
python3 searchcve.py -k microsoft
```

![image](https://user-images.githubusercontent.com/44167150/135640585-d295ce9e-9f4f-49dc-9214-9bc5f60987af.png)

```sh
python3 searchcve.py -i cves.csv
```

![image](https://user-images.githubusercontent.com/44167150/135640892-bc37b259-158e-4194-a8ef-28b348b37111.png)

