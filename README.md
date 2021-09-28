# searchcve
> Web scrapping tool written in python3, using regex, to get CVEs, Source and URLs.

> Generates a CSV file in the current directory.

### Dependencies

* `requests` must be installed.

`pip install requests` should do this job :)



### Example of usage

```sh
python3 searchcve.py https://us-cert.cisa.gov/ncas/alerts/aa21-209a
python3 searchcve.py https://www.kennasecurity.com/blog/top-vulnerabilities-of-the-decade/
python3 searchcve.py https://arstechnica.com/gadgets/2021/07/feds-list-the-top-30-most-exploited-vulnerabilities-many-are-years-old/
python3 searchcve.py https://nvd.nist.gov/ 
```

### On Linux
```sh
./searchcve.py https://us-cert.cisa.gov/ncas/alerts/aa21-209a
./searchcve.py https://nvd.nist.gov/ 
```

![image](https://user-images.githubusercontent.com/44167150/134931282-ca33dba3-4ab6-474d-8e5a-3da9e6013e6a.png)

![image](https://user-images.githubusercontent.com/44167150/134931413-1e3dc51d-9c8f-44b2-acbd-fa4fc1fff8f4.png)

# Work in progress

> Command line tool, will use the NIST API to get resources.
```sh
usage: searchcve_api.py [-h] [-c CVE] [-k KEYWORD] [-u URL] [-i INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -c CVE, --cve CVE     Choose CVE e.g. CVE-2020-1472
  -k KEYWORD, --keyword KEYWORD
                        Choose keyword e.g. microsoft
  -u URL, --url URL     Choose URL e.g. https://nvd.nist.gov/
  -i INPUT_FILE, --input-file INPUT_FILE
                        Choose the path to input file e.g. test.csv
```

```sh
python3 searchcve_api.py -u https://nvd.nist.gov/
```

> This will call `python3 searchcve.py https://nvd.nist.gov/`

```sh
python3 searchcve_api.py -c CVE-2020-1472
```

> This will make this API call `https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-2020-1472`


```sh
python3 searchcve_api.py -k microsoft
```

> This will make this API call `https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=microsoft`
