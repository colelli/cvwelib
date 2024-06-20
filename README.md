## cvwelib at a glance

CVE & CWE Lib allows local querying for CVE and CWE data.

### Data source & fetching

cvwelib fetches its data from the following community project: [Click](https://github.com/fkie-cad/nvd-json-data-feeds)

The project is structured so that the local server will automatically download all the needed .json files upon startup.
In case of an existing server, the data will be automatically updated each day based on the `Modified` feeds

```plain
CVE-Modified.json # CVEs that were modified or added in the previous eight days
```

### Before running the code

Since the code is still in development, before running it for the first time, it is adviced to open the `cvwelib.py` file and change
the `debug` mode from `True` to `False` on line 25. This will allow the script to download all the necessary data at each server start-up. As of
right now it is intended to be set on `True` as the code undergoes modifications.

## Request format

cvwelib provides the following request parameters:
- CVE API
    - `year` allows to fetch all CVEs registered to a specific year
    - `cveId` allows to fetch the specifcied CVE-ID data
    - `includeQuarantined` allows quarantined vulnerabilities (the ones with status 'Undergoing Analysis' and 'Awaiting Analysis') to be fetched
    - `cweId` allows to fetch all CVEs related to the specified CWE-ID
    - `keywordSearch` allows to fetch CVEs based on the given keyword in their description
    - `keywordExactMatch` specifies that the keyword given must exactly match
    - `cveCount` allows to fetch the total CVE count analyzed by the system
- CWE API
    - `all` allows to fetch the entire CWE json file 
    - `cweId` allows to fetch the specifcied CWE-ID data
    - `getParents` allows to fetch the list of parents for the given CWE-ID
    - `getChildren` allows to fetch the list of children for the given CWE-ID
    - `cweCount` allows to fetch the total CWE count analyzed by the system

### Request examples

CVE API Examples

```plain
<HOST>:<PORT>/api/get_cve?year=<YEAR> # Get all CVEs related to inputted year
```

```plain
<HOST>:<PORT>/api/get_cve?cveId=<CVE-ID> # Get data of the specied CVE-ID (excludes quarantined items)
```

```plain
<HOST>:<PORT>/api/get_cve?cveId=<CVE-ID>&includeQuarantined # Get data of the specied CVE-ID even if quarantined
```

```plain
<HOST>:<PORT>/api/get_cve?cweId=<CWE-ID> # Get all CVEs related to inputted CWE
```

```plain
<HOST>:<PORT>/api/get_cve?keywordSearch=<KEY-WORD> # Get all CVEs containing any specified keyword in their description
```

```plain
<HOST>:<PORT>/api/get_cve?keywordSearch=<KEY-WORD>&keywordExactMatch # Get all CVEs matching the keyword exactly
```

CWE API Examples

```plain
<HOST>:<PORT>/api/get_cwe?all # Get all CWEs
```

```plain
<HOST>:<PORT>/api/get_cwe?cweId=<CWE-ID> # Get data of the specied CWE-ID
```

```plain
<HOST>:<PORT>/api/get_cwe?getParents=<CWE-ID> # Get all parents of the inputted CWE
```

```plain
<HOST>:<PORT>/api/get_cwe?getChildren=<CWE-ID> # Get all children of the inputted CWE
```

## Non-Endorsement Clause

As the previously mentioned repo, this project uses and redistributes data from the NVD API but is not endorsed or certified by the NVD.
In addition, this project uses and redistributes data from The MITRE Corporation but is not endorsed or certified by The MITRE Corporation.
