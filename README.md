## cvwelib at a glance

CVE & CWE Lib allows local querying for CVE and CWE data.

### Data source & fetching

cvwelib fetches its data from the following community project: [Click](https://github.com/fkie-cad/nvd-json-data-feeds)

The project is structured so that the local server will automatically download all the needed .json files upon startup.
In case of an existing server, the data will be automatically updated each day based on the `Modified` feeds

```plain
CVE-Modified.json # CVEs that were modified or added in the previous eight days
```

## Request format

cvwelib provides the following request parameters:
- `year` allows to fetch all CVEs registered to a specific year
- `cveId` allows to fetch the specifcied CVE-ID data
- `cweId` allows to fetch all CVEs related to the specified CWE-ID
- `keywordSearch` allows to fetch CVEs based on the given keyword in their description
- `keywordExactMatch` specifies that the keyword given must exactly match

### Request examples

```plain
<HOST>:<PORT>/api/get_cve?year=<YEAR> # Get all CVEs related to inputted year
```

```plain
<HOST>:<PORT>/api/get_cve?cveId=<CVE-ID> # Get data for the specied CVE-ID
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


## Non-Endorsement Clause

As the previously mentioned repo, this project uses and redistributes data from the NVD API but is not endorsed or certified by the NVD.
