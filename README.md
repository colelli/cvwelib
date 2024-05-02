## cvwelib at a glance

CVE & CWE Lib allows local querying for CVE and CWE data.

### Data source & fetching

cvwelib fetches its data from the following community project: [Click](https://github.com/fkie-cad/nvd-json-data-feeds)

The project is structured so that the local server will automatically download all the needed .json files upon startup.
In case of an existing server, the data will be automatically updated each day based on the 'Modified' feeds

```plain
CVE-Modified.json # CVEs that were modified or added in the previous eight days
```

## Non-Endorsement Clause

As the previously mentioned repo, this project uses and redistributes data from the NVD API but is not endorsed or certified by the NVD.
