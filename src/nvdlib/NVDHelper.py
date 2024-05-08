import sys
sys.path.append('src')
import logging
logging.basicConfig(stream = sys.stderr, level = logging.DEBUG)
from datetime import datetime
from utils.Utils import save_to_json_file, get_json_from_file
import requests
import lzma
import json


def __get_json_data_from_xz(url: str):
    """
        Desc:
            Method to retrieve data in .json.xz format from a given url, decompress it and return it in json format
        Params:
            :param url: the url to fetch data from
        Returns:
            The requested .json data
    """
    response = requests.get(url)
    decompressed_data = lzma.decompress(response.content)
    return json.loads(decompressed_data.decode('utf-8'))


def __get_modified_cve_years() -> set:
    """
        Desc:
            Method to get modified CVEs up to the last 8 days. The data is pulled from the following repository:
            https://github.com/fkie-cad/nvd-json-data-feeds by fkie-cad\n
            Only if the current system does not have a record of modified data, or it does not match the latest update
            data will be automatically updated for every CVE year included in the modified json
        Returns:
            set of the modified CVE years
    """
    try:
        last_modified = get_json_from_file("CVE-Modified.json")
    except FileNotFoundError:
        last_modified = None

    request_link = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-Modified.json.xz"
    formatted_data = __get_json_data_from_xz(request_link)

    if last_modified != None and last_modified['timestamp'] == formatted_data['timestamp']:
        logging.info("Data already up-to-date")
        return set([])
    
    out = []
    for cve in formatted_data['cve_items']:
        out.append((str(cve['id']).split('-'))[1])
    
    save_to_json_file(formatted_data, "CVE-Modified.json")
    return set(out)


def check_for_updates():
    """
        Desc:
            Method to check for data update. It uses an internal call to get all the modified CVEs up to the last 8 days. 
            The data is pulled from the following repository:
            https://github.com/fkie-cad/nvd-json-data-feeds by fkie-cad\n
            Only if the current system does not have a record of modified data, or it does not match the latest update
            data will be automatically updated for every CVE year included in the modified json
    """
    modified_years = __get_modified_cve_years()
    if len(modified_years) > 0:
        [save_one_year_json(int(year)) for year in modified_years]
        logging.info(f'Data updated for years: {[year for year in modified_years]}')


def start_up_server(debug: bool = False) -> bool:
    """
        Desc:
            Method to start-up the local sever
        Returns:
            True if the start-up process ends correctly
    """
    if debug:
        return True
    return save_all_years_json()


def save_one_year_json(year: int):
    """
        Desc:
            This method allows the retrieval (and local save) of a specified year CVE dataset from the following repository:
            https://github.com/fkie-cad/nvd-json-data-feeds by fkie-cad
            The data is downloaded in .xz format, extracted and saved to .json in the local /_data folder in the format 'CVE-<YEAR>.json'.
        Params:
            :param year: The desired year to fetch
        Raises:
            :raises ValueError: if the selected year is not valid. Must be in the range [1999, datetime.now().year]
    """
    if year < 1999 or year > datetime.now().year:
        raise ValueError('Invalid input value: please insert valid year from 1999 to today.')
    
    request_link = f"https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"
    formatted_data = __get_json_data_from_xz(request_link)
      
    save_to_json_file(formatted_data, f'CVE-{year}.json')


def save_all_years_json() -> bool:
    """
        Desc:
            This method allows the retrieval (and local save) of all available year CVE datasets from the following repository:
            https://github.com/fkie-cad/nvd-json-data-feeds by fkie-cad
            The data is downloaded in .xz format, extracted and saved to .json in the local /data folder in the format 'CVE-<YEAR>.json'.
        Returns:
            True if the process ends correctly
    """
    for year in range(1999, datetime.now().year + 1):
        try:
            save_one_year_json(year)
        except ValueError:
            return False
    return True


def get_one_year_json(year: int) -> dict:
    """
        Desc:
            Method to get all the CVEs from the specicied year
        Returns:
            The reqeusted data
    """
    return get_json_from_file(f'CVE-{year}.json')


def get_one_cve_from_id(cve_id: str) -> dict:
    """
        Desc: 
            Method to retrieve the specified CVE-ID data
        Params:
            :param cve_id: The requested CVE-ID
        Returns:
            The requested CVE-ID data or empty dict if not found
        Raises:
            :raises ValueError: if the specified CVE-ID is badly formatted
    """
    tokens =  cve_id.split('-')
    if len(tokens) < 3:
        raise ValueError('Badly formatted CVE-ID!')
    data = get_one_year_json(tokens[1])
    for cve in data['cve_items']:
        if cve['id'] == cve_id:
            return cve
    return {}


def get_cves_from_desc(keyword: str, exact_match: bool) -> list:
    """
        Desc:
            Method to retrieve all matching CVEs based on the given keyword.
            The method looks for the keywords in the CVE description and can be of two types:
            - exact_match = False -> every keyword is evaluated individually
            - exact_match = True -> keyword must match exactly
        Params:
            :param keyword: The given keyword to look for
            :param exact_match: The boolean value to specify search mode
        Returns:
            The list of all matching CVEs
    """
    if exact_match:
        return __get_exact_match(keyword)
    else:
        return __get_any_match(keyword)


def __get_exact_match(keyword: str) -> list:
    out = []
    # We look for an exact match
    for year in range(1999, datetime.now().year + 1):
        result = get_one_year_json(year)
        for cve in result['cve_items']:
            if keyword in (cve['descriptions'])[0]['value']:
                out.append(cve)
    return out


def __get_any_match(keyword: str) -> list:
    out = []
    # We look for any keyword match
    keywords = keyword.split(" ")
    for year in range(1999, datetime.now().year + 1):
        result = get_one_year_json(year)
        for cve in result['cve_items']:
            for key in keywords:
                if key in (cve['descriptions'])[0]['value']:
                    out.append(cve)
                    break
    return out


def get_one_cve_from_cwe(cwe_id: str):
    """
        Desc:
            Method to retrieve all CVEs related to the given CWE-ID.
        Params:
            :param cwe_id: The requested CWE-ID
        Returns:
            The list of all CVEs related to the requeste CWE
    """
    out = []
    for year in range(1999, datetime.now().year + 1):
        result = get_one_year_json(year)
        for cve in result['cve_items']:
            if 'weaknesses' not in cve.keys():
                continue
            for cwe in cve['weaknesses']:
                if ((cwe['description'])[0])['value'] == cwe_id:
                    out.append(cve)
                    break
    return out
