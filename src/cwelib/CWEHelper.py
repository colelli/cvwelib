import sys
sys.path.append('src')
from utils.Utils import save_to_json_file, get_json_from_file
from utils.CWEPrettify import get_pretty_cwe_json
from io import BytesIO
import requests
import zipfile
import xmltodict
import logging

__force_list = ('Related_Weakness', 'Language', 'Technology', 'Alternate_Term', 'Consequence', 
                'Detection_Method', 'Mitigation', 'Functional_Area', 'Affected_Resource', 'Taxonomy_Mapping',
                'Related_Attack_Pattern','Reference','Has_Member', 'Operating_System', 'Architecture')


def __get_json_data_from_zip(compressed_data):
    filebytes = BytesIO(compressed_data)
    zip_file = zipfile.ZipFile(filebytes)
    for name in zip_file.namelist():
        # It is known there will be only one .xml in this .zip
        return __get_json_data_from_xml(zip_file.open(name).read())


def __get_json_data_from_xml(xml_data):
    return xmltodict.parse(xml_data, force_list = __force_list)


def save_cwe_json() -> bool:
    """
        Desc:
            This method allows the retrieval (and local save) of the CWE dataset from the following source:
            https://cwe.mitre.org/data/downloads.html by The MITRE Corporation
            The data is downloaded in .zip format, extracted, converted and saved to .json in the local /_data folder in the format 'CWE-All.json'.
        Returns:
            True if the saving process ends successfully
    """
    result = requests.get('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')
    data_dict = __get_json_data_from_zip(result.content)
    try:
        save_to_json_file(get_pretty_cwe_json(data_dict), 'CWE-All.json')
    except FileNotFoundError:
        return False
    return True


def start_up_server(debug: bool = False) -> bool:
    """
        Desc:
            Method to start-up the local sever
        Returns:
            True if the start-up process ends correctly
    """
    if debug:
        return True
    return save_cwe_json()


def update_data():
    if not save_cwe_json():
        logging.debug("Error occurred during CWE data")


def get_all_cwes() -> dict:
    """
        Desc:
            Method to get all CWEs and extra information
        Returns:
            Dictionary of all info fetched from JSON format
    """
    return get_json_from_file('CWE-All.json')


def get_cwe_from_id(cwe_id: str) -> dict:
    """
        Desc:
            Method to get CWE data based on given CWE-ID
        Params:
            :param cwe_id: The requested CWE-ID
        Returns:
            Dictionary of all available information for the given CWE-ID
    """
    data = get_all_cwes()
    for cwe in data['weaknesses']:
        if cwe['id'] == cwe_id:
            return cwe
    return {}


def get_cwe_parents(cwe_id: str) -> list:
    """
        Desc:
            Method to fetch all the parents CWEs of a given CWE-ID
        Params:
            :param cwe_id: The children CWE-ID
        Returns:
            A list of all parent CWEs of the specified ID. 
            The list contains all information for each parent CWE
    """
    out = []
    data = get_cwe_from_id(cwe_id)
    for rel in data['related_cwes']:
        if rel['nature'] == 'ChildOf':
            out.append(get_cwe_from_id(rel['id']))
    return out


def get_cwe_children(cwe_id: str) -> list:
    """
        Desc:
            Method to fetch all the children CWEs of a given CWE-ID
        Params:
            :param cwe_id: The parent CWE-ID
        Returns:
            A list of all children CWEs of the specified ID.
            The list contains all information for each children CWE
    """
    out = []
    data = get_all_cwes()
    for cwe in data['weaknesses']:
        for rel in cwe['related_cwes']:
            if rel['id'] == cwe_id and rel['nature'] == 'ChildOf':
                out.append(cwe)
    return out


def get_cwe_count() -> int:
    """
        Desc:
            Method to fetch the current CWE database count
        Returns:
            Integer representing current CWE count
    """
    data = get_all_cwes()
    return data['weaknessCatalog']['cweCount']
