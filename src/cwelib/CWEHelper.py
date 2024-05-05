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
    result = requests.get('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')
    data_dict = __get_json_data_from_zip(result.content)
    try:
        save_to_json_file(get_pretty_cwe_json(data_dict), 'CWE-All.json')
    except:
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
