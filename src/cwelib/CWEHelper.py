import sys
sys.path.append('src')
from utils.Utils import save_to_json_file, get_json_from_file
from utils.CWEPrettify import get_pretty_cwe_json
from io import BytesIO
import requests
import zipfile
import xmltodict


def __get_json_data_from_zip(compressed_data):
    filebytes = BytesIO(compressed_data)
    zip_file = zipfile.ZipFile(filebytes)
    for name in zip_file.namelist():
        # It is known there will be only one .xml in this .zip
        return __get_json_data_from_xml(zip_file.open(name).read())


def __get_json_data_from_xml(xml_data):
    return xmltodict.parse(xml_data)


def save_cwe_json() -> bool:
    result = requests.get('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')
    data_dict = __get_json_data_from_zip(result.content)
    save_to_json_file(get_pretty_cwe_json(data_dict), 'CWE-All.json')
