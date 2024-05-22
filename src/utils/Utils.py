import sys
sys.path.append('src')
import json
import re

# Regex utils


__cve_regex = r"^(CVE-)\d{4}(-)\d{4,}$"
__cwe_regex = r"^(CWE-)\d*$"


def check_cve(cve_id: str) -> bool:
    return True if re.match(__cve_regex, cve_id) else False


def check_cwe(cwe_id: str) -> bool:
    return True if re.match(__cwe_regex, cwe_id) else False


# File utils


def get_json_from_file(filename: str, path: str = './src/_data/'):
    with open(f"{path}{filename}", "r", encoding='utf-8') as file:
        return json.load(file)


def save_to_json_file(json_data, filename: str, path: str ="./src/_data/"):
    """
        Desc:
            Utility methos to save json data to file.
        Params:
            :param json_data: the data to be saved
            :param filename: the filename including the extension of the file (e.g.: 'file.json')
            :param path: the save folder path - './src/_data/' by default
    """
    json_string = json.dumps(json_data, indent=4, default=str)
    __write_to_file__(json_string, filename, path)


def __write_to_file__(file_content, filename: str, path: str):
    with open(f"{path}{filename}", "w") as outfile:
        outfile.write(file_content)
