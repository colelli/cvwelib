def get_pretty_cwe_json(raw_data: dict) -> dict:
    out = {}

    out['weaknessCatalog'] = {
        'name': raw_data['Weakness_Catalog']['@Name'],
        'version': float(raw_data['Weakness_Catalog']['@Version']),
        'date': raw_data['Weakness_Catalog']['@Date']
    }
    out['weaknesses'] = []
    for weakness in raw_data['Weakness_Catalog']['Weaknesses']['Weakness']:
        weakness_id = weakness['@ID']
        item = {
            'id': f'CWE-{weakness_id}',
            'name': weakness['@Name'],
            'abstraction': weakness['@Abstraction'],
            'structure': weakness['@Structure'],
            'status': weakness['@Status'],
            'short_description': weakness['Description'],
            'full_description':weakness['Extended_Description'] if 'Extended_Description' in weakness.keys() else None,
            'details': weakness['Background_Details']['Background_Detail'] if 'Background_Details' in weakness.keys() else None,
            'related_cwes': [],
            'platforms': {},
            'alternateTerms': [],
            'exploitability': weakness['Likelihood_Of_Exploit'] if 'Likelihood_Of_Exploit' in weakness.keys() else None,
            'consequences': [],
            'detectionMethods': [],
            'mitigations': [],
            'demonstrativeExamples': weakness['Demonstrative_Examples']['Demonstrative_Example'] if 'Demonstrative_Examples' in weakness.keys() else None,
            'observedExamples': weakness['Observed_Examples'] if 'Observed_Examples' in weakness.keys() else None,
            'functionalAreas': [],
            'affectedResources': [],
            'taxonomyMapping': [],
            'relatedAttackPatterns': [],
            'references': [],
            'mappingNotes': weakness['Mapping_Notes'] if 'Mapping_Notes' in weakness.keys() else None,
            'contentHistory': weakness['Content_History'] if 'Content_History' in weakness.keys() else None,
        }

        # Collecting all CWEs
        if 'Related_Weaknesses' in weakness.keys():
            for cwe in weakness['Related_Weaknesses']['Related_Weakness']:
                item['related_cwes'].append(__map_cwe(cwe))
        
        # Collecting all platforms
        if 'Applicable_Platforms' in weakness.keys():
            for platform in weakness['Applicable_Platforms'].keys():
                for sub_item in weakness['Applicable_Platforms'][platform]:
                    item['platforms'][f'{platform.lower()}'] = __map_platforms(sub_item)

        # Collecting all alternate terms
        if 'Alternate_Terms' in weakness.keys():
            for term in weakness['Alternate_Terms']['Alternate_Term']:
                item['alternateTerms'].append(__map_terms(term))
        
        # Collecting all consequences
        if 'Common_Consequences' in weakness.keys():
            for consequence in weakness['Common_Consequences']['Consequence']:
                item['consequences'].append(__map_consequence(consequence))
        
        # Collecting all detection methods
        if 'Detection_Methods' in weakness.keys():
            for detection in weakness['Detection_Methods']['Detection_Method']:
                item['detectionMethods'].append(__map_detection(detection))
        
        # Collecting all mitigations
        if 'Potential_Mitigations' in weakness.keys():
            for mitigation in weakness['Potential_Mitigations']['Mitigation']:
                item['mitigations'].append(__map_mitigation(mitigation))

        # Collecting functional areas
        if 'Functional_Areas' in weakness.keys():
            for area in weakness['Functional_Areas']['Functional_Area']:
                item['functionalAreas'].append(area)

        # Collecting affected resources
        if 'Affected_Resources' in weakness.keys():
            for res in weakness['Affected_Resources']['Affected_Resource']:
                item['affectedResources'].append(res)
        
        # Collecting taxonomy mappings
        if 'Taxonomy_Mappings' in weakness.keys():
            for tax_map in weakness['Taxonomy_Mappings']['Taxonomy_Mapping']:
                item['taxonomyMapping'].append(__map_taxonomy(tax_map))

        # Collecting related attack patterns
        if 'Related_Attack_Patterns' in weakness.keys():
            for rel in weakness['Related_Attack_Patterns']['Related_Attack_Pattern']:
                item['relatedAttackPatterns'].append(__map_capec_id(rel))
        
        # Collecting references
        if 'References' in weakness.keys():
            for ref in weakness['References']['Reference']:
                item['references'].append(__map_cwe_references(ref))

        # Collapse Values
        item = __collapse_value_for_key(item, 'description')
        item = __collapse_value_for_key(item, 'Example_Code')
        item = __collapse_value_for_key(item, 'Note')

        out['weaknesses'].append(item)
    # end-for
    
    # Updating Catalog CWE count
    out['weaknessCatalog']['cweCount'] = len(out['weaknesses'])

    # Collecting Categories
    out['categories'] = __collect_references(raw_data)

    # Collecting external refs
    out['externalRefs'] = __collect_external_refs(raw_data)

    return out


def __map_cwe(cwe: dict) -> dict:
    weakness_id = cwe['@CWE_ID']
    return {
        'id': f'CWE-{weakness_id}' if '@CWE_ID' in cwe.keys() else None,
        'viewId': cwe['@View_ID'] if '@View_ID' in cwe.keys() else None,
        'nature': cwe['@Nature'] if '@Nature' in cwe.keys() else None,
        'type': cwe['@Ordinal'] if '@Ordinal' in cwe.keys() else None
    }


def __map_platforms(sub_item: dict) -> dict:
    return {
        'name': sub_item['@Name'] if '@Name' in sub_item.keys() else None,
        'class': sub_item['@Class'] if '@Class' in sub_item.keys() else None,
        'prevalance': sub_item['@Prevalence'] if '@Prevalence' in sub_item.keys() else None
    }


def __map_terms(term: dict) -> dict:
    return {
        'name': term['Term'] if 'Term' in term.keys() else None,
        'description': term['Description'] if 'Description' in term.keys() else None 
    }


def __map_consequence(consequence: dict) -> dict:
    return {
        'scope': consequence['Scope'] if 'Scope' in consequence.keys() else None,
        'impact': consequence['Impact'] if 'Impact' in consequence.keys() else None,
        'note': consequence['Note'] if 'Note' in consequence.keys() else None,
    }


def __map_detection(detection: dict) -> dict:
    return {
        'id': detection['@Detection_Method_ID'] if '@Detection_Method_ID' in detection.keys() else None,
        'method': detection['Method'] if 'Method' in detection.keys() else None,
        'description': detection['Description'] if 'Description' in detection.keys() else None,
        'effectiveness': detection['Effectiveness'] if 'Effectiveness' in detection.keys() else None
    }


def __map_mitigation(mitigation: dict) -> dict:
    return {
        'phase': mitigation['Phase'] if 'Phase' in mitigation.keys() else None,
        'description': mitigation['Description'] if 'Description' in mitigation.keys() else None,
        'effectiveness': mitigation['Effectiveness'] if 'Effectiveness' in mitigation.keys() else None,
        'notes': mitigation['Effectiveness_Notes'] if 'Effectiveness_Notes' in mitigation.keys() else None
    }


def __map_taxonomy(tax_map: dict) -> dict:
    return {
        'taxonomyName': tax_map['@Taxonomy_Name'] if '@Taxonomy_Name' in tax_map.keys() else None,
        'entryId': tax_map['Entry_ID'] if 'Entry_ID' in tax_map.keys() else None,
        'entryName': tax_map['Entry_Name'] if 'Entry_Name' in tax_map.keys() else None,
        'mappingFit': tax_map['Mapping_Fit'] if 'Mapping_Fit' in tax_map.keys() else None
    }


def __map_capec_id(rel: dict) -> dict:
    capec_id = rel['@CAPEC_ID']
    return {
        'id': f'CAPEC-{capec_id}'
    }


def __map_cwe_references(ref: dict) -> dict:
    return {
        'externalRefId': ref['@External_Reference_ID'],
        'section': ref['@Section'] if '@Section' in ref.keys() else None
    }


def __collect_references(raw_data: dict) -> list:
    out = []
    for category in raw_data['Weakness_Catalog']['Categories']['Category']:
        item = {
            'id': int(category['@ID']),
            'name': category['@Name'],
            'status': category['@Status'],
            'summary': category['Summary'],
            'relationships': [],
            'references': [],
            'mappingNotes': category['Mapping_Notes'],
            'contentHistory': category['Content_History']
        }
    
        # Collecting category relationships
        if 'Relationships' in category.keys():
            for member in category['Relationships']['Has_Member']:
                item['relationships'].append(__map_category_rel(member))
        
        # Collecting references
        if 'References' in category.keys():
            for ref in category['References']['Reference']:
                item['references'].append(__map_category_references(ref))
        out.append(item)


def __map_category_rel(member: dict) -> dict:
    weakness_id = member['@CWE_ID']
    return {
        'cweId': f'CWE-{weakness_id}',
        'viewId': int(member['@View_ID']) if '@View_ID' in member.keys() else None
    }


def __map_category_references(ref: dict) -> dict:
    return {
        'id': ref['@External_Reference_ID'],
        'section': ref['@Section'] if '@Section' in ref.keys() else None
    }


def __collect_external_refs(raw_data: dict) -> list:
    out = []
    for ext in raw_data['Weakness_Catalog']['External_References']['External_Reference']:
        out.append({
            'refId': ext['@Reference_ID'],
            'author': ext['Author'] if 'Author' in ext.keys() else None,
            'title': ext['Title'] if 'Title' in ext.keys() else None,
            'edition': ext['Edition'] if 'Edition' in ext.keys() else None,
            'publisher': ext['Publisher'] if 'Publisher' in ext.keys() else None,
            'publication': ext['Publication'] if 'Publication' in ext.keys() else None,
            'publicationYear': int(ext['Publication_Year']) if 'Publication_Year' in ext.keys() else None,
            'publicationMonth': int(ext['Publication_Month'].replace('-','')) if 'Publication_Month' in ext.keys() else None,
            'publicationDay': int(ext['Publication_Day'].replace('-','')) if 'Publication_Day' in ext.keys() else None,
            'url': ext['URL'] if 'URL' in ext.keys() else None,
            'urlDate': ext['URL_Date'] if 'URL_Date' in ext.keys() else None
        })
    return out


def __concat_sub_values(data) -> list[str]:
    list_of_string = []
    if isinstance(data, str):
        list_of_string.append(data)
    elif isinstance(data, dict):
        for key, value in data.items():
            if 'style' in key:
                continue
            elif '@' in key and isinstance(value, str): 
                # if the key is an attribute, concatenate the value with the key name
                value = f'{key[1:]}: {value}, '
            list_of_string.extend(__concat_sub_values(value))
    elif isinstance(data, list):
        for item in data:
            list_of_string.extend(__concat_sub_values(item))

    return list_of_string

def __collapse_value_for_key(data, key_to_search_for: str):
    if isinstance(data, dict):
        for key, value in data.items():
            if key_to_search_for.lower() in key.lower():
                concatenated_values = ' '.join(__concat_sub_values(value))
                data[key] = concatenated_values
            else:
                __collapse_value_for_key(value, key_to_search_for)
    elif isinstance(data, list):
        for item in data:
            __collapse_value_for_key(item, key_to_search_for)

    return data
