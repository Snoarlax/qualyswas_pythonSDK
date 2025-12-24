import requests
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
from urllib.parse import quote, urlparse
import json
from prettytable import PrettyTable
from lxml import etree
import xml.etree.ElementTree as ET
import os


QUALYS_CREDENTIALS = {
    "username":os.getenv("QUALYS_USERNAME"),
    "password":os.getenv("QUALYS_PASSWORD"),
    "region":os.getenv("QUALYS_REGION")
}

def dict_to_table(results_list, keys):
    table = PrettyTable()
    table.field_names = keys
    # Sort by the left column
    sorted_results = sorted(results_list, key=lambda x: x[table.field_names[0]], reverse=True)
    for result in sorted_results:
        table.add_row([result[key] for key in keys])
    return table

def create_body(criteria_list, verbose=False):
    # takes list of Field, operator value tuples and generates a body of filters to be used within API calls
    root = etree.Element("ServiceRequest")
    if verbose:
        preferences = etree.SubElement(root, "preferences")
        verbose = etree.SubElement(preferences, "verbose")
        verbose.text="true"
    filters = etree.SubElement(root, "filters")
    
    for field, operator, value in criteria_list:
        criteria = etree.SubElement(filters, "Criteria", 
                                  field=field, operator=operator)
        criteria.text = str(value)
    
    return etree.tostring(root, pretty_print=True, 
                         encoding='unicode', xml_declaration=False)

def create_report_body(scan_id):
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<ServiceRequest>
    <data>
        <Report>
            <name>
                <![CDATA[Scan Report for Servers]]>
            </name>
            <format>XML</format>
            <template>
                <id>29069</id>
            </template>
            <config>
                <scanReport>
                    <target>
                        <scans>
                        <WasScan><id>{scan_id}</id></WasScan>
                        </scans>
                    </target>
                </scanReport>
            </config>
        </Report>
    </data>
</ServiceRequest>
"""
    return body

def parse_response(response, keys, pretty_output=True):
    root = ET.fromstring(response.text)
    results = root.find('data')
    if not results:
        return []
    results = results.findall(results[0].tag)
    filtered_results_list = [{elem.tag: elem for elem in result if elem.tag in keys} for result in results]
    for result in filtered_results_list:
        for key in result.keys():
            if key == "tags":
                try:
                    tags_xml = result[key].find("list").findall("Tag")
                    tags = [tag.find("name").text for tag in tags_xml]
                    result[key] = ",".join(tags)
                except Exception as e:
                    print(f"Failed to grab tags: {e}")
                    result[key] = "FAILED"
            elif key == "target":
                try:
                    webApp = result[key].find("webApp").find("name").text
                    result[key] = webApp
                except Exception as e:
                    print(f"Failed to grab webApp: {e}")
                    result[key] = "FAILED"
            else:
                result[key] = result[key].text
    if pretty_output:
        # Convert any timestamps
        """
        if 'startDate' in keys:
            for result in filtered_results_list:
                if 'startDate' in result:
                    unix_timestamp = int(result['startDate']) / 1000
                    result['startDate'] = datetime.utcfromtimestamp(unix_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        """
        print(dict_to_table(filtered_results_list, keys))
    return filtered_results_list

def download_response(response, filename):
    with open(filename, 'wb') as file:
        file.write(response.content)

class QualysRegion(Enum):
    #TODO: fix this with correct urls
    """Qualys platform regions"""
    US1 = "qualysapi.qualys.com"
    US2 = "qualysapi.qg2.apps.qualys.com"
    US3 = "qualysapi.qg3.apps.qualys.com"
    US4 = "qualysapi.qg4.apps.qualys.com"
    EU1 = "qualysapi.qualys.eu"
    EU2 = "qualysapi.qg2.apps.qualys.eu"
    EU3 = "qualysapi.qg3.apps.qualys.it"
    IN1 = "qualysapi.qg1.apps.qualys.in"
    CA1 = "qualysapi.qg1.apps.qualys.ca"
    AE1 = "qualysapi.qg1.apps.qualys.ae"
    UK1 = "qualysapi.qg1.apps.qualys.co.uk"
    AU1 = "qualysapi.qg1.apps.qualys.com.au"
    KSA1 = "qualysapi.qg1.apps.qualysksa.com"


@dataclass
class QualysConfig:
    """Configuration for Qualys API client"""
    username: str
    password: str
    region: QualysRegion
    timeout: int = 30
    verify_ssl: bool = True

class QualysClient:
    """Main Qualys API client"""
    
    def __init__(self, config: QualysConfig):
        self.base_url = f"https://{config.region.value}"
        self.session = requests.Session()
        self.session.verify = config.verify_ssl

    def __send_request(self,endpoint,method="GET",body=None,params=None):
        username = self.config.username
        password = self.config.password
        if method=="GET":
            headers = {
                'Content-Type': 'text/xml',
            }
            response = self.session.get(
                f"{self.base_url}/{endpoint}",
                params=params,
                headers=headers,
                auth=(username, password),
            )
        elif method=="POST":
            headers = {
                'Content-Type': 'text/xml',
            }
            response = self.session.post(
                f"{self.base_url}/{endpoint}",
                data=body,
                headers=headers,
                params=params,
                auth=(username, password),
            )
        else:
            raise Exception(f"Unsupported method: {method}")

        return response


    def authenticate(self):
        username = QUALYS_CREDENTIALS["username"]
        password = QUALYS_CREDENTIALS["password"]

        headers = {
            'Content-Type': 'text/xml',
        }
        response = self.session.post(
            f"{self.base_url}/qps/rest/3.0/search/was/webapp",
            headers=headers,
            auth=(username, password),
        )

        if response.status_code == 200:
            print("Qualys authentication Successful...")
            return True

        print ("Qualys authentication Failed.")
        return False

    def logout(self):
        print("Logout Successful...")
        return True

    def get_qid_details(self, qid):
        # TODO: update this
        criteria = [("qid","EQUALS",f"{qid}")]
        body = create_body(criteria, verbose=True)
        response = self.__send_request("/qps/rest/3.0/search/was/finding/", method="POST", body=body)
        return parse_response(response, ["qid", "name"], pretty_output=False)

    def get_tag_ids(self, tag_name):
        criteria = []
        criteria.append(("name","EQUALS",f"{tag_name}"))
        body = create_body(criteria)
        response = self.__send_request("/qps/rest/2.0/search/am/tag", method="POST", body=body)
        
        return parse_response(response, ["id","name"], pretty_output=False)

    # Web Applications
    def list_webapps(self, filters):
        """List web applications,
        filters: 
            - tag_name
            - URL
        """
        criteria = []
        # takes list of Field, operator value tuples and generates a body of filters to be used within API calls
        if filters.get("tag_name"):
            criteria.append(("tags.name", "CONTAINS", f"{filters['tag_name']}"))
        if filters.get("URL_filter"):
            criteria.append(("url", "CONTAINS", f"{filters['URL_filter']}"))
        if len(criteria):
            body = create_body(criteria, verbose=True)
        else:
            body = ""
        response = self.__send_request("/qps/rest/3.0/search/was/webapp", method="POST", body=body)
        parse_response(response, ["id", "name", "url", "tags"])
    
    def list_was_scans(self, filters):
        #TODO: combine responses before parsing
        criteria = []
        # takes list of Field, operator value tuples and generates a body of filters to be used within API calls
        output = []
        if filters.get("tag_name"):
            tag_ids = self.get_tag_ids(filters['tag_name'])
            for tag in tag_ids:
                tag_criteria = [("webApp.tags.id", "EQUALS", f"{tag['id']}")]
                body = create_body(criteria+tag_criteria)
                response = self.__send_request("/qps/rest/3.0/search/was/wasscan", method="POST", body=body)
                output.append(parse_response(response, ["id", "name", "target", "launchedDate"]))
        else:
            response = self.__send_request("/qps/rest/3.0/search/was/wasscan", method="POST")
            output = [parse_response(response, ["id", "name", "target", "launchedDate"])]
        
        return output

    
    def get_report(self, report_id: int, custom_filename=None):
        """Get Report from report_id"""
        response = self.__send_request(f"/qps/rest/3.0/download/was/report/{report_id}")
        if response.status_code == 200:
            file_location = f"./reports/{custom_filename if custom_filename else report_id}_report.xml"
            print(f"Writing to {file_location}")
            download_response(response, file_location)
        else:
            raise Exception(f"Server Error: {response.status_code}\n{response.content.decode('utf-8')}")

    def create_scan_report(self, scan_id, filename):
        body = create_report_body(scan_id)
        response = self.__send_request("/qps/rest/3.0/create/was/report", method="POST", body=body)
        id = parse_response(response, ["id"])[0]["id"]
        self.get_report(id,custom_filename=filename)

    def mass_create_reports(self, id_filenames):
        print(f"creating and saving {len(id_filenames)} reports...")
        for id, filename in id_filenames:
            self.create_scan_report(id, filename)

    def create_by_tag(self, tag, from_id=0):
        # Flatten the list of was scans
        all_scans = [item for sublist in self.list_was_scans({"tag_name": tag}) for item in sublist]
        reported_scans = []
        for scan in all_scans:
            if int(scan["id"]) >= int(from_id):
                reported_scans.append(scan)
        id_filenames = [(scan["id"], f"{scan["id"]}_{scan["target"]}") for scan in reported_scans]
        self.mass_create_reports(id_filenames)

    
# Utility functions
def create_client() -> QualysClient:
    
    QUALYS_CREDENTIALS["region"] = QualysRegion[QUALYS_CREDENTIALS.get("region")]

    config = QualysConfig(
        **QUALYS_CREDENTIALS
    )

    return QualysClient(config)


