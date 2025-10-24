import json
from xml.etree import ElementTree
from enum import Enum

class SBoMComplianceTags(Enum):
    NAME = 'name'
    VERSION = 'version'
    LICENSE = 'license'
    USECASE = 'usecase'
    DEPENENCIES = 'dependencies'
    LICENSE_OP_AND = 'AND'
    
class SBoMReader:

    def normalize_sbom_file(self, filename):
        return None

    def normalize_sbom_data(self, data):
        return None

    def normalized_sbom(self):
        return None

    def supported_sbom(self):
        return None

    def summarize_licenses(self, licenses):
        return f' {SBoMComplianceTags.LICENSE_OP_AND.value} '.join(licenses)

    def _read_xml(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as fp:
            xml_data = fp.read()
            return ElementTree.fromstring(xml_data)
        
    def _read_json(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as fp:
            data = json.load(fp)
            return data
        
    def _sub_component(self, name, version, usecase, licenses):
        return {
            SBoMComplianceTags.NAME.value: name,
            SBoMComplianceTags.VERSION.value: version,
            SBoMComplianceTags.USECASE.value: usecase,
            SBoMComplianceTags.LICENSE.value: self.summarize_licenses(licenses),
        }
        
    def _meta(self):
        return {
            'format': 'SBoM Compliance Tool',
            'original_format': self.supported_bom(),
        }

    def _component(self, name, version, licenses, dependencies):
        return {
            'meta': self._meta(),
            'sbom': {
                SBoMComplianceTags.NAME.value: name,
                SBoMComplianceTags.VERSION.value: version,
                SBoMComplianceTags.LICENSE.value: self.summarize_licenses(licenses),
                SBoMComplianceTags.DEPENENCIES.value: dependencies
            }
        }

    
