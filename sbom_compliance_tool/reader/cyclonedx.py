# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

# information mainly picked up here: https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf

import logging

from sbom_compliance_tool.reader.sbom_reader import SBoMReader

from licomp.interface import UseCase

from cyclonedx.model.bom import Bom

class CyclonedxSBoMReader(SBoMReader):

    def __init__(self):
        self._normalized_sbom = None
        self.classification_map = {
            'library': UseCase.usecase_to_string(UseCase.LIBRARY),
        }

    def _classification_to_usecase(self, classification):
        return self.classification_map.get(classification, 'library')

    def normalize_sbom_file(self, file_path):

        try:
            data = self._read_xml(file_path)
            return self.normalize_sbom_data(data, 'xml')
        except Exception as e:
            logging.debug(f'tried and failed reading {file_path} as XML. Exception {e}')

        try:
            data = self._read_json(file_path)
            return self.normalize_sbom_data(data, 'json')
        except Exception as e:
            logging.debug(f'tried and failed reading {file_path} as JSON. Exception {e}')

    def _license(self, lic):
        if lic.id:
            return lic.id
        elif lic.name:
            return lic.name


    def _component_license(self, component):
        try:
            licenses = [self._license(lic) for lic in component.licenses]
            return licenses
        except Exception as e:
            logging.debug(f'Failed readinf "licenses" from "{component}"')
        return []
        
        
    def normalize_sbom_data(self, data, sbom_format='json'):
        if sbom_format == 'json':
            deserialized_bom = Bom.from_json(data=data)
        elif sbom_format == 'xml':
            deserialized_bom = Bom.from_xml(data=data)

        components = []
        for component in deserialized_bom.components:
            components.append(self._sub_component(component.name,
                                                  component.version,
                                                  self._classification_to_usecase(component.type),
                                                  self._component_license(component)))

        licenses = [self._license(lic) for lic in deserialized_bom.metadata.component.licenses]
        try:
            packed_component = self._component(deserialized_bom.metadata.component.name,
                                               deserialized_bom.metadata.component.version,
                                               licenses,
                                               components)
        except Exception as e:
            return None

        top_components = self._pack_components([packed_component])
        
        self._normalized_sbom = top_components
#        print(str(self._normalized_sbom))
        return self._normalized_sbom

    def normalized_sbom(self):
        if not self._normalized_sbom:
            raise Exception(f'Failed reading SBoM data, not in CycloneDX format')
        return self._normalized_sbom

    def supported_sbom(self):
        return "CycloneDX"
