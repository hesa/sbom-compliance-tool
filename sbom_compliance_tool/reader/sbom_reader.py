# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
from defusedxml import ElementTree
from enum import Enum

class SBoMComplianceTags(Enum):
    NAME = 'name'
    VERSION = 'version'
    LICENSE = 'license'
    USECASE = 'usecase'
    PROVISIONING = 'provisioning'
    DEPENENCIES = 'dependencies'
    PACKAGES = 'packages'
    SBOM = 'sbom'
    META = 'meta'
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
        logging.debug(f'Reading {file_path} as SPDX')
        with open(file_path, 'r', encoding='utf-8') as fp:
            xml_data = fp.read()
            return ElementTree.fromstring(xml_data, forbid_dtd=True)

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
            'format': 'sbom-compliance-tool',
            'format_version': '0.1',
            'original_format': self.supported_sbom(),
        }

    def _component(self, name, version, licenses, dependencies):
        return {
            SBoMComplianceTags.NAME.value: name,
            SBoMComplianceTags.VERSION.value: version,
            SBoMComplianceTags.LICENSE.value: self.summarize_licenses(licenses),
            SBoMComplianceTags.DEPENENCIES.value: dependencies,
        }

    def _pack_components(self, components):
        return {
            SBoMComplianceTags.META.value: self._meta(),
            SBoMComplianceTags.SBOM.value: {
                SBoMComplianceTags.PACKAGES.value: components,
            },
        }
