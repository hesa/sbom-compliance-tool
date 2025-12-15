# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from sbom_compliance_tool.reader.native import NativeSBoMReader
from sbom_compliance_tool.reader.cyclonedx import CyclonedxSBoMReader
from sbom_compliance_tool.reader.spdx import SPDXSBoMReader

class SBoMComplianceTool:

    def __init__(self):
        self._implementations = [NativeSBoMReader, CyclonedxSBoMReader, SPDXSBoMReader]
        self._implementation = None

    def _from_sbom(self, file_path, data):
        for implementation in self._implementations:
            try:
                impl = implementation()
                if file_path:
                    logging.info(f'Reading {file_path} with {implementation}')
                    impl.normalize_sbom_file(file_path)
                    self._implementation = impl
                    return self.normalized_sbom()
                else:
                    logging.info(f'Reading data with {implementation}')
                    impl.normalize_sbom_data(data)
                    self._implementation = impl
                    return self.normalized_sbom()
                if not self._normalized_sbom:
                    raise Exception(f'Failed parsing {file_path}')
            except Exception as e:
                logging.info(f'Failed reading {file_path} with {implementation}. Exception: {e}')

    def supported_formats(self):
        return [impl().supported_sbom() for impl in self._implementations]

    def from_sbom_file(self, file_path):
        return self._from_sbom(file_path, None)

    def from_sbom_data(self, data):
        return self._from_sbom(None, data)

    def normalized_sbom(self):
        return self._implementation.normalized_sbom()
