# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from sbom_compliance_tool.reader.sbom_reader import SBoMReader

from cyclonedx.model.bom import Bom

class NativeSBoMReader(SBoMReader):

    def normalize_sbom_file(self, filename):
        with open(file_name) as fp:
            print("HER....")
            data = json.load(fp)
            print("HER....")
            assert data['meta']['slsl']
            return self.normalize_sbom_data(data)

    def normalize_sbom_data(self, data):
        self._normalized_sbom = data
        return data

    def normalized_sbom(self):
        return self._normalized_sbom

    def supported_sbom(self):
        return "SBoM Compliance Tool"

    
    
