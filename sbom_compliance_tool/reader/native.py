# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

import json

from sbom_compliance_tool.reader.sbom_reader import SBoMReader

class NativeSBoMReader(SBoMReader):

    def normalize_sbom_file(self, file_path):
        with open(file_path) as fp:
            data = json.load(fp)
            if data['meta']['format'] != 'sbom-compliance-tool':
                raise Exception(f'{file_path} not in SBoM Compliance Tool\'s native format')
            return self.normalize_sbom_data(data)

    def normalize_sbom_data(self, data):
        self._normalized_sbom = data
        return data

    def normalized_sbom(self):
        return self._normalized_sbom

    def supported_sbom(self):
        return "SBoM Compliance Tool"
