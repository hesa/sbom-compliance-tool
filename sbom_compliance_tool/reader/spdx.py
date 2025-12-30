# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

#
# information mainly picked up here: https://spdx.github.io/spdx-spec/v2.3/
#

import logging

from sbom_compliance_tool.reader.sbom_reader import SBoMReader

from licomp.interface import UseCase
from lookup_license.lookuplicense import LookupLicense

from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.model.relationship import RelationshipType

class SPDXSBoMReader(SBoMReader):

    def __init__(self):
        self.relationship_map_raw = {
            RelationshipType.AMENDS: UseCase.UNKNOWN,
            RelationshipType.ANCESTOR_OF: UseCase.UNKNOWN,
            RelationshipType.BUILD_DEPENDENCY_OF: UseCase.UNKNOWN,
            RelationshipType.BUILD_TOOL_OF: UseCase.UNKNOWN,
            RelationshipType.CONTAINED_BY: UseCase.UNKNOWN,
            RelationshipType.CONTAINS: UseCase.UNKNOWN,
            RelationshipType.COPY_OF: UseCase.UNKNOWN,
            RelationshipType.DATA_FILE_OF: UseCase.UNKNOWN,
            RelationshipType.DEPENDENCY_MANIFEST_OF: UseCase.UNKNOWN,
            RelationshipType.DEPENDENCY_OF: UseCase.LIBRARY,
            RelationshipType.DEPENDS_ON: UseCase.LIBRARY,
            RelationshipType.DESCENDANT_OF: UseCase.UNKNOWN,
            RelationshipType.DESCRIBED_BY: UseCase.UNKNOWN,
            RelationshipType.DESCRIBES: UseCase.UNKNOWN,
            RelationshipType.DEV_DEPENDENCY_OF: UseCase.UNKNOWN,
            RelationshipType.DEV_TOOL_OF: UseCase.UNKNOWN,
            RelationshipType.DISTRIBUTION_ARTIFACT: UseCase.UNKNOWN,
            RelationshipType.DOCUMENTATION_OF: UseCase.UNKNOWN,
            RelationshipType.DYNAMIC_LINK: UseCase.LIBRARY,
            RelationshipType.EXAMPLE_OF: UseCase.UNKNOWN,
            RelationshipType.EXPANDED_FROM_ARCHIVE: UseCase.UNKNOWN,
            RelationshipType.FILE_ADDED: UseCase.UNKNOWN,
            RelationshipType.FILE_DELETED: UseCase.UNKNOWN,
            RelationshipType.FILE_MODIFIED: UseCase.UNKNOWN,
            RelationshipType.GENERATED_FROM: UseCase.UNKNOWN,
            RelationshipType.GENERATES: UseCase.UNKNOWN,
            RelationshipType.HAS_PREREQUISITE: UseCase.LIBRARY,
            RelationshipType.METAFILE_OF: UseCase.UNKNOWN,
            RelationshipType.OPTIONAL_COMPONENT_OF: UseCase.UNKNOWN,
            RelationshipType.OPTIONAL_DEPENDENCY_OF: UseCase.LIBRARY,
            RelationshipType.OTHER: UseCase.UNKNOWN,
            RelationshipType.PACKAGE_OF: UseCase.UNKNOWN,
            RelationshipType.PATCH_APPLIED: UseCase.UNKNOWN,
            RelationshipType.PATCH_FOR: UseCase.UNKNOWN,
            RelationshipType.PREREQUISITE_FOR: UseCase.UNKNOWN,
            RelationshipType.PROVIDED_DEPENDENCY_OF: UseCase.LIBRARY,
            RelationshipType.REQUIREMENT_DESCRIPTION_FOR: UseCase.UNKNOWN,
            RelationshipType.RUNTIME_DEPENDENCY_OF: UseCase.LIBRARY,
            RelationshipType.SPECIFICATION_FOR: UseCase.UNKNOWN,
            RelationshipType.STATIC_LINK: UseCase.LIBRARY,
            RelationshipType.TEST_CASE_OF: UseCase.UNKNOWN,
            RelationshipType.TEST_DEPENDENCY_OF: UseCase.UNKNOWN,
            RelationshipType.TEST_OF: UseCase.UNKNOWN,
            RelationshipType.TEST_TOOL_OF: UseCase.UNKNOWN,
            RelationshipType.VARIANT_OF: UseCase.UNKNOWN,
        }

        self.relationship_map = {
            'AMENDS': UseCase.UNKNOWN,
            'ANCESTOR_OF': UseCase.UNKNOWN,
            'BUILD_DEPENDENCY_OF': UseCase.UNKNOWN,
            'BUILD_TOOL_OF': UseCase.UNKNOWN,
            'CONTAINED_BY': UseCase.UNKNOWN,
            'CONTAINS': UseCase.UNKNOWN,
            'COPY_OF': UseCase.UNKNOWN,
            'DATA_FILE_OF': UseCase.UNKNOWN,
            'DEPENDENCY_MANIFEST_OF': UseCase.UNKNOWN,
            'DEPENDENCY_OF': UseCase.LIBRARY,
            'DEPENDS_ON': UseCase.LIBRARY,
            'DESCENDANT_OF': UseCase.UNKNOWN,
            'DESCRIBED_BY': UseCase.UNKNOWN,
            'DESCRIBES': UseCase.UNKNOWN,
            'DEV_DEPENDENCY_OF': UseCase.UNKNOWN,
            'DEV_TOOL_OF': UseCase.UNKNOWN,
            'DISTRIBUTION_ARTIFACT': UseCase.UNKNOWN,
            'DOCUMENTATION_OF': UseCase.UNKNOWN,
            'DYNAMIC_LINK': UseCase.LIBRARY,
            'EXAMPLE_OF': UseCase.UNKNOWN,
            'EXPANDED_FROM_ARCHIVE': UseCase.UNKNOWN,
            'FILE_ADDED': UseCase.UNKNOWN,
            'FILE_DELETED': UseCase.UNKNOWN,
            'FILE_MODIFIED': UseCase.UNKNOWN,
            'GENERATED_FROM': UseCase.UNKNOWN,
            'GENERATES': UseCase.UNKNOWN,
            'HAS_PREREQUISITE': UseCase.LIBRARY,
            'METAFILE_OF': UseCase.UNKNOWN,
            'OPTIONAL_COMPONENT_OF': UseCase.UNKNOWN,
            'OPTIONAL_DEPENDENCY_OF': UseCase.LIBRARY,
            'OTHER': UseCase.UNKNOWN,
            'PACKAGE_OF': UseCase.UNKNOWN,
            'PATCH_APPLIED': UseCase.UNKNOWN,
            'PATCH_FOR': UseCase.UNKNOWN,
            'PREREQUISITE_FOR': UseCase.UNKNOWN,
            'PROVIDED_DEPENDENCY_OF': UseCase.LIBRARY,
            'REQUIREMENT_DESCRIPTION_FOR': UseCase.UNKNOWN,
            'RUNTIME_DEPENDENCY_OF': UseCase.LIBRARY,
            'SPECIFICATION_FOR': UseCase.UNKNOWN,
            'STATIC_LINK': UseCase.LIBRARY,
            'TEST_CASE_OF': UseCase.UNKNOWN,
            'TEST_DEPENDENCY_OF': UseCase.UNKNOWN,
            'TEST_OF': UseCase.UNKNOWN,
            'TEST_TOOL_OF': UseCase.UNKNOWN,
            'VARIANT_OF': UseCase.UNKNOWN,
        }

    def _relationship_to_usecase(self, relationship):
        logging.debug(f'Finding usecase for {relationship}')
        # crash if relationship is missing
        usecase = self.relationship_map[relationship]
        return UseCase.usecase_to_string(usecase)

    def _normalize_sub_package(self, parsed_doc, spdx1, rel, spdx2, inverted=False):
        p_name = parsed_doc.object_name(spdx2)
        p_version = parsed_doc.object_version(spdx2)
        p_license = parsed_doc.object_license(spdx2)
        p_usecase = self._relationship_to_usecase(rel)
        ret = self._sub_component(p_name,
                                  p_version,
                                  p_usecase,
                                  [str(p_license)])

        return ret

    def _normalize_package(self, parsed_doc, package):
        relations, relations_inv = parsed_doc.relations(package)
        packages = []
        for spdx1, rel, spdx2 in relations:
            if spdx2.startswith('SPDXRef-DOCUMENT'):
                continue
            packages.append(self._normalize_sub_package(parsed_doc, spdx1, rel, spdx2))
        for spdx1, rel, spdx2 in relations_inv:
            if spdx1.startswith('SPDXRef-DOCUMENT'):
                continue
            packages.append(self._normalize_sub_package(parsed_doc, spdx2, rel, spdx1))

        packed_component = self._component(parsed_doc.object_name(package),
                                           parsed_doc.object_version(package),
                                           [],
                                           packages)
        return packed_component

    def normalize_sbom_file(self, file_path):
        logging.info(f'Reading {file_path} as SPDX')
        parsed = ParsedSPDXDoc(file_path)
        logging.info(f'Reading {file_path} as SPDX: parse OK')

        packages = []
        for package in parsed.packages():
            normalized_package = self._normalize_package(parsed, package)
            packages.append(normalized_package)

        top_components = self._pack_components(packages)
        self._normalized_sbom = top_components
        return self._normalized_sbom

    def normalize_sbom_data(self, data):
        return None

    def normalized_sbom(self):
        return self._normalized_sbom

    def supported_sbom(self):
        return "SPDX"

class ParsedSPDXDoc:

    def __init__(self, file_path):
        self.rel_map = {}
        self.rel_map_inv = {}
        self.objects = {
            'packages': {},
            'files': {},
            'extracted_text': {},
        }
        self.ll = LookupLicense()
        self._read_spdx_sbom(file_path)

    def _read_spdx_sbom(self, file_path):
        self.doc = parse_file(file_path)
        self._update_relationships()
        self._update_objects()

    def object_name(self, spdxid):
        obj = self.object(spdxid)
        if not obj:
            return "UNKNOWN - probably TOP DOCUMENT"
        return obj.name

    def object_version(self, spdxid):
        try:
            obj = self.object(spdxid)
            if not obj:
                return "missing"
            return obj.version
        except Exception as e:
            logging.debug(f'Failed getting version for {spdxid}. Exception: {e}')

        return ''

    def _lookup_extracted_text(self, license_id):
        """lookup license, provided as extracted license text in the
        SBoM, in the objects dict"""
        try:
            return self.objects['extracted_text'][license_id]
        except Exception as e:
            logging.debug(f'_lookup_extracted_text raised an exception: {e}')
            return None

    def object_license(self, spdxid):
        obj = self.object(spdxid)

        if not obj:
            return "missing"

        try:
            license_concluded = str(obj.license_concluded)
            if license_concluded != 'NOASSERTION':
                if str(obj.license_concluded).startswith('LicenseRef'):
                    lookedup = self._lookup_extracted_text(str(obj.license_concluded))
                    if lookedup:
                        return lookedup

                return obj.license_concluded
        except Exception as e:
            logging.debug(f'object_licens raised an exception: {e}')
        license_declared = str(obj.license_declared)
        if license_declared != 'NOASSERTION':
            if license_declared.startswith('LicenseRef'):
                lookedup = self._lookup_extracted_text(license_declared)
                if lookedup:
                    return lookedup
            return license_declared

        logging.debug(f'Failed getting license for {spdxid}, returning empty string')
        return ''

    def object(self, spdxid):

        obj = self.objects['packages'].get(spdxid, None)
        if obj:
            return obj

        obj = self.objects['files'].get(spdxid, None)
        if obj:
            return obj

        return None

    def relations(self, spdxid):
        return (self.rel_map.get(spdxid, []),
                self.rel_map_inv.get(spdxid, []))

    def spdx_file(self, spdxid):
        return self.objects['files'][spdxid]

    def packages(self):
        return list(self.objects['packages'].keys())

    def files(self):
        return list(self.objects['files'].keys())

    def _update_rel_maps(self, spdx1, rel, spdx2):
        if spdx1 not in self.rel_map:
            self.rel_map[spdx1] = []
        self.rel_map[spdx1].append((spdx1, rel, spdx2))

        if spdx2 not in self.rel_map_inv:
            self.rel_map_inv[spdx2] = []
        self.rel_map_inv[spdx2].append((spdx1, rel, spdx2))

    def _update_relationships(self):
        for rel in self.doc.relationships:
            self._update_rel_maps(rel.spdx_element_id,
                                  rel.relationship_type.name,
                                  rel.related_spdx_element_id)

    def _update_objects(self):
        for pkg in self.doc.packages:
            self.objects['packages'][pkg.spdx_id] = pkg

        for fil in self.doc.files:
            self.objects['files'][fil.spdx_id] = fil

        for snippet in self.doc.snippets:
            self.objects['snippets'][snippet.spdx_id] = snippet

        try:
            for lic in self.doc.extracted_licensing_info:
                lookedup = self.ll.lookup_license_text(lic.extracted_text)
                identification = lookedup['identification']
                if identification == 'flame':
                    normalized_license = ' AND '.join(lookedup['normalized'])
                else:
                    normalized_license = ' AND '.join([x['license'] for x in lookedup['normalized']])
                self.objects['extracted_text'][lic.license_id] = normalized_license

        except Exception as e:
            logging.debug(f'Updating objects raised an exception: {e}')

    def normalized_sbom(self):
        return self._normalized_sbom

    def supported_bom(self):
        return "SPDX"
