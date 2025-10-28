# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

#
# information mainly picked up here: https://spdx.github.io/spdx-spec/v2.3/
#

import logging

from sbom_compliance_tool.reader.sbom_reader import SBoMReader

from licomp.interface import UseCase

from spdx_tools.spdx.parser.parse_anything import parse_file

class SPDXSBoMReader(SBoMReader):

    def __init__(self):
        self.relationship_map = {
            '': UseCase.usecase_to_string(UseCase.LIBRARY),
            'snippet': UseCase.usecase_to_string(UseCase.SNIPPET),
        }

    def _relationship_to_usecase(self, classification):
        return self.relationship_map.get(classification, 'library')

    def _normalize_sub_package(self, parsed_doc, spdx1, rel, spdx2, inverted=False):
        print("    |---> " + str(spdx2))
        p_name = parsed_doc.object_name(spdx2)
        p_version = parsed_doc.object_version(spdx2)
        p_license = parsed_doc.object_license(spdx2)
        p_usecase = self._relationship_to_usecase(rel)
        ret = self._sub_component(p_name,
                                  p_version,
                                  p_usecase,
                                  [str(p_license)])

#        print(str(ret))
        return ret
        
    def _normalize_package(self, parsed_doc, package):
        print(f' * {package} "{parsed_doc.object_name(package)}"')
        relations, relations_inv = parsed_doc.relations(package)
        packages = []
        for spdx1, rel, spdx2 in relations:
            packages.append(self._normalize_sub_package(parsed_doc, spdx1, rel, spdx2))
        for spdx1, rel, spdx2 in relations_inv:
            packages.append(self._normalize_sub_package(parsed_doc, spdx1, rel, spdx2, inverted=True))
            #print("     <--- " + str(relation))

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
            packages.append(self._normalize_package(parsed, package))
        print("done")

        top_components = self._pack_components(packages)
        self._normalized_sbom = top_components
        #print("THIS: " + str(top_components))
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
        }
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
            logging.debug(f'Failed getting version for {spdxid}')

        return ''

    def object_license(self, spdxid):
        obj = self.object(spdxid)
        if not obj:
            return "missing"

        try:
            return obj.license_concluded
        except Exception as e:
            logging.debug(f'Failed getting license_concluded for {spdxid}')

        try:
            return obj.license_declared
        except Exception as e:
            logging.debug(f'Failed getting license_declared for {spdxid}')

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

    def normalized_sbom(self):
        return self._normalized_sbom

    def supported_bom(self):
        return "SPDX"


if False:
    # temp main
    spdx = ParsedSPDXDoc('../../spdx/spdx-examples/software/example9/spdx2.2/appbomination.spdx.json')

    for p in spdx.packages() + spdx.files():
        print(str(p) + " " + str(spdx.object_name(p)))

        rels, inv_rels = spdx.relations(p)
        for spdx1, rel, spdx2 in rels:
            print("       --> " + str(spdx.object_name(spdx2)))

        for spdx1, rel, spdx2 in inv_rels:
            print("       <-- " + str(spdx.object_name(spdx1)))
        
        
        
