#!/bin/env python3

from spdx_tools.spdx.parser.parse_anything import parse_file

class SPDXCompliance:

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

        obj = self.objects['packages'].get(spdxid, None)
        if obj:
            return obj.name

        obj = self.objects['files'].get(spdxid, None)
        if obj:
            return obj.name

        return "UNKNOWN - probably TOP DOCUMENT"

    def relations(self, spdxid):
        return (self.rel_map.get(spdxid, []), 
                self.rel_map_inv.get(spdxid, []))

    def spdx_package(self, spdxid):
        return self.objects['packages'][spdxid]

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
            #print("add " + str(fil
            self.objects['files'][fil.spdx_id] = fil

# temp main
spdx = SPDXCompliance('../../spdx/spdx-examples/software/example9/spdx2.2/appbomination.spdx.json')

for p in spdx.packages() + spdx.files():
    print(str(p) + " " + str(spdx.object_name(p)))
    
    rels, inv_rels = spdx.relations(p)
    for spdx1, rel, spdx2 in rels:
        print("       --> " + str(spdx.object_name(spdx2)))

    for spdx1, rel, spdx2 in inv_rels:
        print("       <-- " + str(spdx.object_name(spdx1)))
        
        
        
