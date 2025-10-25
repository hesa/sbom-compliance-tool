# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

from licomp_toolkit.toolkit import ExpressionExpressionChecker
from flame.license_db import FossLicenses

class SBoMCompatibility():

    def __init__(self):
        self.flame = FossLicenses()

    def update_compat(self, current, new):
        _map = {
            None: 0,
            'yes': 1,
            'mixed': 2,
            'depends': 3,
            'unsupported': 4,
            'no': 5,
            'missing-license': 6,
        }
        p_current = _map[current]
        p_new = _map[new]
        if p_new > p_current:
            return new
        return current

    def compatibility_report(self, sbom, usecase, provisioning, modified):
        sbom_content = sbom['sbom']
        outbound = sbom_content["license"]
        report = {
            'name': sbom_content["name"],
            'version': sbom_content["version"],
            'license': outbound,
        }

        resources = ['licomp_reclicense', 'licomp_osadl', 'licomp_proprietary']
        compat_checker = ExpressionExpressionChecker()
        deps = []
        top_compat = None
        for dep in sbom_content['dependencies']:
            inbound = dep['license']
            usecase = dep.get('usecase', usecase)
            if inbound:
                dep_compat = compat_checker.check_compatibility(self.flame.expression_license(outbound, update_dual=False)['identified_license'],
                                                                self.flame.expression_license(inbound, update_dual=False)['identified_license'],
                                                                usecase,
                                                                provisioning,
                                                                resources)
            else:
                dep_compat = {
                    'compatibility': 'missing-license',
                }

            new_dep = dep.copy()
            compat = dep_compat['compatibility']
            new_dep['compatibility'] = compat
            new_dep['compatibility_details'] = dep_compat
            deps.append(new_dep)
            top_compat = self.update_compat(top_compat, compat)

        report['compatibility'] = top_compat
        report['dependencies'] = deps

        return report
