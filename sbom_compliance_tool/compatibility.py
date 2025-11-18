# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

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

    def _identify_license(self, lic):
        try:
            return self.flame.expression_license(lic, update_dual=False)['identified_license']
        except Exception:
            logging.debug('Could not identify license using flame, returning input.')
            return lic

    def _package_compatibility_report(self, package, usecase, provisioning, modified):
        outbound = package["license"]
        report = {
            'name': package["name"],
            'version': package["version"],
            'license': outbound,
        }

        resources = ['licomp_reclicense', 'licomp_osadl', 'licomp_proprietary']
        compat_checker = ExpressionExpressionChecker()
        deps = []
        top_compat = None
        for dep in package['dependencies']:
            inbound = dep['license']
            usecase = dep.get('usecase', usecase)
            if inbound:
                dep_compat = compat_checker.check_compatibility(self._identify_license(outbound),
                                                                self._identify_license(inbound),
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

    def compatibility_report(self, sbom, usecase, provisioning, modified):
        sbom_content = sbom['sbom']
        sbom_packages = sbom_content['packages']

        packages_report = []
        for s_pkg in sbom_packages:
            package_report = self._package_compatibility_report(s_pkg, usecase, provisioning, modified)
            packages_report.append(package_report)

        return {
            'packages': packages_report,
        }
