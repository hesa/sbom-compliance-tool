# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

import json

from licomp_toolkit.toolkit import ExpressionExpressionChecker

class SBoMReaderFactory():

    @staticmethod
    def reader():
        return SBoMReader()

class SBoMReader():

    def __init__(self):
        pass

    def __read(self, file_name):
        with open(file_name) as fp:
            return json.load(fp)

    def update_compat(self, current, new):
        _map = {
            None: 0,
            'yes': 1,
            'mixed': 2,
            'depends': 3,
            'unsupported': 4,
            'no': 5,
        }
        p_current = _map[current]
        p_new = _map[new]
        if p_new > p_current:
            return new
        return current

    def check_data(self, sbom_content, usecase, provisioning, modified):
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
        for dep in sbom_content["dependencies"]:
            inbound = dep["license"]
            dep_compat = compat_checker.check_compatibility(outbound,
                                                            inbound,
                                                            usecase,
                                                            provisioning,
                                                            resources)

            new_dep = dep.copy()
            compat = dep_compat['compatibility']
            new_dep['compatibility'] = compat
            new_dep['compatibility_details'] = dep_compat
            deps.append(new_dep)
            top_compat = self.update_compat(top_compat, compat)

        report['compatibility'] = top_compat
        report['dependencies'] = deps

        return report

    def check_file(self, file_name, usecase, provisioning, modified):
        with open(file_name) as fp:
            return self.check_data(json.load(fp), usecase, provisioning, modified)
