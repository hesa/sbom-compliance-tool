import json

from licomp_toolkit.toolkit import ExpressionExpressionChecker

from licomp.interface import UseCase
from licomp.interface import Provisioning


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
            'no': 2,
            'depends': 3,
        }
        p_current = _map[current]
        p_new = _map[new]
        if p_new > p_current:
            return new
        return current

    def check_data(self, sbom_content):
        outbound = sbom_content["license"]
        report = {
            'name': sbom_content["name"],
            'version': sbom_content["version"],
            'license': outbound,
        }

        compat_checker = ExpressionExpressionChecker()
        deps = []
        top_compat = None
        for dep in sbom_content["dependencies"]:
            inbound = dep["license"]
            dep_compat = compat_checker.check_compatibility(outbound,
                                                            inbound,
                                                            UseCase.usecase_to_string(UseCase.LIBRARY),
                                                            Provisioning.provisioning_to_string(Provisioning.BIN_DIST))
            
            new_dep = dep.copy()
            compat = dep_compat['compatibility']
            new_dep['compatibility'] = compat
            new_dep['compatibility_details'] = dep_compat
            deps.append(new_dep)
            top_compat = self.update_compat(top_compat, compat)
#            print("compat: " + str(compat) + "   --> " + str(top_compat))
            
        report['compatibility'] = top_compat
        report['dependencies'] = deps

        return report
        
        
    def check_file(self, file_name):
        with open(file_name) as fp:
            return self.check_data(json.load(fp))
        
