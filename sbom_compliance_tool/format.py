# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

import json

class SBoMReportFormatterFactory():

    @staticmethod
    def formatter(fmt):
        if fmt.lower() == 'markdown':
            return SBoMReportFormatterMarkdown()
        else:
            return SBoMReportFormatterJson()


class SBoMReportFormatter():

    def format(self, report):
        return None


class SBoMReportFormatterJson(SBoMReportFormatter):

    def format(self, report):
        return json.dumps(report, indent=4)

class SBoMReportFormatterMarkdown(SBoMReportFormatter):

    def _format_package(self, package):
        lines = []
        lines.append(f'## {package["name"]}')
        lines.append(f'')
        lines.append('### Summary')
        lines.append(f'* name: {package["name"]}')
        lines.append(f'* version: {package["version"]}')
        lines.append(f'* otbound license: {package["license"]}')
        lines.append(f'* compatibility: {package["compatibility"]}')
        lines.append('')
        lines.append('### Details')
        lines.append('')
        lines.append('#### Dependencies ')
        for dep in package['dependencies']:
            lines.append('')
            lines.append(f'##### {dep["name"]}')
            lines.append('')
            lines.append(f'* version: {dep["version"]}')
            lines.append(f'* license: {dep["license"]}')
            lines.append(f'* compatibility: {dep["compatibility"]}')
        return "\n".join(lines)
    
    def format(self, report):
        lines = []

        lines.append('# Compliance report')
        lines.append('')
        for package in report['packages']:
            package_report = self._format_package(package)
            lines.append(package_report)

        return "\n".join(lines)
