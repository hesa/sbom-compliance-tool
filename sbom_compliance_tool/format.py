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

    def format(self, report):
        lines = []

        lines.append('# Compliance report')
        lines.append('')
        lines.append('## Summary')
        lines.append(f'* name: {report["name"]}')
        lines.append(f'* version: {report["version"]}')
        lines.append(f'* otbound license: {report["license"]}')
        lines.append(f'* compatibility: {report["compatibility"]}')
        lines.append('')
        lines.append('## Details')
        lines.append('')
        lines.append('### Dependencies ')
        for dep in report['dependencies']:
            lines.append('')
            lines.append(f'#### {dep["name"]}')
            lines.append('')
            lines.append(f'* version: {dep["version"]}')
            lines.append(f'* license: {dep["license"]}')
            lines.append(f'* compatibility: {dep["compatibility"]}')

        return "\n".join(lines)
