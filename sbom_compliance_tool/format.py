
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
        lines.append(f'## Summary')
        lines.append(f'')
        lines.append(f'## Details')
        lines.append(f'* name {report["name"]}')
        lines.append(f'* version {report["version"]}')
        lines.append(f'* otbound license {report["license"]}')
        lines.append('')
        lines.append(f'### Dependencies ')
        for dep in report['dependencies']:
            lines.append('')
            lines.append(f'#### {dep["name"]}')
            lines.append('')
            lines.append(f'* version: {dep["version"]}')
            lines.append(f'* license: {dep["license"]}')
            lines.append(f'* compatibility: {dep["compatibility"]}')
            lines.append(f'* compatibility details: {json.dumps(dep['compatibility_details']['compatibility_report'], indent=4)}')
            


        return "\n".join(lines)

    
