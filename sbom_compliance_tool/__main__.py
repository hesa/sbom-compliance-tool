#!/bin/env python3

#!/bin/env python3

# SPDX-FileCopyrightText: 2024 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import RawTextHelpFormatter
import argparse
import logging
import sys

from sbom_compliance_tool.sbom import SBoMReaderFactory
from sbom_compliance_tool.format import SBoMReportFormatterFactory

def main():

    args = get_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    logging.debug("SBoM Compliance Tool")

    reader = SBoMReaderFactory.reader()
    logging.debug(f'Reader: {reader}')
        
    report = reader.check_file('example-data/normalized-project.json')
    logging.debug(f'Report: {report}')

    formatter = SBoMReportFormatterFactory.formatter(args.output_format)
    formatted_report = formatter.format(report)
    
    print(formatted_report)
    

def get_parser():
    parser = argparse.ArgumentParser(prog="sbom-....",
                                     description="",
                                     epilog="",
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-of', '--output-format',
                        type=str,
                        default='json')
    
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        default=False)

    parser.add_argument('-d', '--debug',
                        action='store_true',
                        default=False)

    return parser

def get_args():
    return get_parser().parse_args()


if __name__ == '__main__':
    sys.exit(main())


