#!/bin/env python3

# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import logging
import sys

from sbom_compliance_tool.compliance_tool import SBoMComplianceTool
from sbom_compliance_tool.format import SBoMReportFormatterFactory
from sbom_compliance_tool.format import FORMATS
from sbom_compliance_tool.format import DEFAULT_FORMAT
from sbom_compliance_tool.compatibility import SBoMCompatibility

from licomp.interface import UseCase
from licomp.interface import Provisioning
from licomp.interface import Modification

from sbom_compliance_tool.config import long_description
from sbom_compliance_tool.config import program_name
from sbom_compliance_tool.config import sbom_compliance_tool_version
from sbom_compliance_tool.config import epilog


def main():

    args = get_args()

    if args.version:
        print(sbom_compliance_tool_version)
        sys.exit(0)
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    logging.info("SBoM Compliance Tool")

    compliance = SBoMComplianceTool()
    logging.info(f'Tool: {compliance}')

    logging.info(f'Reading: {args.sbom_file}')
    normalized_sbom = compliance.from_sbom_file(args.sbom_file)

    if not normalized_sbom:
        logging.info(f'Failed normalizing: {args.sbom_file}')
        sys.exit(1)

    logging.info(f'Check compatibility: {args.sbom_file}')
    compatibility = SBoMCompatibility()
    report = compatibility.compatibility_report(normalized_sbom,
                                                UseCase.usecase_to_string(UseCase.LIBRARY),
                                                Provisioning.provisioning_to_string(Provisioning.BIN_DIST),
                                                Modification.modification_to_string(Modification.UNMODIFIED))
    logging.debug(f'Report: {report}')

    formatter = SBoMReportFormatterFactory.formatter(args.output_format)
    formatted_report = formatter.format(report)

    print(formatted_report)


def get_parser():
    parser = argparse.ArgumentParser(prog=program_name,
                                     description=long_description,
                                     epilog=epilog,
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-of', '--output-format',
                        type=str,
                        help=f'The format for the resulting output. Avilable formats: {", ".join(FORMATS)}. Default: {DEFAULT_FORMAT}.',
                        default=DEFAULT_FORMAT)

    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Enable verbose output.',
                        default=False)

    parser.add_argument('-V', '--version',
                        action='store_true',
                        help='Output version number.',
                        default=False)

    parser.add_argument('-d', '--debug',
                        action='store_true',
                        help='Output debug information.',
                        default=False)

    subparsers = parser.add_subparsers(help='Sub commands')
    parser_v = subparsers.add_parser('verify',
                                     help='Verify license compatibility between the licenses for packages in an SBoM.')

    parser_v.add_argument("sbom_file")

    return parser

def get_args():
    return get_parser().parse_args()


if __name__ == '__main__':
    sys.exit(main())
