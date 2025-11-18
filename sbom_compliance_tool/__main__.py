#!/bin/env python3

# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import logging
import sys

from sbom_compliance_tool.compliance_tool import SBoMComplianceTool
from sbom_compliance_tool.format import SBoMReportFormatterFactory
from sbom_compliance_tool.compatibility import SBoMCompatibility

from licomp.interface import UseCase
from licomp.interface import Provisioning
from licomp.interface import Modification


def main():

    args = get_args()

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
    parser = argparse.ArgumentParser(prog="sbom-....",
                                     description="",
                                     epilog="",
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("sbom_file")

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
