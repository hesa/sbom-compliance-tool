#!/bin/env python3

# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import logging
import sys

from sbom_compliance_tool.sbom import SBoMReaderFactory
from sbom_compliance_tool.format import SBoMReportFormatterFactory

from licomp.interface import UseCase
from licomp.interface import Provisioning
from licomp.interface import Modification


def main():

    args = get_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    logging.debug("SBoM Compliance Tool")

    reader = SBoMReaderFactory.reader()
    logging.debug(f'Reader: {reader}')

    report = reader.check_file('example-data/normalized-project.json',
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
