# SPDX-FileCopyrightText: 2025 Henrik Sandklef
#
# SPDX-License-Identifier: GPL-3.0-or-later


all:
	@echo done

clean:
	find . -name "*~" | xargs rm -f
	rm -fr sbom_compliance_tool.egg-info
	rm -fr build
	rm -fr dist sdist
	rm -fr sbom_compliance_tool/__pycache__
	rm -fr tests/python/__pycache__
	rm -fr .pytest_cache

.PHONY: build
build:
	rm -fr build && python3 setup.py sdist

lint:
	PYTHONPATH=. flake8 sbom_compliance_tool

