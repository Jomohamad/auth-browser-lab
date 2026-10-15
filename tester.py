#!/usr/bin/env python3
# Signed by JOE
"""Authorized Authentication Testing Tool — CLI entry point.

This thin wrapper delegates to :mod:`auth_audit.cli` so all command/option
logic, exit codes, and help text live in one place. Run ``python tester.py
--help`` for the full command reference.
"""

import sys

from auth_audit.cli import main


if __name__ == "__main__":
    sys.exit(main())
