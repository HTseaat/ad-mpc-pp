#!/usr/bin/env python3
"""Deprecated Figure 9 n=22 hybrid estimator.

Canonical Figure 9 output now accepts only completed local protocol runs for
the selected configuration. Keeping this entry point produces an explicit
diagnostic for older automation instead of silently mixing fitted and measured
communication values.
"""

import argparse


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_root", nargs="?")
    parser.add_argument("--depth", type=int, default=6)
    parser.parse_args(argv)
    parser.exit(
        2,
        "n=22 hybrid estimation is disabled; run "
        "the Figure 9 per-protocol communication runners with n=22 and "
        "summarize "
        "the completed local artifacts instead.\n",
    )


if __name__ == "__main__":
    main()
