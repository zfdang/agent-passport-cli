#!/usr/bin/env python3
#
# Purpose:
#   Enforce minimum region and line coverage thresholds from an llvm-cov summary file.
# Usage:
#   python3 scripts/check_coverage.py <summary-file> <min-region-percent> <min-line-percent>

import pathlib
import re
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: check_coverage.py <summary-file> <min-region-percent> <min-line-percent>",
            file=sys.stderr,
        )
        return 2

    summary_path = pathlib.Path(sys.argv[1])
    min_region = float(sys.argv[2])
    min_line = float(sys.argv[3])
    text = summary_path.read_text()

    match = re.search(
        r"^TOTAL\s+\d+\s+\d+\s+([0-9.]+)%\s+\d+\s+\d+\s+[0-9.]+%\s+\d+\s+\d+\s+([0-9.]+)%",
        text,
        re.MULTILINE,
    )
    if not match:
        print("failed to parse TOTAL coverage line", file=sys.stderr)
        return 1

    region = float(match.group(1))
    line = float(match.group(2))

    print(
        f"coverage summary: regions={region:.2f}% lines={line:.2f}% "
        f"(required: regions>={min_region:.2f}% lines>={min_line:.2f}%)"
    )

    if region < min_region or line < min_line:
        print("coverage gate failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
