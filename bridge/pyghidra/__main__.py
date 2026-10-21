"""REA pyGhidra bridge entry point.

Usage: python <path>/__main__.py <descriptor-path> <target-path>
"""
import json
import os
import sys

# Bridge modules are siblings of this file; python -I does not add the script directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <descriptor-path> <target-path>",
            file=sys.stderr,
        )
        sys.exit(1)

    descriptor_path = sys.argv[1]
    target_path = sys.argv[2]

    with open(descriptor_path, "r", encoding="utf-8") as f:
        descriptor = json.load(f)

    from rea_pyghidra_bridge import run_bridge

    run_bridge(descriptor, descriptor_path, target_path)


if __name__ == "__main__":
    main()
