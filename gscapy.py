#!/usr/bin/env python3
import sys
import os

# Add the package directory to the Python path to ensure relative imports work
# when running this script as the entry point.
# This makes the gscapy/ folder a package that can be imported from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gscapy.main import main

if __name__ == "__main__":
    main()
