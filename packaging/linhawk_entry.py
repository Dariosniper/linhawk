"""PyInstaller entry point (linhawk.exe / linhawk)."""
import multiprocessing
import sys

from linhawk.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
