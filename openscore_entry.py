"""Entry point used by PyInstaller to build the standalone openscore.exe / openscore binary."""
import sys

from openscore.cli import main

if __name__ == "__main__":
    sys.exit(main())
