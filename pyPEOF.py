"""Root entry point for backward compatibility.

Allows running:
    python pyPEOF.py -f sample.exe [options]
"""

from pypeof.cli import main

if __name__ == "__main__":
    main()
