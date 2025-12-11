#!/usr/bin/env python3
# coding=utf-8

"""
Simple Dell PFS extractor wrapper for DellBIOSTools.

This wraps DellPfsExtract into a user-friendly function that can be
called from:

• CLI
• Tkinter GUI
• DellBIOSTools automation modules

Place this file in:
vendor/dell_pfs_extract/dell_pfs_simple.py
"""

import os
import sys
import argparse

# Import DellPfsExtract from the same directory
from .dell_pfs_extract import DellPfsExtract


def run_pfs_extract(input_path: str,
                    output_dir: str | None = None,
                    advanced: bool = False,
                    quiet: bool = False) -> int:
    """
    Run a simplified Dell PFS extraction.

    :param input_path: Path to a Dell update EXE/HDR/PKG or raw PFS image.
    :param output_dir: Optional output folder (default: <file>_PFS).
    :param advanced:   Keep signatures & metadata (default: False).
    :param quiet:      Suppress console prints (useful for GUI calls).
    :return: 0 on success, non-zero on failure.
    """

    # Validate file
    if not os.path.isfile(input_path):
        if not quiet:
            print(f"[!] Input file not found: {input_path}")
        return 1

    # Determine output folder
    if output_dir is None:
        base_name = os.path.splitext(os.path.basename(input_path))[0]
        output_dir = os.path.join(os.getcwd(), f"{base_name}_PFS")

    os.makedirs(output_dir, exist_ok=True)

    if not quiet:
        print(f"[*] Input : {input_path}")
        print(f"[*] Output: {output_dir}")
        print(f"[*] Mode  : {'advanced' if advanced else 'simple'}")

    extractor = DellPfsExtract(
        input_object=input_path,
        extract_path=output_dir,
        padding=0,
        advanced=advanced,
        structure=False,   # GUI-friendly output
    )

    # Check format
    if not extractor.check_format():
        if not quiet:
            print("[!] This file does NOT appear to be a Dell PFS/PKG image.")
        return 2

    # Extract
    try:
        ok = extractor.parse_format()
    except Exception as e:  # noqa: BLE001
        if not quiet:
            print(f"[!] Extraction failed: {e}")
        return 3

    if not ok:
        if not quiet:
            print("[!] Parse returned failure.")
        return 4

    if not quiet:
        print("[+] Extraction completed successfully.")
        print("[+] Firmware components saved in output folder.")

    return 0


def cli_main() -> None:
    """ Command-line entry point. """
    parser = argparse.ArgumentParser(
        description="Simple Dell PFS extractor (DellBIOSTools vendor module)"
    )
    parser.add_argument("input_file",
                        help="Dell BIOS EXE/HDR/PKG or raw PFS file")
    parser.add_argument("-o", "--output", dest="output_dir", default=None,
                        help="Output directory (default: <file>_PFS)")
    parser.add_argument("--advanced", action="store_true",
                        help="Include all signatures & metadata")
    args = parser.parse_args()

    code = run_pfs_extract(
        input_path=args.input_file,
        output_dir=args.output_dir,
        advanced=args.advanced,
        quiet=False
    )

    sys.exit(code)


if __name__ == "__main__":
    cli_main()
