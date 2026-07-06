#!/usr/bin/env python3
from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ENTRY = REPO / "src" / "rtdx_save_codec.py"
DIST = REPO / "dist"


def main() -> int:
    pyinstaller = shutil.which("pyinstaller")
    if not pyinstaller:
        print("PyInstaller is not installed. Run: python -m pip install -r requirements-dev.txt", file=sys.stderr)
        return 1

    name = "rtdx-save-codec"

    cmd = [
        pyinstaller,
        "--onefile",
        "--clean",
        "--name",
        name,
        "--collect-all",
        "cryptography",
        str(ENTRY),
    ]
    print(" ".join(cmd))
    subprocess.check_call(cmd, cwd=REPO)
    print(f"Built standalone executable under: {DIST}")
    print("The built file bundles Python and runtime dependencies for this platform.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
