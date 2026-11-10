# PyInstaller spec: single-file console executable with bundled LinHawk rules.
#   pyinstaller --clean --noconfirm linhawk.spec
# Output: dist/linhawk(.exe)
import sys
from PyInstaller.utils.hooks import collect_data_files

datas = [("linhawk/rules", "linhawk/rules")]
hiddenimports = []
try:  # IANA timezone database (Windows has none)
    datas += collect_data_files("tzdata")
    hiddenimports.append("tzdata")
except Exception:
    pass

a = Analysis(
    ["packaging/linhawk_entry.py"],
    pathex=["."],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "unittest", "pydoc", "pytest", "test"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="linhawk",
    console=True,
    upx=False,
    strip=False,
    version="packaging/version_info.txt" if sys.platform == "win32" else None,
    icon=None,
)
