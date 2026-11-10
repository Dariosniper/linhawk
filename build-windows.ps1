# Build linhawk.exe locally on Windows (PowerShell).
#   Requirements: Python 3.10+ from python.org (with "Add to PATH"), git optional.
#   Usage:  powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
#   Output: dist\linhawk.exe  and  linhawk-<version>-win-x64.zip (exe + SigmaHQ rules)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

python -m venv .venv-build
& .\.venv-build\Scripts\python.exe -m pip install --upgrade pip
& .\.venv-build\Scripts\python.exe -m pip install ".[dev,build]"

# tests (optional but recommended)
& .\.venv-build\Scripts\python.exe tests\generate_samples.py
& .\.venv-build\Scripts\python.exe -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

& .\.venv-build\Scripts\pyinstaller.exe --clean --noconfirm linhawk.spec
if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed" }

& .\dist\linhawk.exe -V

$version = & .\.venv-build\Scripts\python.exe -c "import linhawk;print(linhawk.__version__)"
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
$name = "linhawk-$version-win-$arch"
$pkg = Join-Path "pkg" $name
if (Test-Path $pkg) { Remove-Item -Recurse -Force $pkg }
New-Item -ItemType Directory -Force $pkg | Out-Null
Copy-Item dist\linhawk.exe, README.md, LICENSE $pkg
& .\dist\linhawk.exe update-rules --dest (Join-Path $pkg "rules\sigma")
Compress-Archive -Path $pkg -DestinationPath "$name.zip" -Force
Write-Host "`nBuilt $name.zip"
