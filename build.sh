#!/usr/bin/env bash
# Build the standalone executable on Linux / macOS.
# Output: dist/linhawk and linhawk-<version>-<os>-<arch>.zip (exe + SigmaHQ rules)
set -euo pipefail
cd "$(dirname "$0")"

python3 -m venv .venv-build
.venv-build/bin/pip install -q --upgrade pip
.venv-build/bin/pip install -q ".[dev,build]"
.venv-build/bin/python tests/generate_samples.py
.venv-build/bin/python -m pytest -q
.venv-build/bin/pyinstaller --clean --noconfirm linhawk.spec
./dist/linhawk -V

version=$(.venv-build/bin/python -c "import linhawk;print(linhawk.__version__)")
os=$([[ "$(uname)" == "Darwin" ]] && echo mac || echo lin)
arch=$(uname -m | sed 's/x86_64/x64/;s/arm64/arm64/;s/aarch64/aarch64/')
name="linhawk-${version}-${os}-${arch}"
rm -rf "pkg/$name" && mkdir -p "pkg/$name"
cp dist/linhawk README.md LICENSE "pkg/$name/"
./dist/linhawk update-rules --dest "pkg/$name/rules/sigma"
(cd pkg && zip -qr "../$name.zip" "$name")
echo "Built $name.zip"
