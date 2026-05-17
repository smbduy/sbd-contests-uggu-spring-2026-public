#!/usr/bin/env bash
# Формирует каталог artifacts/cert_bundle и архив artifacts/abu_certification_bundle.tar.gz
# для последующей подачи в Регулятор.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/artifacts/cert_bundle"
mkdir -p "$ROOT/artifacts"
rm -rf "$OUT"
mkdir -p "$OUT"

# CycloneDX для ДВБ и прочих зависимостей: из манифеста docs/sbom_manifest.json
# (правьте манифест и см. docs/sbom_guide.md).
(cd "$ROOT" && pipenv run python scripts/generate_sbom_cdx.py)

cp -a "$ROOT/src_starting_point" "$OUT/source"
mkdir -p "$OUT/sbom"
mkdir -p "$OUT/security"
cp "$ROOT/docs/examples/SBOM_TCB.cdx.json" "$OUT/sbom/SBOM_TCB.cdx.json"
cp "$ROOT/docs/examples/SBOM_OTHER.cdx.json" "$OUT/sbom/SBOM_OTHER.cdx.json"
# Совместимость: агрегированный SBOM (не используется Регулятором v2 при наличии TCB/OTHER)
cp "$ROOT/docs/examples/abu_sbom.cdx.json" "$OUT/sbom/sbom.cdx.json"
cp "$ROOT/docs/examples/sga.json" "$OUT/security/sga.json"
VERSION="${VERSION:-0.1.0}"
cat > "$OUT/manifest.json" <<EOF
{
  "version": "${VERSION}",
  "package_name": "abu-starting-point",
  "tests_root": "tests",
  "python_requirements": "requirements.txt",
  "source_subdir": "source"
}
EOF
tar -czf "$ROOT/artifacts/abu_certification_bundle.tar.gz" -C "$ROOT/artifacts" cert_bundle
echo "Пакет: $ROOT/artifacts/abu_certification_bundle.tar.gz"
