#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ ! -x dist/SurgeSignal ]]; then
  echo "Build the Linux binary first: pyinstaller --clean surge_signal_linux.spec" >&2
  exit 1
fi

APPDIR="$ROOT/build/SURGE-Signal.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
  "$APPDIR/usr/share/icons/hicolor/256x256/apps"

install -m 0755 dist/SurgeSignal "$APPDIR/usr/bin/SurgeSignal"
install -m 0644 packaging/linux/surge-signal.desktop "$APPDIR/usr/share/applications/"
install -m 0644 assets/surge-signal-256.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/surge-signal.png"

cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/SurgeSignal" "$@"
EOF
chmod 0755 "$APPDIR/AppRun"
cp packaging/linux/surge-signal.desktop "$APPDIR/surge-signal.desktop"

if ! command -v appimagetool >/dev/null 2>&1; then
  echo "appimagetool is required. Download it from https://github.com/AppImage/AppImageKit/releases" >&2
  exit 1
fi

mkdir -p installer-output
ARCH=x86_64 appimagetool "$APPDIR" "installer-output/SURGE-Signal-1.0.0-x86_64.AppImage"
echo "Built installer-output/SURGE-Signal-1.0.0-x86_64.AppImage"
