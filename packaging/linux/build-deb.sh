#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="1.0.0"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
APP="dist/SurgeSignal"
STAGE="$(mktemp -d /tmp/surge-deb.XXXXXX)"

if [[ ! -x "$APP" ]]; then
  echo "Build the Linux binary first: pyinstaller --clean surge_signal_linux.spec" >&2
  exit 1
fi

rm -rf "$STAGE"
mkdir -p "$STAGE/opt/surge-signal"
mkdir -p "$STAGE/usr/share/applications"
mkdir -p "$STAGE/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$STAGE/DEBIAN"

install -m 0755 "$APP" "$STAGE/opt/surge-signal/SurgeSignal"
install -m 0644 packaging/linux/surge-signal.desktop "$STAGE/usr/share/applications/surge-signal.desktop"
install -m 0644 assets/surge-signal-256.png "$STAGE/usr/share/icons/hicolor/256x256/apps/surge-signal.png"

sed "s/^Architecture:.*/Architecture: $ARCH/" packaging/linux/DEBIAN/control > "$STAGE/DEBIAN/control"
SIZE="$(du -sk "$STAGE" | awk '{print $1}')"
sed -i "s/^Installed-Size:.*/Installed-Size: $SIZE/" "$STAGE/DEBIAN/control"

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

mkdir -p installer-output
dpkg-deb --build --root-owner-group "$STAGE" "installer-output/surge-signal_${VERSION}_${ARCH}.deb"
echo "Built installer-output/surge-signal_${VERSION}_${ARCH}.deb"
