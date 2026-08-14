#!/bin/bash
set -e

PLUGIN_SRC="$(dirname "$0")"
PLUGIN_DST="/usr/share/wazuh-dashboard/plugins/wptv"

echo "[1/3] Copying plugin..."
cp -r "$PLUGIN_SRC" "$PLUGIN_DST"

# Brotli compression (if available)
if command -v brotli &>/dev/null; then
  brotli -9 -k "$PLUGIN_DST/target/public/wptv.plugin.js"
  echo "      brotli compressed"
fi

echo "[2/3] Setting permissions..."
chown -R wazuh-dashboard:wazuh-dashboard "$PLUGIN_DST"
find "$PLUGIN_DST" -type d -exec chmod 750 {} \;
find "$PLUGIN_DST" -type f -exec chmod 640 {} \;
chmod 750 "$PLUGIN_DST/install.sh"

echo "[3/3] Restarting Wazuh Dashboard..."
systemctl restart wazuh-dashboard

echo ""
echo "Done! Open the Wazuh Dashboard and look for 'Wazuh Process Tree Viewer' in the sidebar under Forensics."
echo "If it does not appear, wait 30 seconds and reload the page."
