#!/bin/bash
set -e

PLUGIN_SRC="$(dirname "$0")"
PLUGIN_DST="/usr/share/wazuh-dashboard/plugins/wptv"

echo "[1/3] Copiando plugin..."
cp -r "$PLUGIN_SRC" "$PLUGIN_DST"

# Brotli no servidor (se disponível)
if command -v brotli &>/dev/null; then
  brotli -9 -k "$PLUGIN_DST/target/public/wptv.plugin.js"
  echo "      brotli comprimido"
fi

echo "[2/3] Ajustando permissões..."
chown -R wazuh-dashboard:wazuh-dashboard "$PLUGIN_DST"
find "$PLUGIN_DST" -type d -exec chmod 750 {} \;
find "$PLUGIN_DST" -type f -exec chmod 640 {} \;
chmod 750 "$PLUGIN_DST/install.sh"

echo "[3/3] Reiniciando Wazuh Dashboard..."
systemctl restart wazuh-dashboard

echo ""
echo "OK! Acesse o Wazuh Dashboard e procure 'Process Tree' na sidebar (seção Forensics)."
echo "Se não aparecer, aguarde 30s e recarregue a página."
