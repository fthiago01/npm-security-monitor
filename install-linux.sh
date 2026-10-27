
#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${1:-}"
INSTALL_DIR="${NPM_MONITOR_INSTALL_DIR:-$HOME/.local/share/npm-security-monitor}"
BIN_DIR="${NPM_MONITOR_BIN_DIR:-$HOME/.local/bin}"

if [[ -z "$REPO_URL" ]]; then
    echo "Uso: $0 https://raw.githubusercontent.com/USUARIO/REPOSITORIO/main"
    exit 1
fi

REPO_URL="${REPO_URL%/}"

for cmd in curl install; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Erro: comando obrigatório não encontrado: $cmd"
        exit 1
    fi
done

mkdir -p "$INSTALL_DIR" "$BIN_DIR"
chmod 700 "$INSTALL_DIR"

download_file() {
    local name="$1"
    local destination="$2"
    local tmp

    tmp="$(mktemp)"

    echo "Baixando $name..."
    if ! curl --fail --silent --show-error --location \
        --connect-timeout 15 --max-time 120 \
        "$REPO_URL/$name" -o "$tmp"; then
        rm -f "$tmp"
        echo "Erro ao baixar $name" >&2
        exit 1
    fi

    if [[ ! -s "$tmp" ]]; then
        rm -f "$tmp"
        echo "Erro: arquivo vazio: $name" >&2
        exit 1
    fi

    install -m 600 "$tmp" "$destination"
    rm -f "$tmp"
}

download_file "npm-security-monitor.sh" \
    "$INSTALL_DIR/npm-security-monitor.sh"

chmod 700 "$INSTALL_DIR/npm-security-monitor.sh"

# Configuração local: não baixa nem sobrescreve credenciais.
CONFIG_FILE="$INSTALL_DIR/.env"

if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" <<'EOF'
# Configure ao menos Telegram ou webhook para receber alertas.
# Não compartilhe este arquivo.

# TELEGRAM_BOT_TOKEN=
# TELEGRAM_CHAT_ID=
# WEBHOOK_URL=

# Diretórios separados por dois-pontos.
# Exemplo: SCAN_ROOTS="$HOME/projetos:$HOME/www"
SCAN_ROOTS="$HOME"

# Opcional: caminho do OSV-Scanner, se instalado.
# OSV_SCANNER=/usr/local/bin/osv-scanner
EOF
    chmod 600 "$CONFIG_FILE"
    echo "Criado arquivo de configuração: $CONFIG_FILE"
fi

# Wrapper para carregar as variáveis de ambiente sem exibir os segredos.
cat > "$BIN_DIR/npm-security-monitor" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${NPM_MONITOR_INSTALL_DIR:-$HOME/.local/share/npm-security-monitor}"
CONFIG_FILE="$INSTALL_DIR/.env"

if [[ -f "$CONFIG_FILE" ]]; then
    set -a
    # Arquivo local de configuração, criado e editado pelo próprio usuário.
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    set +a
fi

exec "$INSTALL_DIR/npm-security-monitor.sh" "$@"
EOF

chmod 700 "$BIN_DIR/npm-security-monitor"

echo
echo "Instalação concluída."
echo "Script: $INSTALL_DIR/npm-security-monitor.sh"
echo "Configuração: $CONFIG_FILE"
echo "Comando: $BIN_DIR/npm-security-monitor"
echo
echo "Próximos passos:"
echo "1. Edite o arquivo de configuração:"
echo "   nano \"$CONFIG_FILE\""
echo "2. Configure o Telegram ou webhook e os diretórios a verificar."
echo "3. Teste manualmente:"
echo "   \"$BIN_DIR/npm-security-monitor\""
echo "4. Configure a execução diária no cron, após validar o teste."

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo
    echo "Adicione ao PATH, se desejar:"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
fi
