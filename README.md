# NPM Security Monitor

Monitoramento de segurança de dependências npm para Linux e Windows, com suporte a alertas via Telegram ou webhook.

## Recursos

- Verificação de vulnerabilidades em dependências com `npm audit`.
- Verificação do cache npm.
- Análise heurística de scripts de ciclo de vida dos pacotes.
- Suporte opcional ao OSV-Scanner.
- Notificações via Telegram ou webhook.
- Execução manual e possibilidade de agendamento diário.
- Instalação local, sem precisar clonar o repositório.

## Requisitos

### Linux

- Bash
- `curl`
- Node.js e npm
- Conexão com a internet

### Windows

- PowerShell
- Node.js e npm
- Conexão com a internet

## Instalação no Linux

### 1. Baixar o instalador

```bash
curl -fsSL \
  https://github.com/fthiago01/npm-security-monitor/main/install-linux.sh \
  -o install-linux.sh
```

### 2. Conferir o instalador

Antes de executar qualquer script baixado da internet, confira seu conteúdo:

```bash
less install-linux.sh
```

### 3. Executar a instalação

```bash
bash install-linux.sh \
  "https://github.com/fthiago01/npm-security-monitor/main"
```

O instalador baixa o script principal para:

```text
~/.local/share/npm-security-monitor/
```

E cria o comando:

```text
~/.local/bin/npm-security-monitor
```

### 4. Configurar os alertas

Edite o arquivo de configuração:

```bash
nano ~/.local/share/npm-security-monitor/.env
```

Configure o Telegram ou webhook e os diretórios que deseja verificar.

Exemplo:

```bash
TELEGRAM_BOT_TOKEN="seu_token"
TELEGRAM_CHAT_ID="seu_chat_id"

# Opcional: webhook para receber o relatório.
# WEBHOOK_URL="https://seu-servidor.example/webhook"

SCAN_ROOTS="$HOME/www:$HOME/projetos"
```

Configure apenas os meios de notificação que pretende utilizar. Não publique esse arquivo nem compartilhe seus tokens.

### 5. Executar o monitoramento

```bash
~/.local/bin/npm-security-monitor
```

Para executar com mais detalhes, consulte as opções aceitas pelo script principal.

## Instalação no Windows

### 1. Baixar o instalador

Abra o PowerShell e execute:

```powershell
Invoke-WebRequest `
  -Uri "https://github.com/fthiago01/npm-security-monitor/main/install-windows.ps1" `
  -OutFile ".\install-windows.ps1"
```

### 2. Conferir o arquivo

```powershell
notepad .\install-windows.ps1
```

### 3. Executar a instalação

```powershell
.\install-windows.ps1 `
  -BaseUrl "https://github.com/fthiago01/npm-security-monitor/main"
```

Os arquivos serão instalados por padrão em:

```text
%LOCALAPPDATA%\npm-security-monitor\
```

### 4. Configurar os alertas

Abra o arquivo de configuração:

```powershell
notepad "$env:LOCALAPPDATA\npm-security-monitor\.env.psd1"
```

Exemplo de configuração:

```powershell
@{
    TelegramBotToken = "seu_token"
    TelegramChatId   = "seu_chat_id"
    WebhookUrl       = ""

    ScanRoots = @(
        "$HOME\www",
        "$HOME\projects"
    )

    OsvScanner = ""
}
```

**Importante:** o script principal precisa carregar essa configuração e reconhecer esses nomes. Confira a compatibilidade antes de executar.

### 5. Executar o monitoramento

```powershell
& "$env:LOCALAPPDATA\npm-security-monitor\npm-security-monitor.ps1"
```

## Configuração do Telegram

1. Abra o Telegram e converse com o `@BotFather`.
2. Crie um bot e obtenha o token.
3. Envie uma mensagem ao bot ou inicie a conversa.
4. Obtenha o ID do chat usando a API do Telegram.
5. Configure `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID` no Linux, ou os campos correspondentes no Windows.

Trate o token do bot como uma senha. Se ele for exposto, revogue-o e gere outro.

## Agendamento diário

Os instaladores apresentados não configuram automaticamente a execução diária. Primeiro, execute o monitor manualmente e confirme que os alertas funcionam.

### Linux: cron

Abra o crontab:

```bash
crontab -e
```

Exemplo para executar todos os dias às 08h15:

```cron
15 8 * * * /home/SEU_USUARIO/.local/bin/npm-security-monitor >> /home/SEU_USUARIO/npm-security-monitor.log 2>&1
```

Substitua `SEU_USUARIO` pelo nome do usuário Linux que fez a instalação.

### Windows: Agendador de Tarefas

Abra o Agendador de Tarefas do Windows e crie uma tarefa básica:

- **Disparador:** diariamente, às 08h15.
- **Programa:** `powershell.exe`
- **Argumentos:**

```text
-NoProfile -File "%LOCALAPPDATA%\npm-security-monitor\npm-security-monitor.ps1"
```

Se o Agendador não expandir `%LOCALAPPDATA%` nesse campo, informe o caminho absoluto para o script, por exemplo:

```text
-NoProfile -File "C:\Users\SEU_USUARIO\AppData\Local\npm-security-monitor\npm-security-monitor.ps1"
```

Garanta que o usuário da tarefa tenha acesso aos diretórios monitorados e às configurações necessárias.

## O que o monitor verifica?

O monitor pode executar verificações como:

- Vulnerabilidades conhecidas nas dependências, quando há arquivos de lock compatíveis com `npm audit`.
- Integridade do cache npm.
- Scripts de instalação e outros scripts de ciclo de vida potencialmente suspeitos.
- Verificações adicionais com OSV-Scanner, quando configurado.

Essas verificações são complementares e não garantem que um pacote seja seguro ou que uma máquina esteja livre de comprometimento.

## Limitações e segurança

- Uma análise heurística pode produzir falsos positivos e não detecta todo código malicioso.
- `npm audit` identifica vulnerabilidades conhecidas, mas não é um detector geral de malware.
- A verificação do cache não substitui uma análise forense do sistema.
- O monitor não deve corrigir, remover ou atualizar dependências automaticamente sem revisão.
- Mantenha os tokens e URLs privados fora do repositório.
- Revise os scripts antes de executá-los, mesmo quando o repositório é público.

## Estrutura do repositório

```text
npm-security-monitor/
├── npm-security-monitor.sh
├── npm-security-monitor.ps1
├── install-linux.sh
├── install-windows.ps1
└── README.md
```

## Licença

Adicione aqui a licença escolhida para o projeto, por exemplo, MIT, caso queira permitir reutilização conforme seus termos.
