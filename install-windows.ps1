
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BaseUrl,

    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "npm-security-monitor")
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$BaseUrl = $BaseUrl.TrimEnd("/")
$MonitorPath = Join-Path $InstallDir "npm-security-monitor.ps1"
$ConfigPath = Join-Path $InstallDir ".env.psd1"

function Download-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $Url = "$BaseUrl/$Name"
    $TempFile = [System.IO.Path]::GetTempFileName()

    try {
        Write-Host "Baixando $Name..."

        Invoke-WebRequest `
            -Uri $Url `
            -OutFile $TempFile `
            -UseBasicParsing

        if ((Get-Item $TempFile).Length -eq 0) {
            throw "O arquivo baixado está vazio: $Name"
        }

        Move-Item -Path $TempFile -Destination $Destination -Force
    }
    catch {
        Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
        throw "Falha ao baixar $Name de $Url. $($_.Exception.Message)"
    }
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

Download-File `
    -Name "npm-security-monitor.ps1" `
    -Destination $MonitorPath

if (-not (Test-Path $ConfigPath)) {
    @'
@{
    # Configure Telegram ou webhook para receber alertas.
    TelegramBotToken = ""
    TelegramChatId   = ""
    WebhookUrl       = ""

    # Lista de diretórios a verificar.
    ScanRoots = @(
        "$HOME\www",
        "$HOME\projects"
    )

    # Opcional: caminho completo para o OSV-Scanner.
    OsvScanner = ""
}
'@ | Set-Content -Path $ConfigPath -Encoding UTF8

    Write-Host "Criado arquivo de configuração: $ConfigPath"
}

Write-Host ""
Write-Host "Instalação concluída."
Write-Host "Script: $MonitorPath"
Write-Host "Configuração: $ConfigPath"
Write-Host ""
Write-Host "Edite a configuração local antes de executar:"
Write-Host "  notepad `"$ConfigPath`""
Write-Host ""
Write-Host "Depois teste o script manualmente:"
Write-Host "  & `"$MonitorPath`""
Write-Host ""
Write-Host "Atenção: a configuração precisa usar os nomes de variáveis"
Write-Host "esperados pelo script npm-security-monitor.ps1."
