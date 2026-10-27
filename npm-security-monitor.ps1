# npm-security-monitor.ps1 — read-only checks for Node/npm projects.
# Set notification settings through environment variables, not this file.
param(
    [string[]]$ScanRoots = @("$HOME\www", "$HOME\projects", "$HOME\code"),
    [int]$MaxProjects = 100
)
$ErrorActionPreference = "Continue"
$HostName = $env:COMPUTERNAME
$Stamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
$ReportDir = if ($env:REPORT_DIR) { $env:REPORT_DIR } else { Join-Path $HOME ".npm-security-monitor" }
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
$ReportPath = Join-Path $ReportDir ("report-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".txt")
$script:Issues = 0
$script:Warnings = 0
$script:Projects = 0
$Lines = [System.Collections.Generic.List[string]]::new()
$Lines.Add("Node/npm security scan")
$Lines.Add("Host: $HostName")
$Lines.Add("Date: $Stamp")
$Lines.Add("Roots: $($ScanRoots -join '; ')")
$Lines.Add("")

function Add-Issue([string]$Message) {
    $script:Issues++
    $Lines.Add("ISSUE: $Message")
}
function Add-Warning([string]$Message) {
    $script:Warnings++
    $Lines.Add("WARNING: $Message")
}

$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) {
    Add-Issue "npm não encontrado no PATH."
} else {
    $Lines.Add("=== Runtime ===")
    $Lines.Add((& node --version 2>&1 | Out-String).Trim())
    $Lines.Add((& npm --version 2>&1 | Out-String).Trim())
    $Lines.Add("")
    $Lines.Add("=== Cache npm ===")
    $cacheOutput = & npm cache verify 2>&1
    $Lines.Add(($cacheOutput | Out-String).Trim())
    if ($LASTEXITCODE -ne 0) { Add-Warning "npm cache verify falhou." }
    $Lines.Add("")
}

$lockfiles = foreach ($root in $ScanRoots) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
    Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -in @("package-lock.json", "npm-shrinkwrap.json") -and
            $_.FullName -notmatch '[\\/](node_modules|\.git|\.cache|\.npm|vendor)[\\/]'
        } | ForEach-Object FullName
}
$lockfiles = @($lockfiles | Sort-Object -Unique)
$Lines.Add("=== npm audit por projeto ===")
foreach ($lockfile in $lockfiles) {
    if ($script:Projects -ge $MaxProjects) { Add-Warning "Limite MaxProjects=$MaxProjects atingido."; break }
    $dir = Split-Path -Parent $lockfile
    $script:Projects++
    $Lines.Add("")
    $Lines.Add("--- $dir ---")
    $auditPath = Join-Path $env:TEMP ("npm-audit-" + [guid]::NewGuid().ToString() + ".json")
    Push-Location $dir
    try {
        & npm audit --json 1> $auditPath 2> $null
        $auditExit = $LASTEXITCODE
    } finally { Pop-Location }
    try {
        $audit = Get-Content -LiteralPath $auditPath -Raw | ConvertFrom-Json
        $v = $audit.metadata.vulnerabilities
        $counts = [ordered]@{
            critical = [int]$v.critical; high = [int]$v.high
            moderate = [int]$v.moderate; low = [int]$v.low; info = [int]$v.info
        }
        $total = ($counts.Values | Measure-Object -Sum).Sum
        $Lines.Add("total=$total; " + (($counts.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "))
        if ($total -gt 0) {
            Add-Issue "npm audit reportou $total vulnerabilidade(s) em $dir."
            foreach ($prop in $audit.vulnerabilities.PSObject.Properties) {
                $item = $prop.Value
                $titles = @($item.via | Where-Object { $_ -is [pscustomobject] -and $_.title } | ForEach-Object title)
                $Lines.Add("  - $($prop.Name): severity=$($item.severity); range=$($item.range); fixAvailable=$($item.fixAvailable); advisories=$($titles -join ', ')")
            }
        } elseif ($auditExit -ne 0) {
            Add-Warning "npm audit falhou em $dir (exit $auditExit); verifique rede/registry."
        }
    } catch {
        Add-Warning "Não foi possível interpretar a saída de npm audit em $dir."
    } finally {
        Remove-Item -LiteralPath $auditPath -Force -ErrorAction SilentlyContinue
    }
}
if ($script:Projects -eq 0) { $Lines.Add("Nenhum package-lock.json/npm-shrinkwrap.json encontrado.") }

$Lines.Add("")
$Lines.Add("=== Heurística de scripts de instalação ===")
$manifestPaths = @()
$searchRoots = @()
$globalRoot = (& npm root -g 2>$null | Select-Object -First 1)
if ($globalRoot -and (Test-Path $globalRoot)) { $searchRoots += $globalRoot }
$searchRoots += $ScanRoots | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
foreach ($root in $searchRoots) {
    $manifestPaths += Get-ChildItem -LiteralPath $root -Recurse -File -Filter package.json -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '[\\/](\.git|\.cache|\.npm)[\\/]' } | ForEach-Object FullName
}
$hits = 0
$patterns = @(
    '(?is)(curl|wget|fetch)\b.{0,300}(\|\s*(sh|bash)|\b(base64\s+-d|eval)\b)',
    '(?i)\b(eval\s*\(|Function\s*\(|atob\s*\(|fromCharCode\s*\()',
    '(?is)\b(child_process|execSync|spawnSync)\b.{0,250}\b(curl|wget|bash|sh|powershell|pwsh)\b',
    '(?is)\b(powershell|pwsh)\b.{0,150}(-enc|-encodedcommand)\b'
)
foreach ($manifest in ($manifestPaths | Sort-Object -Unique)) {
    try {
        $pkg = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        foreach ($hook in @("preinstall","install","postinstall","prepare")) {
            $cmd = $pkg.scripts.$hook
            if (-not ($cmd -is [string])) { continue }
            $matched = @($patterns | Where-Object { $cmd -match $_ })
            if ($matched.Count -gt 0) {
                $hits++
                if ($hits -le 100) {
                    $Lines.Add("- $($pkg.name)@$($pkg.version) hook=$hook sinais=$($matched.Count)")
                    $Lines.Add("  arquivo=$manifest")
                    $Lines.Add("  comando=$($cmd.Substring(0,[Math]::Min(350,$cmd.Length)))")
                }
            }
        }
    } catch {}
}
if ($hits -gt 0) { Add-Warning "$hits script(s) de lifecycle corresponderam a heurísticas; revisar manualmente, pois podem ser falsos positivos." }
else { $Lines.Add("Nenhum script de lifecycle correspondeu às heurísticas simples.") }

$Lines.Add("")
$Lines.Add("=== OSV-Scanner (opcional) ===")
if (Get-Command osv-scanner -ErrorAction SilentlyContinue) {
    foreach ($root in $ScanRoots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $Lines.Add("--- $root ---")
        $osv = & osv-scanner scan source -r $root --format table 2>&1
        $Lines.Add(($osv | Out-String).Trim())
        if ($LASTEXITCODE -ne 0) { Add-Warning "OSV-Scanner retornou exit $LASTEXITCODE em $root." }
    }
} else {
    $Lines.Add("Não instalado; opcional.")
}
$Lines.Add("")
$Lines.Add("=== Resumo ===")
$Lines.Add("Projetos auditados: $script:Projects")
$Lines.Add("Issues: $script:Issues")
$Lines.Add("Warnings: $script:Warnings")
$Lines.Add("Relatório: $ReportPath")
$Lines.Add("Nota: scanners de vulnerabilidade e heurísticas não provam nem excluem comprometimento.")
$Lines | Set-Content -LiteralPath $ReportPath -Encoding UTF8

# Alert on issues/warnings unless explicitly configured to report clean scans too.
$send = ($script:Issues -gt 0 -or $script:Warnings -gt 0 -or $env:ALERT_ON_CLEAN -eq "true")
if ($send) {
    $tail = ($Lines | Select-Object -Last 35) -join "`n"
    $message = "Node/npm security scan on $HostName`nIssues: $script:Issues | Warnings: $script:Warnings | Projects: $script:Projects`nReport: $ReportPath`n`n$tail"
    if ($message.Length -gt 3500) { $message = $message.Substring(0,3500) }
    try {
        if ($env:TELEGRAM_BOT_TOKEN -and $env:TELEGRAM_CHAT_ID) {
            $uri = "https://api.telegram.org/bot$($env:TELEGRAM_BOT_TOKEN)/sendMessage"
            $body = @{ chat_id = $env:TELEGRAM_CHAT_ID; text = $message } | ConvertTo-Json
            Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null
            Write-Host "Notification sent via Telegram."
        } elseif ($env:WEBHOOK_URL) {
            $body = @{ text = $message; host = $HostName; report = ($Lines -join "`n") } | ConvertTo-Json -Depth 5
            Invoke-RestMethod -Method Post -Uri $env:WEBHOOK_URL -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null
            Write-Host "Notification sent via webhook."
        } else {
            Write-Warning "Alertas encontrados, mas TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID ou WEBHOOK_URL não configurados."
        }
    } catch {
        Write-Warning "Falha ao enviar notificação: $($_.Exception.Message)"
    }
}
Write-Host "Scan complete: $ReportPath"
if ($script:Issues -gt 0) { exit 1 } else { exit 0 }
