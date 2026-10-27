#!/usr/bin/env bash
# npm-security-monitor.sh — read-only checks for Node/npm projects.
# Configure notifications through environment variables; never put tokens in this file.
set -uo pipefail
umask 077

SCRIPT_VERSION="1.0.0"
HOST="$(hostname 2>/dev/null || printf 'unknown-host')"
STAMP="$(date -Is 2>/dev/null || date)"
REPORT_DIR="${REPORT_DIR:-$HOME/.local/state/npm-security-monitor}"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/report-$(date +%Y%m%d-%H%M%S).txt"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Colon-separated paths. Defaults cover common personal project directories.
SCAN_ROOTS="${SCAN_ROOTS:-$HOME/www:$HOME/projects:$HOME/code}"
GLOBAL_ROOT="$(npm root -g 2>/dev/null || true)"
ALERT_ON_CLEAN="${ALERT_ON_CLEAN:-false}"
MAX_PROJECTS="${MAX_PROJECTS:-100}"

{
  echo "Node/npm security scan"
  echo "Version: $SCRIPT_VERSION"
  echo "Host: $HOST"
  echo "Date: $STAMP"
  echo "Roots: $SCAN_ROOTS"
  echo "Global npm root: ${GLOBAL_ROOT:-not found}"
  echo
} > "$REPORT"

ISSUES=0
WARNINGS=0
PROJECTS=0
SCAN_ERRORS=0

add_issue() { ISSUES=$((ISSUES + 1)); printf 'ISSUE: %s\n' "$*" >> "$REPORT"; }
add_warning() { WARNINGS=$((WARNINGS + 1)); printf 'WARNING: %s\n' "$*" >> "$REPORT"; }

if ! command -v npm >/dev/null 2>&1; then
  add_issue "npm não encontrado no PATH."
else
  {
    echo "=== Runtime ==="
    node --version 2>&1 || true
    npm --version 2>&1 || true
    echo
    echo "=== Cache npm ==="
    npm cache verify 2>&1 || add_warning "npm cache verify falhou; verifique a saída acima."
    echo
  } >> "$REPORT"
fi

# Find lockfiles while avoiding dependency trees, VCS metadata and caches.
: > "$TMP/lockfiles"
IFS=':' read -r -a ROOT_ARRAY <<< "$SCAN_ROOTS"
for root in "${ROOT_ARRAY[@]}"; do
  [ -d "$root" ] || continue
  find "$root" \
    \( -type d \( -name node_modules -o -name .git -o -name .cache -o -name .npm -o -name vendor \) -prune \) -o \
    \( -type f \( -name package-lock.json -o -name npm-shrinkwrap.json \) -print \) 2>/dev/null
done | sort -u > "$TMP/lockfiles"

echo "=== npm audit por projeto ===" >> "$REPORT"
while IFS= read -r lockfile; do
  [ -n "$lockfile" ] || continue
  [ "$PROJECTS" -lt "$MAX_PROJECTS" ] || { add_warning "Limite MAX_PROJECTS=$MAX_PROJECTS atingido."; break; }
  project_dir="$(dirname "$lockfile")"
  PROJECTS=$((PROJECTS + 1))
  echo >> "$REPORT"
  echo "--- $project_dir ---" >> "$REPORT"
  audit_file="$TMP/audit-$PROJECTS.json"
  (cd "$project_dir" && npm audit --json) > "$audit_file" 2>"$TMP/audit-$PROJECTS.err"
  audit_rc=$?
  if command -v python3 >/dev/null 2>&1; then
    parsed="$(python3 - "$audit_file" <<'PY'
import json, sys
try:
    d=json.load(open(sys.argv[1], encoding="utf-8"))
    meta=d.get("metadata", {}).get("vulnerabilities", {})
    counts={k:int(meta.get(k,0) or 0) for k in ("critical","high","moderate","low","info")}
    total=sum(counts.values())
    print(f"total={total}; critical={counts['critical']}; high={counts['high']}; moderate={counts['moderate']}; low={counts['low']}; info={counts['info']}")
    if total:
        for name, item in (d.get("vulnerabilities") or {}).items():
            via=item.get("via", [])
            titles=[]
            for v in via:
                if isinstance(v, dict) and v.get("title"):
                    titles.append(v["title"])
            print(f"  - {name}: severity={item.get('severity','unknown')}; range={item.get('range','?')}; fixAvailable={item.get('fixAvailable',False)}; advisories={'; '.join(titles[:3])}")
except Exception as e:
    print("parse_error=" + str(e))
PY
)"
    echo "$parsed" >> "$REPORT"
    if printf '%s' "$parsed" | grep -Eq 'critical=[1-9]|high=[1-9]|moderate=[1-9]|low=[1-9]|info=[1-9]'; then
      add_issue "npm audit reportou vulnerabilidades em $project_dir: $(printf '%s' "$parsed" | head -n1)"
    elif [ "$audit_rc" -ne 0 ]; then
      add_warning "npm audit falhou em $project_dir (exit $audit_rc); veja erro no relatório."
      cat "$TMP/audit-$PROJECTS.err" >> "$REPORT"
    fi
  else
    add_warning "Python 3 não encontrado; não foi possível interpretar npm audit em $project_dir."
    head -c 12000 "$audit_file" >> "$REPORT"
    echo >> "$REPORT"
  fi
done < "$TMP/lockfiles"
[ "$PROJECTS" -gt 0 ] || echo "Nenhum package-lock.json/npm-shrinkwrap.json encontrado nos diretórios configurados." >> "$REPORT"

# Static heuristic: report lifecycle scripts with potentially dangerous combinations.
# This is a heuristic, not a malware verdict; legitimate packages can match.
echo >> "$REPORT"
echo "=== Heurística de scripts de instalação ===" >> "$REPORT"
if command -v python3 >/dev/null 2>&1; then
  python3 - "$GLOBAL_ROOT" "$SCAN_ROOTS" "$REPORT" <<'PY'
import json, os, re, sys
global_root, roots_raw, report_path = sys.argv[1:4]
roots=[p for p in roots_raw.split(":") if p and os.path.isdir(p)]
bases=[]
if global_root and os.path.isdir(global_root): bases.append(global_root)
bases += roots
lifecycle={"preinstall","install","postinstall","prepare"}
# Patterns are deliberately conservative and only flag a script when combinations appear.
patterns=[
    ("download + shell execution", re.compile(r"(curl|wget|fetch)\b.{0,300}(\|\s*(sh|bash)|\b(base64\s+-d|eval)\b)", re.I|re.S)),
    ("obfuscation/evaluation", re.compile(r"\b(eval\s*\(|Function\s*\(|atob\s*\(|fromCharCode\s*\()", re.I)),
    ("shell launch from install hook", re.compile(r"\b(child_process|execSync|spawnSync)\b.{0,250}\b(curl|wget|bash|sh|powershell|pwsh)\b", re.I|re.S)),
    ("encoded command", re.compile(r"\b(powershell|pwsh)\b.{0,150}(-enc|-encodedcommand)\b", re.I|re.S)),
]
seen=set(); hits=[]
for base in bases:
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in {".git",".cache",".npm"}]
        if "package.json" not in files: continue
        path=os.path.join(root,"package.json")
        if path in seen: continue
        seen.add(path)
        try:
            if os.path.getsize(path)>2_000_000: continue
            data=json.load(open(path,encoding="utf-8"))
            scripts=data.get("scripts") or {}
            for hook in lifecycle:
                cmd=scripts.get(hook)
                if not isinstance(cmd,str): continue
                matched=[label for label,rx in patterns if rx.search(cmd)]
                if matched:
                    hits.append((data.get("name","unknown"),data.get("version","?"),hook,path,matched,cmd[:350].replace("\n"," ")))
        except Exception:
            continue
with open(report_path,"a",encoding="utf-8") as out:
    if not hits:
        out.write("Nenhum script de lifecycle correspondeu às heurísticas simples.\n")
    else:
        out.write(f"{len(hits)} script(s) correspondem a heurísticas; revisar manualmente (podem ser falsos positivos):\n")
        for name,version,hook,path,matched,cmd in hits[:100]:
            out.write(f"- {name}@{version} hook={hook} sinais={','.join(matched)}\n  arquivo={path}\n  comando={cmd}\n")
        if len(hits)>100: out.write(f"... mais {len(hits)-100} ocorrências omitidas do relatório.\n")
PY
  if grep -qE 'correspondem a heurísticas|sinal' "$REPORT"; then
    # Only count actual hit list, not the explanatory sentence.
    if grep -q 'hook=' "$REPORT"; then add_warning "Há scripts de lifecycle que merecem revisão manual (heurística; não confirma malware)."; fi
  fi
else
  add_warning "Python 3 não encontrado; etapa heurística de scripts ignorada."
fi

# Optional independent scanner. Install OSV-Scanner separately if desired.
echo >> "$REPORT"
echo "=== OSV-Scanner (opcional) ===" >> "$REPORT"
if command -v osv-scanner >/dev/null 2>&1; then
  for root in "${ROOT_ARRAY[@]}"; do
    [ -d "$root" ] || continue
    echo "--- $root ---" >> "$REPORT"
    osv-scanner scan source -r "$root" --format table >> "$REPORT" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then add_warning "OSV-Scanner retornou exit $rc em $root; verifique o relatório."; fi
  done
else
  echo "Não instalado. Opcional: instalar OSV-Scanner seguindo a documentação oficial." >> "$REPORT"
fi

{
  echo
  echo "=== Resumo ==="
  echo "Projetos auditados: $PROJECTS"
  echo "Issues: $ISSUES"
  echo "Warnings: $WARNINGS"
  echo "Relatório: $REPORT"
  echo "Nota: scanners de vulnerabilidade e heurísticas não provam nem excluem comprometimento."
} >> "$REPORT"

# Keep a bounded local history.
find "$REPORT_DIR" -type f -name 'report-*.txt' -mtime +30 -delete 2>/dev/null || true

send_alert() {
  local message="$1"
  # Telegram preferred when both token and chat ID are present.
  if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
    local body
    body="$(python3 -c 'import json,sys; print(json.dumps({"chat_id":sys.argv[1],"text":sys.argv[2]}))' "$TELEGRAM_CHAT_ID" "$message" 2>/dev/null)" || return 1
    curl -fsS --max-time 20 \
      -H 'Content-Type: application/json' \
      -d "$body" \
      "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" >/dev/null
    return $?
  fi
  if [ -n "${WEBHOOK_URL:-}" ]; then
    local body
    body="$(python3 -c 'import json,sys; print(json.dumps({"text":sys.argv[1],"host":sys.argv[2],"report":sys.argv[3]}))' "$message" "$HOST" "$(cat "$REPORT")" 2>/dev/null)" || return 1
    curl -fsS --max-time 20 -X POST -H 'Content-Type: application/json' -d "$body" "$WEBHOOK_URL" >/dev/null
    return $?
  fi
  return 2
}

if [ "$ISSUES" -gt 0 ] || [ "$WARNINGS" -gt 0 ] || [ "$ALERT_ON_CLEAN" = "true" ]; then
  SUMMARY="Node/npm security scan on $HOST
Issues: $ISSUES | Warnings: $WARNINGS | Projects audited: $PROJECTS
Report: $REPORT

$(tail -n 35 "$REPORT")"
  # Telegram limit is 4096 chars; keep a margin.
  SUMMARY="$(printf '%s' "$SUMMARY" | head -c 3500)"
  if send_alert "$SUMMARY"; then
    echo "Notification sent."
  else
    echo "Notification not sent (configure Telegram or webhook environment variables)." >&2
  fi
fi

echo "Scan complete: $REPORT"
[ "$ISSUES" -eq 0 ] || exit 1
