"""Atomic Red Team: безопасный план тестов на хостах, готовые скрипты запуска и сверка событий в Graylog.

План (art/plan.json) собран вручную из тестов Atomic Red Team (c) Red Canary, лицензия MIT: только безопасные тесты
с очисткой. Скрипты запуска генерируются из плана и не требуют ни PowerShell на Linux/macOS, ни самого
Atomic Red Team: каждая команда видна в скрипте целиком. По умолчанию скрипт ничего не выполняет, а печатает план.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLAN = HERE / "art" / "plan.json"
PLATFORMS = ("linux", "macos", "windows")
PLATFORM_RU = {"linux": "Linux", "macos": "macOS", "windows": "Windows"}


def load_plan(platform=None):
    data = json.loads(PLAN.read_text(encoding="utf-8"))
    tests = data["tests"]
    if platform:
        tests = [t for t in tests if t["platform"] == platform]
    return tests


def parse_time(s, now=None):
    """'2026-11-01T20:30' (по местному времени), '...Z' (UTC) или относительное '90m', '2h'."""
    now = now or datetime.now(timezone.utc)
    s = (s or "").strip()
    m = re.fullmatch(r"(\d+)\s*([mhd])", s)
    if m:
        n, u = int(m.group(1)), m.group(2)
        return now - timedelta(minutes={"m": 1, "h": 60, "d": 1440}[u] * n)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("время ожидается как 2026-11-01T20:30, 2026-11-01T15:30Z или 90m")
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------- скрипты запуска

SH_HEAD = r'''#!/usr/bin/env bash
# Atomic Red Team для GraylogRuleTester: безопасные тесты для {ru}. Сгенерировано art.py из art/plan.json.
# Тесты: Atomic Red Team (c) Red Canary, лицензия MIT, https://github.com/redcanaryco/atomic-red-team
#
#   bash {name}                 показать план и ничего не выполнять
#   sudo bash {name} --run      выполнить все тесты (после каждого идёт очистка)
#   sudo bash {name} --run --only T1136.001#1,T1059.004#5
#   sudo bash {name} --cleanup  только очистка (если тест прервали)
#
# Не запускайте на рабочих машинах без согласования. Тесты создают события, похожие на атаки, и настоящие алерты.
set -u
MODE=plan; ONLY=""; PAUSE=${{ART_PAUSE:-4}}
while [ $# -gt 0 ]; do
  case "$1" in
    --run) MODE=run;; --cleanup) MODE=cleanup;; --only) shift; ONLY="$1";;
    -h|--help) sed -n 2,12p "$0"; exit 0;; *) echo "неизвестный параметр $1"; exit 2;;
  esac; shift
done
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1
sel() {{ [ -z "$ONLY" ] && return 0; case ",$ONLY," in *",$1,"*) return 0;; esac; return 1; }}
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_test() {{ # id, имя, нужен root, что делает, ожидаемые правила, риск
  sel "$1" || return 0
  echo; echo "=== $1  $2"; echo "    делает: $4"; echo "    ждём правила: $5"; echo "    риск: $6"
  [ "$MODE" = plan ] && {{ echo "    (план, не выполняется)"; return 0; }}
  if [ "$3" = 1 ] && [ "$IS_ROOT" != 1 ]; then echo "    ПРОПУЩЕНО: нужен root (запустите через sudo)"; return 0; fi
}}
'''

SH_TEST = r'''
run_test {id} {name} {admin} {effect} {rules} {risk}
if sel {id} && [ "$MODE" != plan ]; then
  if [ "{admin}" != 1 ] || [ "$IS_ROOT" = 1 ]; then
    cat > "$TMP/c.sh" <<'ART_CMD'
{command}
ART_CMD
    cat > "$TMP/x.sh" <<'ART_CLEAN'
{cleanup}
ART_CLEAN
    if [ "$MODE" = run ]; then {exe} "$TMP/c.sh"; echo "    код возврата: $?"; fi
    {exe} "$TMP/x.sh" >/dev/null 2>&1; echo "    очистка выполнена"
    [ "$MODE" = run ] && sleep "$PAUSE"
  fi
fi
'''

SH_TAIL = r'''
echo
END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [ "$MODE" = run ]; then
  echo "Окно тестов (UTC): $START .. $END"
  echo "Через 10 минут сверьте события (правила проверяются раз в 5 минут):"
  echo "  python3 rule_tester.py --url ... art-verify --os {plat} --since $START"
fi
'''

PS_HEAD = r'''# Atomic Red Team для GraylogRuleTester: безопасные тесты для Windows. Сгенерировано art.py из art/plan.json.
# Тесты: Atomic Red Team (c) Red Canary, лицензия MIT, https://github.com/redcanaryco/atomic-red-team
#
#   powershell -File art-windows.ps1                  показать план и ничего не выполнять
#   powershell -File art-windows.ps1 -Run             выполнить все тесты (от администратора; после каждого очистка)
#   powershell -File art-windows.ps1 -Run -Only T1136.001#4,T1082#7
#   powershell -File art-windows.ps1 -Cleanup         только очистка (если тест прервали)
#
# Не запускайте на рабочих машинах без согласования. Тесты создают события, похожие на атаки, и настоящие алерты.
param([switch]$Run, [switch]$Cleanup, [string[]]$Only = @(), [int]$Pause = 4)
$mode = if ($Run) { 'run' } elseif ($Cleanup) { 'cleanup' } else { 'plan' }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$tmp = Join-Path $env:TEMP ('art-' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $tmp | Out-Null
$start = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
function Invoke-Art($id, $name, $admin, $effect, $rules, $risk, $exe, $cmd, $clean) {
  if ($Only.Count -gt 0 -and ($Only -notcontains $id)) { return }
  Write-Host ""; Write-Host "=== $id  $name"; Write-Host "    делает: $effect"; Write-Host "    ждём правила: $rules"
  Write-Host "    риск: $risk"
  if ($mode -eq 'plan') { Write-Host "    (план, не выполняется)"; return }
  if ($admin -and -not $isAdmin) { Write-Host "    ПРОПУЩЕНО: нужен запуск от администратора"; return }
  $ext = if ($exe -eq 'powershell') { 'ps1' } else { 'cmd' }
  $c = Join-Path $tmp "c.$ext"; $x = Join-Path $tmp "x.$ext"
  Set-Content -Path $c -Value $cmd -Encoding UTF8; Set-Content -Path $x -Value $clean -Encoding UTF8
  if ($mode -eq 'run') {
    if ($exe -eq 'powershell') { & powershell -NoProfile -ExecutionPolicy Bypass -File $c } else { & cmd /c $c }
    Write-Host "    код возврата: $LASTEXITCODE"
  }
  if ($exe -eq 'powershell') { & powershell -NoProfile -ExecutionPolicy Bypass -File $x *> $null } else { & cmd /c $x *> $null }
  Write-Host "    очистка выполнена"
  if ($mode -eq 'run') { Start-Sleep -Seconds $Pause }
}
'''

PS_TEST = r'''
Invoke-Art '{id}' '{name}' {admin} '{effect}' '{rules}' '{risk}' '{exe}' @'
{command}
'@ @'
{cleanup}
'@
'''

PS_TAIL = r'''
$end = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
if ($mode -eq 'run') {
  Write-Host ""; Write-Host "Окно тестов (UTC): $start .. $end"
  Write-Host "Через 10 минут сверьте события (правила проверяются раз в 5 минут):"
  Write-Host "  python3 rule_tester.py --url ... art-verify --os windows --since $start"
}
'''


def _q(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def _pq(s):
    return str(s).replace("'", "''")


def runner_name(platform):
    return "art-windows.ps1" if platform == "windows" else "art-%s.sh" % platform


def gen_runner(platform):
    tests = load_plan(platform)
    if not tests:
        raise ValueError("для платформы %s нет тестов" % platform)
    if platform == "windows":
        out = [PS_HEAD]
        for t in tests:
            exe = "powershell" if t["executor"] == "powershell" else "cmd"
            out.append(PS_TEST.format(id=t["id"], name=_pq(t["name"]), admin="$true" if t["admin"] else "$false",
                                      effect=_pq(t["effect"]), rules=_pq("; ".join(t["expected"])),
                                      risk=_pq(t["risk"]), exe=exe,
                                      command=t["command"], cleanup=t["cleanup"] or "rem"))
        out.append(PS_TAIL)
        return "\r\n".join("".join(out).splitlines()) + "\r\n"
    out = [SH_HEAD.format(ru=PLATFORM_RU[platform], name=runner_name(platform))]
    for t in tests:
        exe = "bash" if t["executor"] == "bash" else "sh"
        out.append(SH_TEST.format(id=_q(t["id"]), name=_q(t["name"]), admin="1" if t["admin"] else "0",
                                  effect=_q(t["effect"]), rules=_q("; ".join(t["expected"])), risk=_q(t["risk"]),
                                  exe=exe, command=t["command"], cleanup=t["cleanup"] or ":"))
    out.append(SH_TAIL.format(plat=platform))
    return "".join(out)


# ---------------------------------------------------------------- сверка событий

def plan_rules(tests):
    """Правило -> список тестов, которые его ожидают."""
    by = {}
    for t in tests:
        for r in t["expected"]:
            by.setdefault(r, []).append(t)
    return by


def verify(gl, platform, since, until=None):
    """Сверяет события Graylog за окно since..until с ожиданиями плана.

    Возвращает (rows, summary): rows совместимы с отчётами инструмента (статусы СОБЫТИЕ ЕСТЬ / НЕТ СОБЫТИЯ / ПРОПУЩЕНО).
    """
    tests = load_plan(platform)
    by = plan_rules(tests)
    defs = {d["title"]: d["id"] for d in gl.event_definitions()}
    id2title = {v: k for k, v in defs.items()}
    ids = [defs[t] for t in by if t in defs]
    events = {}
    if ids:
        for e in gl.search_events(ids, since, until, per_page=200):
            did = e.get("event_definition_id")
            if did:
                events.setdefault(did, []).append(e)
    # всё, что сработало за окно у остальных правил платформы: полезно знать, но тест на него не рассчитан
    prefix = {"windows": "Windows", "linux": "LNX", "macos": "macOS"}[platform]
    others = [i for t, i in defs.items() if t.split(" - ")[0] == prefix and t not in by]
    extra = {}
    if others:
        for e in gl.search_events(others, since, until, per_page=200):
            did = e.get("event_definition_id")
            if did:
                extra.setdefault(did, []).append(e)
    rows, hit = [], 0
    for title in sorted(by):
        names = ", ".join(t["id"] for t in by[title])
        if title not in defs:
            rows.append({"rule": title, "status": "ПРОПУЩЕНО", "detail": "правила нет в Graylog (тесты: %s)" % names})
            continue
        evs = events.get(defs[title], [])
        if evs:
            hit += 1
            first = sorted(e.get("timestamp", "") for e in evs)[0]
            rows.append({"rule": title, "status": "СОБЫТИЕ ЕСТЬ",
                         "detail": "событий %d, первое %s; тесты: %s" % (len(evs), first, names)})
        else:
            rows.append({"rule": title, "status": "НЕТ СОБЫТИЯ",
                         "detail": "тест подходит по технике MITRE, но событие не создано; тесты: %s. Проверьте, что тест "
                                   "выполнялся на хосте с агентом, что прошло 10+ минут и что поле, которое ищет правило, "
                                   "тест действительно создаёт (техника общая, а правило может быть уже)" % names})
    for did, evs in sorted(extra.items(), key=lambda kv: id2title.get(kv[0], "")):
        rows.append({"rule": id2title.get(did, did), "status": "ПРОПУЩЕНО",
                     "detail": "вне плана: сработало %d раз за окно, но выбранные тесты на него не рассчитаны" % len(evs)})
    total = len(by)
    summary = "правил в плане %d, событий получено %d, без события %d, вне плана сработало %d" % (
        total, hit, total - hit, len(extra))
    return rows, summary
