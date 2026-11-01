#!/usr/bin/env python3
"""Сборка плана art/plan.json из локальной копии Atomic Red Team (нужен только при обновлении плана).

  git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /путь/к/atomic-red-team
  python3 art_build.py /путь/к/atomic-red-team/atomics

В план попадают только вручную отобранные безопасные тесты (список CURATED ниже): каждый проверен глазами,
у каждого есть очистка, нет скачивания из интернета, отключения защиты, шифрования и выгрузки учётных данных.
Каждому тесту сопоставляются правила каталога с той же техникой MITRE ATT&CK и платформой.
Нужен PyYAML (pip install pyyaml). Atomic Red Team (c) Red Canary, лицензия MIT, см. art/NOTICE.md.
"""
import json
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
CATALOG = HERE.parent / "graylog" / "detections" / "detections-source.json"

# (платформа, техника, номер теста в YAML, подмена аргументов, что делает тест на хосте, риск)
#
# Риск по умолчанию определяется автоматически (см. risk_of): для тестов на чтение — «нет», для тестов без
# прав root/администратора, которые сами всё убирают — «низкий». Явная строка в 6-м элементе нужна только
# тестам, где это недостаточно (создают механизм закрепления, меняют реестр/systemd/правило файрвола) —
# такие тесты отбирались с дополнительной осторожностью: без скачивания файлов, без отключения существующей
# защиты/журналирования/бэкапов, без внедрения в процессы и без похищения учётных данных — это по-прежнему
# не включается в план ни при каких условиях.
CURATED = [
    ("linux", "T1018", 6, {}, "читает ARP-таблицу"),
    ("linux", "T1018", 12, {}, "читает таблицу соседей (ip neighbour)"),
    ("linux", "T1033", 2, {}, "выводит вошедших пользователей (users, w, who)"),
    ("linux", "T1053.003", 1, {}, "на время теста подменяет crontab пользователя, потом возвращает прежний"),
    ("linux", "T1059.004", 1, {"host": "127.0.0.1"}, "создаёт и запускает скрипт /tmp/art.sh, пингует localhost"),
    ("linux", "T1059.004", 5, {}, "запускает временный скрипт из /tmp (id)"),
    ("linux", "T1070.004", 1, {}, "создаёт и удаляет файл в /tmp/victim-files"),
    ("linux", "T1078.003", 8, {}, "создаёт пользователя art, входит под ним и удаляет его"),
    ("linux", "T1098.004", 1, {}, "перезаписывает ~/.ssh/authorized_keys тем же содержимым"),
    ("linux", "T1136.001", 1, {}, "создаёт системного пользователя evil_user и удаляет его"),
    ("linux", "T1140", 3, {}, "кодирует и декодирует строку base64 в Python"),
    ("linux", "T1552.001", 1, {"file_path": "/home"}, "ищет файлы .aws/credentials в /home (чтение)"),
    ("linux", "T1552.001", 3, {"file_path": "/tmp"}, "ищет слово password в /tmp (чтение)"),
    ("linux", "T1560.001", 6, {}, "сжимает файл gzip в домашнем каталоге с вымышленными данными"),
    ("macos", "T1018", 6, {}, "читает ARP-таблицу"),
    ("macos", "T1059.004", 1, {"host": "127.0.0.1"}, "создаёт и запускает скрипт /tmp/art.sh, пингует localhost"),
    ("macos", "T1098.004", 1, {}, "перезаписывает ~/.ssh/authorized_keys тем же содержимым"),
    ("macos", "T1113", 1, {}, "делает снимок экрана в /tmp и удаляет его (нужно разрешение на запись экрана)"),
    ("macos", "T1136.001", 3, {}, "создаёт пользователя evil_user через dscl и удаляет его"),
    ("macos", "T1552.001", 1, {"file_path": "/Users"}, "ищет файлы .aws/credentials в /Users (чтение)"),
    ("macos", "T1552.001", 3, {"file_path": "/tmp"}, "ищет слово password в /tmp (чтение)"),
    ("macos", "T1569.001", 1, {}, "запускает Калькулятор как задачу launchctl и снимает задачу"),
    ("windows", "T1018", 1, {}, "net view (чтение)"),
    ("windows", "T1018", 2, {}, "net group \"Domain Computers\" /domain (чтение)"),
    ("windows", "T1047", 1, {}, "wmic useraccount (чтение, нужен wmic)"),
    ("windows", "T1047", 2, {}, "wmic process (чтение, нужен wmic)"),
    ("windows", "T1053.005", 2, {}, "создаёт задачу планировщика spawn и удаляет её"),
    ("windows", "T1082", 1, {}, "systeminfo и чтение ветки реестра (чтение)"),
    ("windows", "T1082", 7, {}, "hostname (чтение)"),
    ("windows", "T1087.002", 3, {}, "query user (чтение)"),
    ("windows", "T1136.001", 4, {}, "создаёт локального пользователя T1136.001_CMD и удаляет его"),
    ("windows", "T1136.001", 5, {}, "создаёт локального пользователя T1136.001_PowerShell и удаляет его"),
    ("windows", "T1482", 2, {}, "nltest /domain_trusts (чтение, нужен RSAT)"),
    ("windows", "T1547.001", 1, {}, "добавляет и удаляет значение в HKCU\\...\\Run"),
    ("windows", "T1552.001", 4, {}, "ищет слово pass в файлах текущего каталога (чтение)"),
    ("windows", "T1569.002", 1, {}, "создаёт службу ARTService, запускает, удаляет; создаёт и удаляет C:\\art-marker.txt"),
    # --- дополнительные тесты с повышенным риском (нужны права root/администратора) ---
    ("linux", "T1543.002", 1, {}, "создаёт systemd-службу с безвредными командами (touch маркеров), включает её "
     "автозапуск и удаляет юнит",
     "средний: нужен root; служба реально включается (systemctl enable, start). Если скрипт прервётся до очистки, "
     "служба art-systemd-service.service останется включённой — проверьте `systemctl list-unit-files | grep art-systemd` "
     "и уберите вручную: systemctl disable --now art-systemd-service.service; rm /etc/systemd/system/art-systemd-service.service"),
    ("linux", "T1686", 11, {}, "добавляет правило ufw, запрещающее несуществующий адрес 1.2.3.4, и удаляет его "
     "(сам firewall не отключает)",
     "средний: нужен root. На РЕД ОС обычно нет ufw (используется firewalld/iptables) — команда просто завершится "
     "ошибкой «command not found», без эффекта. Если ufw есть, проверьте после теста `ufw status numbered`: "
     "правила на 1.2.3.4 быть не должно"),
    ("linux", "T1548.001", 3, {"file_to_setuid": "/tmp/art-setuid-test"}, "создаёт пустой файл /tmp/art-setuid-test, "
     "делает его владельцем root и ставит бит setuid, затем удаляет файл",
     "средний: нужен root. Файл создаётся специально для теста и пустой (не исполняемый код) — поставленный "
     "setuid безопасен сам по себе, но если скрипт прервётся до удаления, в /tmp останется файл с битом setuid "
     "от root — проверьте `ls -la /tmp/art-setuid-test` и удалите его вручную, если он остался"),
    ("macos", "T1548.001", 3, {"file_to_setuid": "/tmp/art-setuid-test"}, "создаёт пустой файл /tmp/art-setuid-test, "
     "делает его владельцем root и ставит бит setuid, затем удаляет файл",
     "средний: нужен root (sudo). Файл пустой, не исполняемый код. Если скрипт прервётся до очистки, проверьте "
     "`ls -la /tmp/art-setuid-test` и удалите вручную, если он остался"),
    ("windows", "T1546.012", 1, {}, "добавляет ключ отладчика (Debugger) в Image File Execution Options для "
     "calc.exe (запуск calc.exe подменяется на cmd.exe) и удаляет ключ",
     "средний: нужны права администратора. На время теста запуск calc.exe на этом хосте будет открывать cmd.exe "
     "вместо калькулятора. Если скрипт прервётся до очистки, это останется — проверьте ключ реестра "
     "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\calc.exe и удалите "
     "значение Debugger вручную, если он остался"),
    ("windows", "T1547.004", 1, {}, "правит HKCU\\...\\Winlogon\\Shell, добавляя запуск cmd.exe при следующем "
     "входе в систему, и возвращает значение обратно",
     "средний: прав администратора не требует (меняет только текущего пользователя). Если во время теста "
     "произойдёт выход из системы/перезапуск explorer.exe до очистки, при следующем входе рядом с рабочим столом "
     "запустится окно cmd.exe — не выходите из системы во время теста. Если ключ остался, проверьте "
     "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell и верните значение в \"explorer.exe\""),
    ("windows", "T1546.003", 1, {}, "создаёт постоянную подписку WMI (фильтр + получатель + привязка), которая "
     "при попадании в узкое окно времени работы системы запускает notepad.exe, и удаляет все три объекта",
     "средний: нужны права администратора. Подписка WMI создаётся реально; условие запуска узкое (аптайм "
     "240-325 секунд), поэтому срабатывание notepad.exe на практике редкое, но если скрипт прервётся до "
     "очистки, подписка останется в системе. Проверьте: Get-WmiObject -Namespace root/subscription -Class "
     "__EventFilter -Filter \"Name='AtomicRedTeam-WMIPersistence-CommandLineEventConsumer-Example'\" — и удалите "
     "её вместе с CommandLineEventConsumer и __FilterToConsumerBinding, если она осталась"),
]

PREFIX = {"windows": "Windows", "linux": "LNX", "macos": "macOS"}


def load_rules():
    cat = json.loads(CATALOG.read_text(encoding="utf-8"))
    return cat if isinstance(cat, list) else next(v for v in cat.values() if isinstance(v, list))


def rules_for(rules, platform, tech):
    out = []
    for r in rules:
        if r["title"].split(" - ")[0] != PREFIX[platform]:
            continue
        techs = [t.strip().split(" ")[0] for t in (r.get("techniques") or "").split(",") if t.strip()]
        if not techs and r.get("technique"):
            techs = [r["technique"].split(" ")[0]]
        if tech in techs:
            out.append(r["title"])
    return out


def subst(text, args):
    def one(m):
        return str(args[m.group(1)])
    return re.sub(r"#\{([^}]+)\}", one, text or "")


def risk_of(admin, effect, explicit):
    if explicit:
        return explicit
    if re.search(r"чита|чтение|выводит|ищет|кодирует", effect):
        return "нет: тест только читает данные, ничего не меняет"
    if admin:
        return "низкий: нужны права root/администратора, но тест сам создаёт и удаляет свой тестовый объект"
    return "низкий: не требует повышенных прав, тест сам создаёт и удаляет свой тестовый объект"


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = Path(sys.argv[1])
    rules = load_rules()
    plan, dropped = [], []
    for row in CURATED:
        platform, tech, no, over, effect = row[:5]
        explicit_risk = row[5] if len(row) > 5 else ""
        d = yaml.safe_load((root / tech / (tech + ".yaml")).read_text(encoding="utf-8"))
        a = d["atomic_tests"][no - 1]
        if platform not in a.get("supported_platforms", []):
            raise SystemExit("%s#%d не для %s" % (tech, no, platform))
        ex = a["executor"]
        args = {k: v.get("default", "") for k, v in (a.get("input_arguments") or {}).items()}
        args.update(over)
        cmd, clean = subst(ex.get("command"), args).strip("\n"), subst(ex.get("cleanup_command"), args).strip("\n")
        if "PathToAtomicsFolder" in cmd + clean or "#{" in cmd + clean:
            raise SystemExit("%s#%d зависит от файлов Atomic Red Team: %s" % (tech, no, a["name"]))
        read_only = re.search(r"чита|чтение|выводит|ищет|кодирует", effect)
        if not clean and not read_only:
            raise SystemExit("%s#%d без очистки" % (tech, no))
        exp = rules_for(rules, platform, tech)
        if not exp:
            dropped.append("%s %s#%d" % (platform, tech, no))
            continue
        admin = bool(ex.get("elevation_required"))
        plan.append({"id": "%s#%d" % (tech, no), "platform": platform, "technique": tech, "test": no,
                     "name": a["name"], "guid": a.get("auto_generated_guid", ""), "executor": ex.get("name"),
                     "admin": admin, "effect": effect, "risk": risk_of(admin, effect, explicit_risk),
                     "args": args if over else {}, "command": cmd, "cleanup": clean, "expected": exp})
    out = HERE / "art" / "plan.json"
    out.write_text(json.dumps({"source": "https://github.com/redcanaryco/atomic-red-team", "license": "MIT",
                               "tests": plan}, ensure_ascii=False, indent=1), encoding="utf-8")
    print("тестов в плане: %d, без правил (отброшено): %s" % (len(plan), dropped or "нет"))
    per = {}
    for t in plan:
        per.setdefault(t["platform"], set()).update(t["expected"])
    for p, s in per.items():
        print("  %s: тестов %d, правил ожидается %d" % (p, sum(t["platform"] == p for t in plan), len(s)))


if __name__ == "__main__":
    main()
