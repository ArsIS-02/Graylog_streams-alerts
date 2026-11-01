#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сборка набора проверок детектов.

Читает tests_def.py и ../graylog/detections/catalog.csv, затем:
  * проверяет, что каждое правило в тестах есть в каталоге (и подстрока однозначна);
  * проверяет, что у каждого теста есть реализация в раннере своей платформы;
  * пишет tests.json и встраивает описания в раннеры между метками BEGIN-META и END-META;
  * собирает ../docs/15-detection-tests.md.

Запуск: python3 build_tests.py            (пересобрать)
        python3 build_tests.py --check    (только проверки, ничего не пишет)
"""
import csv
import json
import os
import re
import sys
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tests_def  # noqa: E402

CATALOG = os.path.join(HERE, "..", "graylog", "detections", "catalog.csv")
DOC = os.path.join(HERE, "..", "docs", "15-detection-tests.md")

PLATFORMS = OrderedDict([
    ("WIN", dict(title="Windows", catalog=lambda p: p == "Windows", runner="windows/Invoke-DetectionTests.ps1",
                 impl=lambda i: f"Test-{i.replace('-', '')}")),
    ("LNX", dict(title="Linux (auditd)", catalog=lambda p: p == "Linux", runner="linux/detection-tests.sh",
                 impl=lambda i: f"t_{i.replace('-', '_')}")),
    ("MAC", dict(title="macOS", catalog=lambda p: p.startswith("macOS"), runner="macos/detection-tests.sh",
                 impl=lambda i: f"t_{i.replace('-', '_')}")),
    ("IPA", dict(title="FreeIPA", catalog=lambda p: p.startswith("FreeIPA"), runner="freeipa/ipa_detection_tests.py",
                 impl=lambda i: f"test_{i.replace('-', '_')}")),
])


def load_catalog():
    with open(CATALOG, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def resolve(rows, key, sub):
    pool = [r for r in rows if PLATFORMS[key]["catalog"](r["Платформа"])]
    exact = [r for r in pool if r["Правило"].split(" - ", 1)[-1] == sub or r["Правило"] == sub]
    if len(exact) == 1:
        return exact[0]["Правило"]
    hit = [r for r in pool if sub in r["Правило"]]
    if len(hit) == 1:
        return hit[0]["Правило"]
    raise SystemExit(f"[{key}] подстрока «{sub}»: найдено {len(hit)} правил " + "; ".join(r["Правило"] for r in hit[:4]))


def build():
    rows = load_catalog()
    tests = []
    errors = []
    for d in tests_def.T:
        key = d["platform"]
        try:
            rules = [resolve(rows, key, s) for s in d["rules"]]
        except SystemExit as e:
            errors.append(f"{d['id']}: {e}")
            continue
        tests.append(dict(d, rules=rules))
    # реализации
    for key, p in PLATFORMS.items():
        path = os.path.join(HERE, p["runner"])
        if not os.path.exists(path):
            errors.append(f"нет раннера {p['runner']}")
            continue
        text = open(path, encoding="utf-8-sig").read()
        for d in tests:
            if d["platform"] == key and not re.search(r"\b" + re.escape(p["impl"](d["id"])) + r"\b", text):
                errors.append(f"{d['id']}: в {p['runner']} нет функции {p['impl'](d['id'])}")
    ids = [d["id"] for d in tests]
    if len(ids) != len(set(ids)):
        errors.append("повторяющиеся id тестов")
    return rows, tests, errors


def embed(tests, check_only):
    for key, p in PLATFORMS.items():
        path = os.path.join(HERE, p["runner"])
        raw = open(path, "rb").read()
        bom = raw.startswith(b"\xef\xbb\xbf")
        text = raw.decode("utf-8-sig")
        mine = [d for d in tests if d["platform"] == key]
        slim = [dict(id=d["id"], name=d["name"], risk=d["risk"], needs=d["needs"], note=d["note"], rules=d["rules"]) for d in mine]
        if path.endswith(".ps1"):
            body = "$TestsMeta = @'\n" + json.dumps(slim, ensure_ascii=False, indent=1) + "\n'@ | ConvertFrom-Json"
        elif path.endswith(".py"):
            body = "TESTS_META = json.loads(r'''\n" + json.dumps(slim, ensure_ascii=False, indent=1) + "\n''')"
        else:
            lines = ["\t".join([d["id"], d["name"], d["risk"], " || ".join(d["rules"])]) for d in mine]
            body = "META=$(cat <<'META_EOF'\n" + "\n".join(lines) + "\nMETA_EOF\n)"
        new, n = re.subn(r"(# BEGIN-META\n).*?(\n# END-META)", lambda m: m.group(1) + body + m.group(2), text, flags=re.S)
        if n != 1:
            raise SystemExit(f"в {p['runner']} нет меток BEGIN-META и END-META")
        if not check_only and new != text:
            data = new.encode("utf-8")
            if bom:
                data = b"\xef\xbb\xbf" + data
            open(path, "wb").write(data)


def doc(rows, tests):
    covered = {}
    for d in tests:
        for r in d["rules"]:
            covered.setdefault(r, []).append(d["id"])
    out = []
    w = out.append
    total_rules = len(rows)
    w("# Проверка детектов\n")
    w("> Набор безопасных сценариев, которые на тестовой машине создают события, похожие на следы атак, чтобы убедиться: "
      "правила из [каталога детектов](14-detections.md) срабатывают и письма доходят. "
      f"Проверок: **{len(tests)}**, правил каталога покрыто: **{len(covered)}** из {total_rules}.\n")
    w("Файлы лежат в каталоге [`detection-tests`](../detection-tests). Скрипты ничего не ломают: тестовые учётные записи, файлы, "
      "службы и ключи реестра создаются с префиксом `DT_` или `dt_test` и удаляются в конце, а опасные техники "
      "имитируются безвредной командной строкой (`cmd /c rem ...`, `bash -c 'true # ...'`). "
      "Запускайте их только в лаборатории.\n")
    w("## Содержание\n")
    w("- [Как это работает](#как-это-работает)")
    w("- [Запуск](#запуск)")
    w("- [Как сверять результат](#как-сверять-результат)")
    for key, p in PLATFORMS.items():
        w(f"- [{p['title']}](#{p['title'].lower().replace(' ', '-').replace('(', '').replace(')', '')})")
    w("- [Что проверить нельзя](#что-проверить-нельзя)")
    w("- [Как добавить проверку](#как-добавить-проверку)\n")
    w("## Как это работает\n")
    w("1. Раннер выполняет выбранные проверки по очереди и пишет в отчёт время начала и конца каждой.")
    w("2. После каждой проверки он делает паузу (по умолчанию 5 секунд) и в конце удаляет всё созданное.")
    w("3. Вы открываете Graylog (`Alerts → Events`) и сверяете по отчёту, какие алерты пришли. Колонка `seen_in_graylog` в отчёте пустая: заполните её сами.\n")
    w("Правило срабатывает с задержкой: расчёт идёт раз в 5 минут, плюс доставка письма. Ожидайте до 10 минут после конца прогона.\n")
    w("**Важно про повторы.** У большинства правил есть период тишины (чаще всего час): пока он не прошёл, повторное событие нового алерта не даёт. "
      "Если прогон уже срабатывал недавно, а алерта нет, это не обязательно ошибка. Для повторной проверки подождите час или временно "
      "уменьшите период тишины у правила.\n")
    w("## Запуск\n")
    w("Каждый раннер умеет одно и то же:\n")
    w("| Действие | Windows (PowerShell) | Linux, macOS (bash) | FreeIPA (Python) |")
    w("|---|---|---|---|")
    w("| Список проверок | `-List` | `--list` | `--list` |")
    w("| Показать, что будет сделано | `-DryRun` | `--dry-run` | `--dry-run` |")
    w("| Выбрать проверки | `-Id WIN-01,WIN-05` | `--id LNX-01,LNX-05` | `--id IPA-01,IPA-06` |")
    w("| Все проверки | `-All` | `--all` | `--all` |")
    w("| Без вопросов | `-Force` | `--yes` | `--yes` |")
    w("| Пауза между проверками | `-PauseSec 5` | `--pause 5` | `--pause 5` |")
    w("| Путь отчёта | `-Report путь.csv` | `--report путь.csv` | `--report путь.csv` |\n")
    w("Без параметров раннер показывает список и просит выбрать проверки.\n")
    w("```powershell\n# Windows: на контроллере домена или рабочей станции, от администратора\n"
      ".\\Invoke-DetectionTests.ps1 -List\n.\\Invoke-DetectionTests.ps1 -Id WIN-01,WIN-09 -DryRun\n"
      ".\\Invoke-DetectionTests.ps1 -All -Target dc01.example.test\n```\n")
    w("```bash\n# Linux: на хосте с auditd, от root\nsudo ./detection-tests.sh --list\nsudo ./detection-tests.sh --id LNX-01,LNX-05\n"
      "# macOS: из пользовательской сессии администратора\n./detection-tests.sh --all\n"
      "# FreeIPA: на сервере или клиенте IPA\nkinit admin\npython3 ipa_detection_tests.py --all\n```\n")
    w("## Как сверять результат\n")
    w("Раннер печатает в конце сводку: окно времени, список ожидаемых алертов по каждой проверке и путь к CSV-отчёту. "
      "В Graylog откройте `Alerts → Events`, задайте то же окно времени и сверьте названия. Если алерта нет, идите по цепочке: "
      "дошёл ли лог в поток (поиск по потоку), подходит ли поле под запрос правила, не действует ли период тишины.\n")
    for key, p in PLATFORMS.items():
        w(f"## {p['title']}\n")
        w(f"Раннер: [`{p['runner']}`](../detection-tests/{p['runner']}).\n")
        w("| Проверка | Что делает | Ожидаемые алерты | Риск | Условия и оговорки |")
        w("|---|---|---|---|---|")
        for d in [x for x in tests if x["platform"] == key]:
            rules = "<br>".join(r.replace("|", "\\|") for r in d["rules"])
            extra = "; ".join(x for x in (d["needs"], d["note"]) if x)
            w(f"| `{d['id']}` | {d['name']} | {rules} | {d['risk']} | {extra} |")
        w("")
    w("## Что проверить нельзя\n")
    w("Часть правил скриптом не проверить безопасно. Ниже все правила каталога без проверки и причина. "
      "«Проверка не написана» означает, что способ есть, но руки пока не дошли.\n")
    untestable = tests_def.UNTESTABLE
    for key, p in PLATFORMS.items():
        miss = [r for r in rows if p["catalog"](r["Платформа"]) and r["Правило"] not in covered]
        if not miss:
            continue
        w(f"### {p['title']}: {len(miss)}\n")
        w("| Правило | Причина |")
        w("|---|---|")
        for r in miss:
            why = next((v for k, v in untestable.items() if k in r["Правило"] and v), "проверка не написана")
            w(f"| {r['Правило'].replace('|', chr(92) + '|')} | {why} |")
        w("")
    other = [r for r in rows if not any(p["catalog"](r["Платформа"]) for p in PLATFORMS.values())]
    w(f"Платформы без проверок: Keenetic и контейнеры ({len(other)} правил). Роутер и Docker требуют отдельных сценариев.\n")
    w("## Как добавить проверку\n")
    w("1. Опишите её в [`tests_def.py`](../detection-tests/tests_def.py): id, название, подстроки названий правил из каталога, риск, условия.")
    w("2. Напишите реализацию в раннере платформы: функция `Test-WIN34`, `t_LNX_31`, `t_MAC_30` или `test_IPA_12` (по id). "
      "Всё созданное регистрируйте для удаления.")
    w("3. Выполните `python3 build_tests.py`: скрипт проверит правила по `catalog.csv`, наличие функции, обновит описания в раннерах и эту страницу.")
    w("4. Прогоните проверку у себя и убедитесь, что алерт приходит.\n")
    return "\n".join(out)


def main():
    check = "--check" in sys.argv
    rows, tests, errors = build()
    if errors:
        print("Ошибки:")
        for e in errors:
            print("  -", e)
        sys.exit(1)
    embed(tests, check)
    if not check:
        json.dump(tests, open(os.path.join(HERE, "tests.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        open(os.path.join(HERE, "tests.json"), "a").write("\n")
        open(DOC, "w", encoding="utf-8").write(doc(rows, tests))
    covered = {r for d in tests for r in d["rules"]}
    print(f"проверок: {len(tests)}, правил покрыто: {len(covered)} из {len(rows)}")
    for key, p in PLATFORMS.items():
        pool = [r for r in rows if p["catalog"](r["Платформа"])]
        c = sum(1 for r in pool if r["Правило"] in covered)
        print(f"  {p['title']}: {c} из {len(pool)}")


if __name__ == "__main__":
    main()
