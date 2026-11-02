"""Проверка детектов (глава 15, detection-tests/): раздаёт уже готовые раннеры хостов и сверяет
результат с Graylog — так же, как art.py делает для Atomic Red Team, но без переписывания
уже рабочих скриптов. Описания проверок: ../detection-tests/tests.json (его собирает
detection-tests/build_tests.py из tests_def.py и держит в соответствии с каталогом и раннерами).
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DT = ROOT / "detection-tests"
TESTS = DT / "tests.json"

PLATFORMS = ("windows", "linux", "macos", "freeipa")
PLATFORM_RU = {"windows": "Windows", "linux": "Linux (auditd)", "macos": "macOS", "freeipa": "FreeIPA"}
PLATFORM_KEY = {"windows": "WIN", "linux": "LNX", "macos": "MAC", "freeipa": "IPA"}
PLATFORM_PREFIX = {"windows": "Windows", "linux": "LNX", "macos": "macOS", "freeipa": "FREEIPA"}
RUNNER = {
    "windows": "windows/Invoke-DetectionTests.ps1",
    "linux": "linux/detection-tests.sh",
    "macos": "macos/detection-tests.sh",
    "freeipa": "freeipa/ipa_detection_tests.py",
}
HOW_TO_RUN = {
    "windows": "powershell -File {f} -List            (список)\npowershell -File {f} -Id WIN-01,WIN-09 -DryRun\npowershell -File {f} -All            (от администратора)",
    "linux": "sudo ./{f} --list\nsudo ./{f} --id LNX-01,LNX-05\nsudo ./{f} --all",
    "macos": "./{f} --list\n./{f} --all",
    "freeipa": "kinit admin\npython3 {f} --list\npython3 {f} --all",
}


def _all_tests():
    return json.loads(TESTS.read_text(encoding="utf-8"))


def load_tests(platform=None):
    data = _all_tests()
    if platform:
        key = PLATFORM_KEY[platform]
        data = [t for t in data if t["platform"] == key]
    return data


def runner_path(platform):
    return DT / RUNNER[platform]


def runner_filename(platform):
    return RUNNER[platform].split("/")[-1]


def how_to_run(platform):
    return HOW_TO_RUN[platform].format(f=runner_filename(platform))


def plan_rules(tests):
    """Правило каталога (полное название) -> список проверок, которые его ожидают."""
    by = {}
    for t in tests:
        for r in t["rules"]:
            by.setdefault(r, []).append(t)
    return by


def verify(gl, platform, since, until=None):
    """Сверяет события Graylog за окно since..until с ожиданиями проверок главы 15.

    Возвращает (rows, summary); rows совместимы с отчётами инструмента
    (статусы СОБЫТИЕ ЕСТЬ / НЕТ СОБЫТИЯ / ПРОПУЩЕНО) — как art.verify().
    """
    tests = load_tests(platform)
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
    prefix = PLATFORM_PREFIX[platform]
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
            rows.append({"rule": title, "status": "ПРОПУЩЕНО", "detail": "правила нет в Graylog (проверки: %s)" % names})
            continue
        evs = events.get(defs[title], [])
        if evs:
            hit += 1
            first = sorted(e.get("timestamp", "") for e in evs)[0]
            rows.append({"rule": title, "status": "СОБЫТИЕ ЕСТЬ",
                         "detail": "событий %d, первое %s; проверки: %s" % (len(evs), first, names)})
        else:
            rows.append({"rule": title, "status": "НЕТ СОБЫТИЯ",
                         "detail": "проверка подобрана под правило, но событие не создано; проверки: %s. "
                                   "Проверьте, что проверка выполнялась на хосте с агентом, что прошло 10+ минут "
                                   "и что окно сверки захватывает время запуска" % names})
    for did, evs in sorted(extra.items(), key=lambda kv: id2title.get(kv[0], "")):
        rows.append({"rule": id2title.get(did, did), "status": "ПРОПУЩЕНО",
                     "detail": "вне плана: сработало %d раз за окно, но выбранные проверки на него не рассчитаны" % len(evs)})
    total = len(by)
    summary = "правил в плане %d, событий получено %d, без события %d, вне плана сработало %d" % (
        total, hit, total - hit, len(extra))
    return rows, summary
