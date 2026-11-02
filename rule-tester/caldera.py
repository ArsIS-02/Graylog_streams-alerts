"""CALDERA (MITRE, https://github.com/mitre/caldera): здесь НЕТ сервера и агентов CALDERA — инструмент их
не разворачивает и не запускает, это делаешь ты сам (CALDERA — полноценный C2-сервер с агентами Sandcat
на хостах). Модуль берёт технику MITRE ATT&CK из каталога детектов (поле "techniques" в
detections-source.json — то же самое, что видно на странице «Покрытие») и:

  1. строит «список покупок» — какие техники стоит собрать в adversary-профиль CALDERA (в самом CALDERA
     abilities ищутся и добавляются в профиль по технике ATT&CK через веб-интерфейс), чтобы проверить
     именно те правила, что уже есть в Graylog. Готовых ability-файлов/UUID мы не генерируем: id способностей
     в стандартном наборе stockpile могут отличаться между версиями CALDERA, и выдумывать команды, которые
     реально запускаются на хосте, без проверенного источника — плохая идея;
  2. сверяет результат с Graylog по списку техник и окну времени — так же, как art.verify()/methodology.verify(),
     только ключ сверки — не заранее собранный план тестов, а список технических ID, которые ты указываешь сам
     (после того как в CALDERA отработал нужный adversary-профиль).
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CATALOG = HERE.parent / "graylog" / "detections" / "detections-source.json"
TECH_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)\s*(.*)$")


def _platform_of(title):
    return re.split(r"\s*[-:]\s", title, maxsplit=1)[0].strip()


def load_catalog():
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    return data["definitions"]


def techniques_by_rule(defs=None):
    """technique_id -> [{'rule','platform','tactic'}, ...]; и technique_id -> человекочитаемое имя (где известно)."""
    defs = defs if defs is not None else load_catalog()
    by_tech, names = {}, {}
    for d in defs:
        raw = (d.get("techniques") or "").strip()
        if not raw:
            continue
        ids = [t.strip() for t in raw.split(",") if t.strip()]
        m = TECH_RE.match((d.get("technique") or "").strip())
        if m and m.group(1) in ids:
            names.setdefault(m.group(1), m.group(2).strip())
        for tid in ids:
            by_tech.setdefault(tid, []).append({"rule": d["title"], "platform": _platform_of(d["title"]),
                                                "tactic": d.get("tactic", "")})
    return by_tech, names


def build_guide_text(platform=None):
    """Текст «списка покупок» по техникам: что собрать в adversary-профиль CALDERA, чтобы покрыть
    уже существующие правила. platform — префикс (Windows/LNX/macOS/...), без него — все платформы."""
    by_tech, names = techniques_by_rule()
    lines = ["Список техник MITRE ATT&CK, под которые уже есть правила в Graylog.",
             "Собери adversary-профиль в CALDERA: Adversaries -> create -> добавляй abilities, фильтруя по этим",
             "техникам (в самом CALDERA у ability есть фильтр/поиск по ATT&CK technique). Полезно взять по одной",
             "способности на технику для нужной платформы — покрывать все способности сразу не нужно.", ""]
    total_tech, total_rules = 0, 0
    for tid in sorted(by_tech):
        rules = by_tech[tid]
        if platform:
            rules = [r for r in rules if r["platform"].lower().startswith(platform.lower())]
            if not rules:
                continue
        total_tech += 1
        total_rules += len(rules)
        name = names.get(tid, "")
        plats = sorted({r["platform"] for r in rules})
        lines.append("%s%s  [%s]" % (tid, (" " + name) if name else "", ", ".join(plats)))
        for r in rules:
            lines.append("    -> %s" % r["rule"])
    lines.append("")
    lines.append("Техник: %d, правил под ними: %d." % (total_tech, total_rules))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- сверка событий

def _rule_matches(title, rule_filters):
    """Тот же формат фильтра, что у filter_rules() в rule_tester.py: '=Точное название' или подстрока
    (можно несколько через запятую/несколько --rule)."""
    if not rule_filters:
        return True
    exact = [r[1:] for r in rule_filters if r.startswith("=")]
    subs = [s.strip().lower() for r in rule_filters if not r.startswith("=") for s in r.split(",") if s.strip()]
    return title in exact or any(s in title.lower() for s in subs)


def verify(gl, techniques, since, until=None, platform=None, rule=None):
    """Сверяет события Graylog за окно since..until с правилами, ожидаемыми под указанные техники MITRE
    (techniques — список T-кодов, например ['T1110', 'T1021.004']; сравнение по полному ID, без обрезки
    под-техники). rule — тот же фильтр по названию правила, что и у остальных команд (--rule). Возвращает
    (rows, summary) в том же формате, что art.verify()/methodology.verify()."""
    by_tech, _ = techniques_by_rule()
    wanted = {t.strip().upper() for t in techniques if t.strip()}
    by_rule = {}
    for tid in wanted:
        for r in by_tech.get(tid, []):
            if platform and not r["platform"].lower().startswith(platform.lower()):
                continue
            if not _rule_matches(r["rule"], rule):
                continue
            by_rule.setdefault(r["rule"], []).append(tid)
    defs = {d["title"]: d["id"] for d in gl.event_definitions()}
    ids = [defs[t] for t in by_rule if t in defs]
    events = {}
    if ids:
        for e in gl.search_events(ids, since, until, per_page=200):
            did = e.get("event_definition_id")
            if did:
                events.setdefault(did, []).append(e)
    rows, hit = [], 0
    for title in sorted(by_rule):
        tids = ", ".join(sorted(set(by_rule[title])))
        if title not in defs:
            rows.append({"rule": title, "status": "ПРОПУЩЕНО",
                         "detail": "правила нет в Graylog (техники: %s)" % tids})
            continue
        evs = events.get(defs[title], [])
        if evs:
            hit += 1
            first = sorted(e.get("timestamp", "") for e in evs)[0]
            row = {"rule": title, "status": "СОБЫТИЕ ЕСТЬ",
                   "detail": "событий %d, первое %s; техники: %s" % (len(evs), first, tids)}
            lat = _latency_approx(since, first)
            if lat is not None:
                row["latency_sec"] = lat
                row["latency_approx"] = True
                row["detail"] += " (задержка от --since ~%.0fs, приблизительно)" % lat
            rows.append(row)
        else:
            rows.append({"rule": title, "status": "НЕТ СОБЫТИЯ",
                         "detail": "правило ожидается по технике, но событие не создано; техники: %s. Проверьте, "
                                   "что adversary-профиль CALDERA реально выполнил способность на этом хосте, что "
                                   "агент дошёл до Graylog и что прошло 10+ минут" % tids})
    if not rule:
        covered = {t for tids in by_rule.values() for t in tids}
        if wanted - covered:
            missing = sorted(wanted - covered)
            rows.append({"rule": "(без правил)", "status": "ПРОПУЩЕНО",
                         "detail": "под эти техники нет ни одного правила в каталоге: %s" % ", ".join(missing)})
    total = len(by_rule)
    summary = "правил под указанные техники %d, событий получено %d, без события %d" % (total, hit, total - hit)
    return rows, summary


def _latency_approx(since, first_ts):
    try:
        ev_dt = datetime.fromisoformat(str(first_ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if ev_dt.tzinfo is None:
        ev_dt = ev_dt.replace(tzinfo=timezone.utc)
    return max(0.0, (ev_dt - since).total_seconds())
