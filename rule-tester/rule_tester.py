#!/usr/bin/env python3
"""Автоматическая проверка правил Graylog без запуска чего-либо на хостах.

Режимы:
  selftest     офлайн: разбор всех запросов, сборка образцов, проверка самих образцов, замечания к регулярным выражениям
  list         список правил и число образцов
  generate     записать собранные образцы в файл для просмотра
  doctor       проверить доступ к Graylog, вход GELF и тестовый поток
  setup        создать тестовый поток (с --apply)
  harvest      собрать настоящие сообщения по запросам правил, обезличить, сохранить
  run-queries  отправить образцы в тестовый поток и проверить, какие запросы их находят (алертов нет)
  run-e2e      отправить образцы в боевой путь и дождаться событий (будут настоящие алерты)

Токен API: переменная окружения GRAYLOG_TOKEN. Адрес: --url или GRAYLOG_URL.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import graylog_api as G  # noqa: E402
from version import NAME, VERSION  # noqa: E402
import lucene as L  # noqa: E402

HERE = Path(__file__).resolve().parent
CATALOG = HERE.parent / "graylog" / "detections" / "detections-source.json"
DATA = Path(os.environ.get("RT_DATA") or HERE)  # в контейнере: том с историей и собранными образцами
MANUAL = HERE / "samples" / "manual.json"            # в репозитории (git)
VOL_MANUAL = DATA / "samples" / "manual.json"        # правки из интерфейса (том контейнера)
HARVESTED = DATA / "samples" / "harvested.json"
REPORTS = DATA / "reports"
NUMERIC_DEFAULT = {"win_event_id"}
PLACEHOLDER = re.compile(r"<[^<>]*[А-Яа-яЁё][^<>]*>")


# ---------------------------------------------------------------- правила

def platform_of(title):
    return re.split(r"\s*[-:]\s", title, maxsplit=1)[0].strip()


def cond_of(c):
    """Приводит условие определения событий к {'op','value'} или None."""
    if not c:
        return None
    if "op" in c:
        return c
    ex = c.get("expression") if isinstance(c, dict) else None
    if isinstance(ex, dict) and ex.get("expr") in (">", ">=", "<", "<=", "=="):
        right = ex.get("right") or {}
        if right.get("expr") == "number":
            return {"op": ex["expr"], "value": right.get("value")}
    return None


def is_silence(cond):
    return bool(cond) and cond["op"] in ("<", "<=", "==") and (cond["value"] or 0) <= 1


def threshold(cond):
    if not cond or is_silence(cond):
        return 1
    v = int(cond["value"] or 0)
    return v + 1 if cond["op"] == ">" else max(v, 1)


def load_file_rules():
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    out = []
    for d in data["definitions"]:
        out.append({"title": d["title"], "query": d["query"], "streams": d["streams"], "stream_ids": [],
                    "group_by": d.get("group_by") or [], "cond": cond_of(d.get("condition")),
                    "window_min": d.get("window_min"), "every_min": 5, "id": None, "priority": d.get("priority")})
    return out


def load_live_rules(gl):
    names = {s["id"]: s["title"] for s in gl.streams()}
    out = []
    for e in gl.event_definitions():
        c = e.get("config", {})
        if c.get("type") != "aggregation-v1":
            continue
        cond = cond_of(c.get("conditions"))
        sids = c.get("streams") or []
        out.append({"title": e["title"], "query": c.get("query", ""), "streams": [names.get(s, s) for s in sids],
                    "stream_ids": sids, "group_by": c.get("group_by") or [], "cond": cond,
                    "window_min": (c.get("search_within_ms") or 0) / 60000.0,
                    "every_min": (c.get("execute_every_ms") or 300000) / 60000.0,
                    "id": e["id"], "priority": e.get("priority")})
    return out


def filter_rules(rules, args):
    sel = rules
    if getattr(args, "rule", None):
        exact = [r[1:] for r in args.rule if r.startswith("=")]
        subs = [s.strip().lower() for r in args.rule if not r.startswith("=") for s in r.split(",") if s.strip()]
        sel = [r for r in sel if r["title"] in exact or any(s in r["title"].lower() for s in subs)]
    if getattr(args, "platform", None):
        p = args.platform.lower()
        sel = [r for r in sel if platform_of(r["title"]).lower().startswith(p)]
    return sel


# ---------------------------------------------------------------- образцы

def sid(title, kind, n):
    return "%s%s%d" % (hashlib.sha1(title.encode("utf-8")).hexdigest()[:8], kind, n)


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def load_manual():
    """Ручные образцы: из репозитория и с тома; у каждого образца помечено происхождение."""
    out = {}
    for origin, path in (("репозиторий", MANUAL), ("том", VOL_MANUAL)):
        for key, v in load_json(path, {}).items():
            e = out.setdefault(key, {"positive": [], "negative": []})
            for kind in ("positive", "negative"):
                for it in v.get(kind, []):
                    e[kind].append(dict(it, origin=origin))
    return out


def build_samples(rules, variants=3, use_manual=True, use_harvest=True):
    manual = load_manual() if use_manual else {}
    harv = load_json(HARVESTED, {}) if use_harvest else {}
    out, report = [], {}
    for r in rules:
        title = r["title"]
        if PLACEHOLDER.search(r["query"]):
            report[title] = {"placeholder": PLACEHOLDER.search(r["query"]).group(0)}
            continue
        try:
            node, warns = L.parse(r["query"])
        except L.QueryError as e:
            report[title] = {"error": "запрос не разобран: %s" % e}
            continue
        lint = []
        for lit in L.literals(node):
            if lit.kind == "regex":
                lint += ["%s: %s" % (lit.field, m) for m in L.lucene_regex_lint(lit.text)]
        pos, neg, problems = L.make_samples(node, r["group_by"], max_pos=variants)
        items = [("auto", "P", p) for p in pos] + [("auto", "N", n) for n in neg]
        for key, extra in list(manual.items()) + list(harv.items()):
            if key.lower() in title.lower():
                src = "manual" if key in manual else "harvest"
                items += [(src, "P", x) for x in extra.get("positive", [])]
                items += [(src, "N", x) for x in extra.get("negative", [])]
        rng = sorted({l.field for l in L.literals(node) if l.kind == "range"})
        counters = {"P": 0, "N": 0}
        for src, kind, it in items:
            counters[kind] += 1
            doc = it["doc"]
            expect = "match" if kind == "P" else "no_match"
            agree = L.evaluate(node, doc) == (kind == "P")
            out.append({"id": sid(title, kind, counters[kind]), "rule": title, "expect": expect, "doc": doc,
                        "why": it.get("why", ""), "src": src, "offline_ok": agree, "numeric": rng,
                        "origin": it.get("origin", "авто" if src == "auto" else "")})
        report[title] = {"warns": sorted(set(warns)), "lint": lint, "problems": problems,
                         "pos": len(pos), "neg": len(neg)}
    return out, report


def prepare_doc(sample, run, numeric):
    numeric = set(numeric) | set(sample.get("numeric", []))
    d = {}
    for k, v in sample["doc"].items():
        if k in numeric and isinstance(v, str) and re.fullmatch(r"-?\d+", v):
            v = int(v)
        d[k] = v
    d.setdefault("source", "rt-tester")
    d["rt_run"] = run
    d["rt_sample"] = sample["id"]
    return d


# ---------------------------------------------------------------- подключение

def connect(args, need_token=True):
    url = args.url or os.environ.get("GRAYLOG_URL")
    token = os.environ.get(args.token_env)
    if not url:
        sys.exit("Не задан адрес Graylog: --url или GRAYLOG_URL (например https://graylog.apps.monitoring.test)")
    if need_token and not token:
        sys.exit("Не задан токен API: переменная окружения %s. Создайте токен в Graylog (профиль → Edit tokens) "
                 "под учётной записью с правом чтения." % args.token_env)
    return G.Graylog(url, token, insecure=args.insecure, ca_file=args.ca_file)


def get_rules(args, gl=None):
    if args.source == "file" or (args.source == "auto" and gl is None):
        return load_file_rules(), "файл каталога"
    if gl is None:
        gl = connect(args)
    return load_live_rules(gl), "Graylog"


def resolve_stream(gl, name):
    if not name:
        return None
    for s in gl.streams():
        if name in (s["id"], s["title"]):
            return s["id"]
    sys.exit("Поток %r не найден. Создайте его: rule_tester.py setup --apply" % name)


def run_id():
    return "rt" + datetime.now().strftime("%m%d%H%M%S") + hashlib.sha1(os.urandom(4)).hexdigest()[:3]


def log(*a):
    print(*a, flush=True)


# ---------------------------------------------------------------- команды без Graylog

def cmd_list(args):
    rules = filter_rules(load_file_rules(), args)
    samples, rep = build_samples(rules, args.variants)
    per = {}
    for s in samples:
        per.setdefault(s["rule"], []).append(s)
    log("%-4s %-64s %s" % ("№", "Правило", "обр.(+/−)  тип"))
    for i, r in enumerate(rules, 1):
        ss = per.get(r["title"], [])
        p = sum(1 for s in ss if s["expect"] == "match")
        kind = "тишина" if is_silence(r["cond"]) else ("агрегация" if r["cond"] else "событие")
        log("%-4d %-64s %2d/%-2d     %s" % (i, r["title"][:64], p, len(ss) - p, kind))
    log("\nПравил: %d, образцов: %d" % (len(rules), len(samples)))


def cmd_selftest(args):
    rules = filter_rules(load_file_rules(), args)
    samples, rep = build_samples(rules, args.variants)
    bad = 0
    ph = [(t, v["placeholder"]) for t, v in rep.items() if v.get("placeholder")]
    no_pos = [t for t, v in rep.items() if not v.get("placeholder") and (v.get("error") or not v.get("pos"))]
    disagree = [s for s in samples if not s["offline_ok"]]
    lint = [(t, m) for t, v in rep.items() for m in v.get("lint", [])]
    warns = [(t, m) for t, v in rep.items() for m in v.get("warns", [])]
    log("Правил: %d. Образцов: %d (положительных %d, отрицательных %d)." % (
        len(rules), len(samples), sum(s["expect"] == "match" for s in samples),
        sum(s["expect"] == "no_match" for s in samples)))
    log("Правил с заглушкой вместо значений в каталоге (проверяйте с --source live): %d" % len(ph))
    for t, h in ph:
        log("  - %s: %s" % (t, h))
    log("Правил без положительного образца: %d" % len(no_pos))
    for t in no_pos:
        log("  - %s: %s" % (t, rep[t].get("error") or "; ".join(rep[t].get("problems", []))))
    log("Образцов, где эталонный вычислитель не согласен с ожиданием: %d" % len(disagree))
    for s in disagree:
        log("  - %s [%s] %s" % (s["rule"], s["src"], s["why"]))
    log("Замечания к регулярным выражениям Lucene: %d" % len(lint))
    for t, m in lint:
        log("  - %s\n      %s" % (t, m))
    if warns:
        log("Прочие замечания: %d" % len(warns))
        for t, m in warns:
            log("  - %s: %s" % (t, m))
    if args.cross:
        nodes = {r["title"]: L.parse(r["query"])[0] for r in rules
                 if not is_silence(r["cond"]) and r["query"].strip() != "*"}
        log("\nПерекрёстные срабатывания (первый образец правила находят запросы других правил):")
        seen, done = 0, set()
        for s in samples:
            if s["expect"] != "match" or s["rule"] in done or s["rule"] not in nodes:
                continue
            done.add(s["rule"])
            others = [t for t, n in nodes.items() if t != s["rule"] and L.evaluate(n, s["doc"])]
            if others:
                seen += 1
                log("  %s → ещё: %s" % (s["rule"][:60], "; ".join(o[:50] for o in others[:3])))
        log("  правил с перекрытием: %d" % seen)
    bad = len(no_pos) + len(disagree)
    log("\nИтог: %s" % ("всё согласовано" if not bad else "есть расхождения (%d)" % bad))
    return 1 if bad else 0


def cmd_generate(args):
    rules = filter_rules(load_file_rules(), args)
    samples, rep = build_samples(rules, args.variants)
    out = Path(args.out)
    out.write_text(json.dumps({"generated": datetime.now().isoformat(timespec="seconds"), "samples": samples,
                               "report": rep}, ensure_ascii=False, indent=1), encoding="utf-8")
    log("Записано %d образцов для %d правил: %s" % (len(samples), len(rules), out))
    return 0


# ---------------------------------------------------------------- команды с Graylog

def cmd_doctor(args):
    ok = True

    def check(name, fn):
        nonlocal ok
        try:
            msg = fn()
            log("  ✓ %s%s" % (name, (" — " + msg) if msg else ""))
            return True
        except Exception as e:  # noqa: BLE001
            ok = False
            log("  ✗ %s — %s" % (name, e))
            return False

    gl = connect(args)
    log("Проверка доступа")
    check("REST и токен", lambda: "Graylog %s" % gl.system().get("version"))
    defs = {}

    def defs_check():
        defs["live"] = load_live_rules(gl)
        return "%d определений событий" % len(defs["live"])
    if check("определения событий (чтение)", defs_check):
        file_rules = {r["title"]: r for r in load_file_rules()}
        live = {r["title"]: r for r in defs["live"]}
        miss = [t for t in file_rules if t not in live]
        extra = [t for t in live if t not in file_rules]
        diff = [t for t in live if t in file_rules and live[t]["query"].strip() != file_rules[t]["query"].strip()]
        log("      совпадают по названию: %d; нет в Graylog: %d; нет в каталоге: %d; запрос отличается: %d" % (
            len(live) - len(extra), len(miss), len(extra), len(diff)))
        for t in diff[:10]:
            log("        отличается: %s" % t)
    sid_ = {}

    def stream_check():
        if not args.stream:
            raise RuntimeError("тестовый поток не задан (--stream), поиск пойдёт по всем потокам")
        sid_["id"] = resolve_stream(gl, args.stream)
        return "id %s" % sid_["id"]
    check("тестовый поток", stream_check)
    if args.gelf:
        run = run_id() + "d"

        def gelf_check():
            G.send_gelf(args.gelf, {"message": "rule-tester doctor", "source": "rt-doctor", "rt_run": run,
                                    "rt_sample": run + "p1"}, ctx=gl.ctx)
            found = G.wait_until(lambda: gl.search_messages("rt_run:%s" % run, [sid_["id"]] if sid_.get("id") else None,
                                                            minutes=5)[0] or None, 45)
            if not found:
                raise RuntimeError("отправлено, но в поиске за 45 с не появилось (проверьте правило потока rt_run и индекс-набор)")
            return "сообщение дошло и найдено"
        check("вход GELF HTTP и индексация", gelf_check)
    else:
        log("  – вход GELF не задан (--gelf http://хост:12201/gelf), отправку не проверяем")
    log("\n%s" % ("Всё готово к run-queries." if ok else "Есть проблемы, см. ✗ выше."))
    return 0 if ok else 1


def cmd_setup(args):
    gl = connect(args)
    title = args.stream or "Rule Tester"
    existing = [s for s in gl.streams() if s["title"] == title]
    if existing:
        log("Поток %r уже есть (id %s). Ничего не меняю." % (title, existing[0]["id"]))
        return 0
    sets = gl.index_sets()
    log("Индекс-наборы:")
    for s in sets:
        log("  %s  %s%s" % (s["id"], s["title"], "  (по умолчанию)" if s.get("default") else ""))
    chosen = args.index_set or next((s["id"] for s in sets if s.get("default")), sets[0]["id"])
    log("План: создать поток %r (правило: есть поле rt_run; из «All messages» сообщения убираются), "
        "индекс-набор %s." % (title, chosen))
    log("Рекомендация: заведите отдельный индекс-набор с коротким хранением (1 день) и укажите его: --index-set ID.")
    if not args.apply:
        log("Это пробный показ. Для создания добавьте --apply.")
        return 0
    new = gl.create_test_stream(title, chosen)
    log("Создан и запущен поток %r, id %s." % (title, new))
    log("Вход GELF HTTP создайте вручную: System → Inputs → GELF HTTP → Launch (порт 12201).")
    return 0


STRIP = re.compile(r"^(gl2_|streams$|_id$|timestamp$|message_id$|winlogbeat_agent_|winlogbeat_ecs_|winlogbeat_@|"
                   r"filebeat_agent_|filebeat_ecs_)")


def anonymize(doc, extra_words, ipmap, hostmap):
    ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    mail = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
    mac = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

    def ip_sub(m):
        v = m.group(0)
        if v in ("127.0.0.1", "0.0.0.0") or v.startswith("255."):
            return v
        if v not in ipmap:
            ipmap[v] = "192.0.2.%d" % (len(ipmap) % 250 + 1)
        return ipmap[v]
    out = {}
    for k, v in doc.items():
        if STRIP.match(k):
            continue
        if isinstance(v, str):
            v = ip.sub(ip_sub, v)
            v = mail.sub("user@example.test", v)
            v = mac.sub("00:00:5e:00:53:01", v)
            for w in extra_words:
                v = re.sub(re.escape(w), "redacted", v, flags=re.I)
        out[k] = v
    if "source" in out:
        out["source"] = hostmap.setdefault(out["source"], "rt-host-%d" % (len(hostmap) + 1))
    return out


def cmd_harvest(args):
    gl = connect(args)
    rules = filter_rules(load_live_rules(gl), args)
    extra = [w for w in (args.redact or "").split(",") if w]
    store = load_json(HARVESTED, {})
    ipmap, hostmap, got, empty, broken = {}, {}, 0, [], []
    for r in rules:
        if is_silence(r["cond"]) or r["query"].strip() in ("*", ""):
            continue
        try:
            node, _ = L.parse(r["query"])
            total, msgs = gl.search_messages(r["query"], r["stream_ids"] or None, minutes=args.days * 1440,
                                             limit=args.per_rule)
        except (L.QueryError, G.ApiError) as e:
            broken.append((r["title"], str(e)[:120]))
            continue
        if not msgs:
            empty.append(r["title"])
            continue
        kept = []
        for m in msgs[:args.per_rule]:
            doc = anonymize(m, extra, ipmap, hostmap)
            if L.evaluate(node, doc):
                kept.append({"doc": doc, "why": "настоящее сообщение (обезличено), найдено запросом правила"})
        if kept:
            store.setdefault(r["title"], {})["positive"] = kept
            got += len(kept)
        else:
            broken.append((r["title"], "после обезличивания образец перестал проходить запрос"))
        log("  %-70s %s" % (r["title"][:70], "образцов: %d (в Graylog найдено %d)" % (len(kept), total)))
    HARVESTED.parent.mkdir(parents=True, exist_ok=True)
    HARVESTED.write_text(json.dumps(store, ensure_ascii=False, indent=1), encoding="utf-8")
    log("\nСобрано образцов: %d. Нет сообщений за %d дн. у правил: %d. Проблемы: %d." % (got, args.days, len(empty), len(broken)))
    for t, m in broken:
        log("  ! %s: %s" % (t, m))
    log("Файл %s не попадает в git (см. .gitignore); просмотрите его перед тем, как делиться." % HARVESTED)
    return 0


def numeric_fields(args):
    return NUMERIC_DEFAULT | set(x for x in (args.numeric or "").split(",") if x)


OKS = ("ПРОШЛО", "СОБЫТИЕ ЕСТЬ")


def stats_of(rows):
    return {"total": len(rows), "passed": sum(r["status"] in OKS for r in rows),
            "skipped": sum(r["status"] == "ПРОПУЩЕНО" for r in rows),
            "failed": sum(r["status"] not in OKS and r["status"] != "ПРОПУЩЕНО" for r in rows)}


def write_report(run, kind, rows, summary, meta=None):
    REPORTS.mkdir(parents=True, exist_ok=True)
    data = {"run": run, "kind": kind, "version": VERSION, "created": datetime.now().isoformat(timespec="seconds"),
            "summary": summary, "stats": stats_of(rows), "meta": meta or {}, "rows": rows}
    (REPORTS / ("%s-%s.json" % (run, kind))).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    md = ["# %s %s: проверка правил (%s), запуск %s" % (NAME, VERSION, kind, run), "", "Итог: " + summary, "",
          "| Правило | Результат | Подробности |", "|---|---|---|"]
    for r in rows:
        md.append("| %s | %s | %s |" % (r["rule"].replace("|", "/"), r["status"], r["detail"].replace("|", "/")))
    p = REPORTS / ("%s-%s.md" % (run, kind))
    p.write_text("\n".join(md) + "\n", encoding="utf-8")
    return p


def cmd_run_queries(args):
    gl = connect(args)
    rules, src = get_rules(args, gl)
    rules = filter_rules(rules, args)
    if not rules:
        sys.exit("Нет правил под фильтр.")
    stream = resolve_stream(gl, args.stream)
    if not stream:
        log("! Тестовый поток не задан: сообщения попадут в обычные потоки. Лучше: setup --apply и --stream «Rule Tester».")
    if not args.gelf:
        sys.exit("Не задан вход GELF: --gelf http://хост:12201/gelf")
    samples, rep = build_samples(rules, args.variants)
    if not samples:
        sys.exit("Нет образцов.")
    run, num = run_id(), numeric_fields(args)
    log("Запуск %s: правил %d (источник: %s), образцов %d. Алерты не создаются (поток тестовый)." % (run, len(rules), src, len(samples)))
    for s in samples:
        G.send_gelf(args.gelf, prepare_doc(s, run, num), ctx=gl.ctx)
    log("Отправлено, жду индексации…")
    sids = [stream] if stream else None
    ok = G.wait_until(lambda: gl.search_messages("rt_run:%s" % run, sids, minutes=10, limit=1)[0] >= len(samples) or None,
                      args.index_wait)
    if not ok:
        got = gl.search_messages("rt_run:%s" % run, sids, minutes=10, limit=1)[0]
        log("! Проиндексировано %d из %d. Часть результатов будет «нет в индексе»." % (got, len(samples)))
    per = {}
    for s in samples:
        per.setdefault(s["rule"], []).append(s)
    rows, bad = [], 0
    for r in rules:
        ss = per.get(r["title"])
        if not ss:
            rp = rep.get(r["title"], {})
            why = ("заглушка в запросе каталога: %s (запускайте с источником Graylog)" % rp["placeholder"]) if rp.get("placeholder") \
                else rp.get("error", "нет образцов")
            rows.append({"rule": r["title"], "status": "ПРОПУЩЕНО", "detail": why, "query": r["query"],
                         "platform": platform_of(r["title"]), "priority": r.get("priority"), "samples": []})
            log("  %-9s %s" % ("ПРОПУЩЕНО", r["title"][:90]))
            continue
        ids = " OR ".join(s["id"] for s in ss)
        q = "rt_run:%s AND rt_sample:(%s) AND (%s)" % (run, ids, r["query"])
        try:
            _, msgs = gl.search_messages(q, sids, minutes=10, limit=len(ss) + 5, fields=["rt_sample"])
        except G.ApiError as e:
            rows.append({"rule": r["title"], "status": "ОШИБКА ЗАПРОСА", "detail": str(e)[:300], "query": r["query"],
                         "platform": platform_of(r["title"]), "priority": r.get("priority"), "samples": []})
            log("  %-9s %s" % ("ОШИБКА ЗАПРОСА", r["title"][:90]))
            bad += 1
            continue
        found = {m.get("rt_sample") for m in msgs}
        miss = [s for s in ss if s["expect"] == "match" and s["id"] not in found]
        false = [s for s in ss if s["expect"] == "no_match" and s["id"] in found]
        sam = [{"id": s["id"], "expect": s["expect"], "src": s["src"], "origin": s.get("origin", ""), "why": s["why"],
                "found": s["id"] in found, "ok": (s["id"] in found) == (s["expect"] == "match"), "doc": s["doc"]} for s in ss]
        details = []
        for s in miss:
            details.append("не найдено [%s] %s" % (s["src"], s["why"][:60]))
        for s in false:
            details.append("ложное срабатывание [%s] %s" % (s["src"], s["why"][:60]))
        for s in miss + false:
            if not s["offline_ok"]:
                details.append("(эталонный вычислитель тоже не согласен — образец неверный)")
        if miss or false:
            bad += 1
            hint = diagnose(gl, run, miss[0], sids) if miss else ""
            rows.append({"rule": r["title"], "status": "ПРОВАЛ", "detail": "; ".join(details) + hint, "query": r["query"],
                         "platform": platform_of(r["title"]), "priority": r.get("priority"), "samples": sam})
        else:
            rows.append({"rule": r["title"], "status": "ПРОШЛО",
                         "detail": "найдено %d из %d положительных, отрицательных не найдено: %d" % (
                             sum(s["expect"] == "match" for s in ss), sum(s["expect"] == "match" for s in ss),
                             sum(s["expect"] == "no_match" for s in ss)), "query": r["query"],
                         "platform": platform_of(r["title"]), "priority": r.get("priority"), "samples": sam})
        log("  %-9s %s" % (rows[-1]["status"], r["title"][:90]))
    summary = "правил %d, прошло %d, провалов %d" % (len(rows), sum(r["status"] == "ПРОШЛО" for r in rows), bad)
    path = write_report(run, "queries", rows, summary, {"platform": getattr(args, "platform", None) or "",
                                                       "rule": ",".join(args.rule or []), "source": src})
    log("\n" + summary + "\nОтчёт: " + str(path))
    return 1 if bad else 0


def diagnose(gl, run, sample, sids):
    """Сравнивает отправленные поля с проиндексированными: пайплайн мог изменить или убрать поле."""
    try:
        _, msgs = gl.search_messages("rt_sample:%s" % sample["id"], sids, minutes=10, limit=1)
    except G.ApiError:
        return ""
    if not msgs:
        return " | образец не найден в индексе (не дошёл или в другом потоке)"
    stored, diffs = msgs[0], []
    for k, v in sample["doc"].items():
        if k == "source":
            continue
        sv = stored.get(k)
        if sv is None:
            diffs.append("%s: поле пропало" % k)
        elif str(sv) != str(v):
            diffs.append("%s: изменено пайплайном/маппингом" % k)
    return (" | расхождения полей: " + ", ".join(diffs[:5])) if diffs else " | поля в индексе совпадают с отправленными — запрос не находит образец"


def stream_fix(rules_, doc):
    unmet = []
    for sr in rules_:
        f, t, v, inv = sr.get("field"), sr.get("type"), sr.get("value", ""), sr.get("inverted")
        have = doc.get(f)
        if t == 7:
            continue
        if t == 5:
            ok = have is not None
        elif t == 1:
            ok = have is not None and str(have) == v
        elif t == 2:
            ok = have is not None and re.search(v, str(have)) is not None
        elif t == 6:
            ok = have is not None and v in str(have)
        else:
            ok = None
        if ok is None:
            unmet.append("правило типа %s по полю %s" % (t, f))
            continue
        if ok == bool(inv):
            if not inv and t in (1, 5):
                doc[f] = v if t == 1 else "rt"
            else:
                unmet.append("поле %s не удовлетворяет правилу потока" % f)
    return unmet


def cmd_run_e2e(args):
    if not args.yes_send_alerts:
        sys.exit("Режим создаёт НАСТОЯЩИЕ события и отправляет уведомления (почту). Подтвердите флагом --yes-send-alerts.")
    if not args.rule and not args.platform and not args.all:
        sys.exit("Укажите, что проверять: --rule, --platform или --all.")
    if not args.gelf:
        sys.exit("Нужен --gelf: адрес входа, сообщения с которого попадают в боевые потоки.")
    gl = connect(args)
    rules = [r for r in filter_rules(load_live_rules(gl), args) if not is_silence(r["cond"]) and r["query"].strip() != "*"]
    if not rules:
        sys.exit("Нет подходящих правил (правила «тишина» этим режимом не проверяются).")
    samples, rep = build_samples(rules, args.variants)
    pos = {}
    for s in samples:
        if s["expect"] == "match":
            pos.setdefault(s["rule"], s)
    run, num = run_id(), numeric_fields(args)
    stream_cache, plan, t0 = {}, [], G.now_utc()
    log("Запуск %s: правил %d. Сообщения пойдут в боевые потоки, сработают настоящие алерты." % (run, len(rules)))
    for r in rules:
        s = pos.get(r["title"])
        if not s:
            plan.append((r, None, "нет образца"))
            continue
        doc = prepare_doc(s, run, num)
        unmet = []
        for sid_ in r["stream_ids"]:
            if sid_ not in stream_cache:
                stream_cache[sid_] = gl.stream_rules(sid_)
            unmet += stream_fix(stream_cache[sid_], doc)
        if unmet:
            plan.append((r, None, "поток не примет сообщение: " + "; ".join(unmet[:2])))
            continue
        plan.append((r, doc, ""))
    sent = []
    for r, doc, why in plan:
        if not doc:
            continue
        for _ in range(threshold(r["cond"])):
            G.send_gelf(args.gelf, doc, ctx=gl.ctx)
        sent.append(r)
        log("  отправлено: %s (копий %d)" % (r["title"][:80], threshold(r["cond"])))
    t0 = t0 - timedelta(minutes=1)
    seen, deadline = {}, time.time() + args.wait
    log("Жду события до %d с (проверка каждые 20 с)…" % args.wait)
    while time.time() < deadline and len(seen) < len(sent):
        evs = gl.search_events([r["id"] for r in sent], t0)
        for e in evs:
            did = e.get("event_definition_id")
            if did and did not in seen:
                seen[did] = e
        time.sleep(20)
    rows, bad = [], 0
    for r, doc, why in plan:
        if not doc:
            rows.append({"rule": r["title"], "status": "ПРОПУЩЕНО", "detail": why})
        elif r["id"] in seen:
            rows.append({"rule": r["title"], "status": "СОБЫТИЕ ЕСТЬ", "detail": "событие %s в %s" % (
                seen[r["id"]].get("id", "")[:12], seen[r["id"]].get("timestamp", ""))})
        else:
            bad += 1
            rows.append({"rule": r["title"], "status": "НЕТ СОБЫТИЯ", "detail":
                         "за %d с события не было: проверьте, что поток принял сообщение, и период тишины/интервал запуска" % args.wait})
    summary = "правил %d, событий получено %d, без события %d" % (len(rows), len(seen), bad)
    byt = {r["title"]: r for r in rules}
    for row in rows:
        r = byt.get(row["rule"], {})
        row.update(query=r.get("query", ""), platform=platform_of(row["rule"]), priority=r.get("priority"), samples=[])
    path = write_report(run, "e2e", rows, summary, {"platform": getattr(args, "platform", None) or "",
                                                    "rule": ",".join(args.rule or []), "source": "Graylog"})
    for r in rows:
        log("  %-13s %s" % (r["status"], r["rule"][:90]))
    log("\n" + summary + "\nОтчёт: " + str(path))
    return 1 if bad else 0


# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", help="адрес Graylog (или GRAYLOG_URL)")
    ap.add_argument("--token-env", default="GRAYLOG_TOKEN", help="переменная окружения с токеном API")
    ap.add_argument("--insecure", action="store_true", help="не проверять сертификат (только лаборатория)")
    ap.add_argument("--ca-file", help="файл CA для проверки сертификата Graylog")
    ap.add_argument("--gelf", help="адрес входа GELF HTTP, например http://graylog:12201/gelf")
    ap.add_argument("--stream", help="название или id тестового потока")
    ap.add_argument("--source", choices=["auto", "file", "live"], default="auto",
                    help="откуда брать правила: каталог в репозитории или Graylog")
    ap.add_argument("--rule", action="append", help="часть названия правила (можно несколько, через запятую)")
    ap.add_argument("--platform", help="префикс платформы: Windows, LNX, macOS, FREEIPA, HEALTH …")
    ap.add_argument("--variants", type=int, default=3, help="сколько положительных вариантов на правило")
    ap.add_argument("--numeric", help="поля, которые отправлять числом (через запятую), по умолчанию win_event_id")
    ap.add_argument("--version", action="version", version="%s %s" % (NAME, VERSION))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    p = sub.add_parser("selftest")
    p.add_argument("--cross", action="store_true", help="показать перекрытия между правилами")
    p = sub.add_parser("generate")
    p.add_argument("--out", default=str(HERE / "samples" / "generated.json"))
    sub.add_parser("doctor")
    p = sub.add_parser("setup")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--index-set")
    p = sub.add_parser("harvest")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--per-rule", type=int, default=1)
    p.add_argument("--redact", help="слова для замены на redacted, через запятую")
    p = sub.add_parser("run-queries")
    p.add_argument("--index-wait", type=int, default=90)
    p = sub.add_parser("run-e2e")
    p.add_argument("--wait", type=int, default=720)
    p.add_argument("--all", action="store_true")
    p.add_argument("--yes-send-alerts", action="store_true")
    args = ap.parse_args(argv)
    fn = {"list": cmd_list, "selftest": cmd_selftest, "generate": cmd_generate, "doctor": cmd_doctor,
          "setup": cmd_setup, "harvest": cmd_harvest, "run-queries": cmd_run_queries, "run-e2e": cmd_run_e2e}[args.cmd]
    try:
        return fn(args) or 0
    except G.ApiError as e:
        log("Ошибка Graylog: %s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
