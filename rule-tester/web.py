#!/usr/bin/env python3
"""GraylogRuleTester: веб-интерфейс проверки правил Graylog.

Только стандартная библиотека. Настройки берутся из переменных окружения, а изменения из интерфейса
сохраняются на томе (RT_DATA/settings.json) и имеют приоритет:
  GRAYLOG_URL, GRAYLOG_TOKEN   доступ к Graylog (токен только на чтение)
  RT_GELF, RT_STREAM           вход GELF HTTP и тестовый поток
  RT_PASSWORD                  пароль администратора (обязателен)
  RT_VIEWER_PASSWORD           пароль наблюдателя: только просмотр (необязателен)
  RT_INSECURE=1, RT_CA_FILE    проверка сертификата Graylog
  RT_DATA                      каталог тома: история, отчёты, образцы, настройки, журнал
  RT_SCHEDULE                  расписание: «queries@02:30,selftest@03:00,drift@03:30,e2e@04:00»
  RT_SCHEDULE_ENABLED          "0" — выключить запуски по расписанию, не трогая само расписание (по умолчанию включено)
  RT_E2E_PLATFORMS             платформы для ночного e2e (по умолчанию e2e по расписанию выключен)
  RT_PORT                      порт (по умолчанию 8080)
"""
import csv
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import graylog_api as G  # noqa: E402
import insights  # noqa: E402
import lucene as L  # noqa: E402
import mdlite  # noqa: E402
import rule_tester as R  # noqa: E402
from version import NAME, VERSION  # noqa: E402

HERE = Path(__file__).resolve().parent
GUIDE_MD = HERE.parent / "docs" / "17-admin-guide-ruletester.md"
GUIDE_IMAGES = HERE.parent / "docs" / "images"
GUIDE_IMAGE_RE = re.compile(r"17-[\w-]+\.png")
SESSIONS = {}
JOB = {"lock": threading.Lock(), "cur": None, "last": None}
CACHE = {}
LIVE = {"t": 0, "data": {}, "running": False, "done": 0, "total": 0, "error": ""}
MODES = {"queries": "run-queries", "e2e": "run-e2e", "doctor": "doctor", "selftest": "selftest", "harvest": "harvest",
         "art": "art-verify", "method": "method-verify", "drift": "drift", "fp": "fp-check", "latency": "latency"}
MODE_RU = {"queries": "Запросы в тестовом потоке", "e2e": "До алерта", "doctor": "Проверка доступа",
           "selftest": "Самопроверка запросов", "harvest": "Сбор настоящих сообщений",
           "drift": "Сверка каталога с Graylog", "fp": "Проверка ложных срабатываний",
           "latency": "Задержка обнаружения"}
SETTING_ENV = {"graylog_url": "GRAYLOG_URL", "graylog_token": "GRAYLOG_TOKEN", "gelf": "RT_GELF", "stream": "RT_STREAM",
               "schedule": "RT_SCHEDULE", "schedule_enabled": "RT_SCHEDULE_ENABLED", "e2e_platforms": "RT_E2E_PLATFORMS",
               "insecure": "RT_INSECURE", "ca_file": "RT_CA_FILE"}
OK_STATUS = ("ПРОШЛО", "СОБЫТИЕ ЕСТЬ", "ЧИСТО", "ИЗМЕРЕНО")
ADMIN_LOGIN = "admin"  # единственная учётная запись; другие пока не планируются


# ------------------------------------------------------------------ настройки, журнал

def settings_path():
    return R.DATA / "settings.json"


def load_settings():
    try:
        return json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def cfg(name):
    v = load_settings().get(name)
    if v not in (None, ""):
        return str(v)
    return os.environ.get(SETTING_ENV[name], "")


def save_settings(data):
    cur = load_settings()
    for k, v in data.items():
        if k in SETTING_ENV:
            if k == "graylog_token" and not v:
                continue  # пустое поле токена = «не менять»
            cur[k] = v
    settings_path().parent.mkdir(parents=True, exist_ok=True)
    tmp = settings_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(cur, ensure_ascii=False, indent=1), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(settings_path())
    CACHE.clear()


def audit(role, ip, action, detail=""):
    p = R.DATA / "audit.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"t": datetime.now().isoformat(timespec="seconds"), "role": role, "ip": ip,
                            "action": action, "detail": str(detail)[:300]}, ensure_ascii=False) + "\n")


def child_env():
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    for k in ("graylog_url", "graylog_token"):
        if cfg(k):
            env[SETTING_ENV[k]] = cfg(k)
    return env


def connect_gl():
    url, tok = cfg("graylog_url"), cfg("graylog_token")
    if not url:
        raise G.ApiError("не задан адрес Graylog (Настройки)")
    return G.Graylog(url, tok, insecure=cfg("insecure") == "1", ca_file=cfg("ca_file") or None, timeout=15)


def base_cmd():
    c = [sys.executable, str(HERE / "rule_tester.py")]
    for flag, key in (("--gelf", "gelf"), ("--stream", "stream"), ("--ca-file", "ca_file")):
        if cfg(key):
            c += [flag, cfg(key)]
    if cfg("insecure") == "1":
        c.append("--insecure")
    return c


# ------------------------------------------------------------------ запуски

def start_job(mode, platform="", rule="", confirm=False, who="вручную", since=""):
    if mode not in MODES:
        return None, "неизвестный режим"
    if mode == "art":
        if platform not in ("linux", "macos", "windows"):
            return None, "для сверки Atomic Red Team выберите систему: linux, macos или windows"
        import art
        try:
            art.parse_time(since)
        except ValueError as e:
            return None, str(e)
    if mode == "method":
        if platform not in ("linux", "macos", "windows", "freeipa", "containers", "keenetic"):
            return None, "для сверки проверки детектов выберите систему: linux, macos, windows, freeipa, containers или keenetic"
        import art
        try:
            art.parse_time(since)
        except ValueError as e:
            return None, str(e)
    if mode == "e2e" and not confirm:
        return None, "для режима «до алерта» нужно подтверждение"
    if mode == "e2e" and not (platform or rule):
        return None, "для режима «до алерта» выберите платформу или правило"
    with JOB["lock"]:
        if JOB["cur"] and JOB["cur"]["status"] == "идёт":
            return None, "уже идёт другой запуск"
        cmd = base_cmd()
        if platform and mode not in ("art", "method"):
            cmd += ["--platform", platform]
        if rule and mode not in ("art", "method"):
            cmd += ["--rule", rule]
        cmd.append(MODES[mode])
        if mode in ("art", "method"):
            cmd += ["--os", platform, "--since", since]
        if mode == "e2e":
            cmd.append("--yes-send-alerts")
        job = {"id": datetime.now().strftime("%Y%m%d-%H%M%S"), "mode": mode, "platform": platform,
               "rule": rule.lstrip("="), "who": who, "started": datetime.now().isoformat(timespec="seconds"),
               "status": "идёт", "log": "", "total": 0, "passed": 0, "failed": 0, "skipped": 0}
        JOB["cur"] = job
    threading.Thread(target=run_job, args=(job, cmd), daemon=True).start()
    return job, None


STATUS_LINE = re.compile(r"^\s+(ПРОШЛО|ПРОВАЛ|ПРОПУЩЕНО|ОШИБКА ЗАПРОСА|СОБЫТИЕ ЕСТЬ|НЕТ СОБЫТИЯ|РАСХОЖДЕНИЕ|ЧИСТО|ЕСТЬ СОВПАДЕНИЯ|ИЗМЕРЕНО)\s")
TOTAL_LINE = re.compile(r"правил (\d+)")


def run_job(job, cmd):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=child_env())
        for line in p.stdout:
            job["log"] = (job["log"] + line)[-80000:]
            if not job["total"]:
                m = TOTAL_LINE.search(line)
                if m and line.startswith("Запуск"):
                    job["total"] = int(m.group(1))
            m = STATUS_LINE.match(line)
            if m:
                st = m.group(1)
                key = "passed" if st in OK_STATUS else "skipped" if st == "ПРОПУЩЕНО" else "failed"
                job[key] += 1
        p.wait()
        job["code"] = p.returncode
        job["status"] = "успешно" if p.returncode == 0 else "есть замечания"
    except Exception as e:  # noqa: BLE001
        job["log"] += "\nОшибка запуска: %s\n" % e
        job["status"] = "ошибка"
    job["finished"] = datetime.now().isoformat(timespec="seconds")
    CACHE.pop("results", None)
    CACHE.pop("rules", None)
    with JOB["lock"]:
        JOB["last"] = job
    hist = R.DATA / "history.jsonl"
    hist.parent.mkdir(parents=True, exist_ok=True)
    with hist.open("a", encoding="utf-8") as f:
        f.write(json.dumps({k: v for k, v in job.items() if k != "log"}, ensure_ascii=False) + "\n")


def pub_job(job, log=False):
    if not job:
        return None
    d = {k: v for k, v in job.items() if k != "log"}
    if log:
        d["log"] = job["log"]
    return d


# ------------------------------------------------------------------ отчёты

def read_reports(limit=200):
    out = []
    for p in sorted(R.REPORTS.glob("*.json"), reverse=True)[:limit]:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        d["file"] = p.name
        out.append(d)
    return out


def report_head(d):
    return {"file": d["file"], "run": d.get("run"), "kind": d.get("kind"), "summary": d.get("summary"),
            "created": d.get("created") or "", "stats": d.get("stats") or R.stats_of(d.get("rows", [])),
            "meta": d.get("meta") or {}, "version": d.get("version", "")}


def last_results():
    """Последний известный результат каждого правила по отчётам вида queries (новые отчёты важнее)."""
    c = CACHE.get("results")
    if c and time.time() - c[0] < 30:
        return c[1]
    res = {}
    for d in read_reports():
        if d.get("kind") != "queries":
            continue
        for row in d.get("rows", []):
            res.setdefault(row["rule"], {"status": row["status"], "run": d.get("run"),
                                         "created": d.get("created") or "", "file": d["file"]})
    CACHE["results"] = (time.time(), res)
    return res


def load_report(name):
    name = Path(name).name
    p = R.REPORTS / name
    if not name.endswith(".json") or not p.is_file():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    d["file"] = name
    return d


def compare(a, b):
    ra = {r["rule"]: r["status"] for r in a["rows"]}
    rb = {r["rule"]: r["status"] for r in b["rows"]}
    ok = lambda s: s in OK_STATUS  # noqa: E731
    out = {"broke": [], "fixed": [], "still_bad": [], "new": [], "gone": []}
    for t, sb in rb.items():
        if t not in ra:
            out["new"].append({"rule": t, "to": sb})
        elif ok(ra[t]) and not ok(sb) and sb != "ПРОПУЩЕНО":
            out["broke"].append({"rule": t, "from": ra[t], "to": sb})
        elif not ok(ra[t]) and ra[t] != "ПРОПУЩЕНО" and ok(sb):
            out["fixed"].append({"rule": t, "from": ra[t], "to": sb})
        elif not ok(sb) and sb != "ПРОПУЩЕНО":
            out["still_bad"].append({"rule": t, "from": ra[t], "to": sb})
    out["gone"] = [{"rule": t} for t in ra if t not in rb]
    return out


def trend():
    items = []
    for d in read_reports(120):
        if d.get("kind") != "queries":
            continue
        h = report_head(d)
        m = h["meta"]
        h["full"] = not m.get("platform") and not m.get("rule")
        items.append(h)
    return sorted(items, key=lambda x: x["created"])[-40:]


# ------------------------------------------------------------------ правила и образцы

def rules_data(force=False):
    c = CACHE.get("rules")
    if c and not force and time.time() - c[0] < 60:
        return c[1]
    note, src = "", "Graylog"
    try:
        rules = R.load_live_rules(connect_gl())
    except G.ApiError as e:
        rules, src, note = R.load_file_rules(), "каталог в репозитории", "Graylog недоступен: %s" % e
    meta = insights.catalog_meta(R.CATALOG)
    samples, rep = R.build_samples(rules)
    cnt = {}
    for s in samples:
        c2 = cnt.setdefault(s["rule"], {"pos": 0, "neg": 0, "manual": 0})
        c2["pos" if s["expect"] == "match" else "neg"] += 1
        if s["src"] in ("manual", "harvest"):
            c2["manual"] += 1
    file_q = {r["title"]: r["query"] for r in R.load_file_rules()}
    first_pos = {}
    for s in samples:
        if s["expect"] == "match":
            first_pos.setdefault(s["rule"], s["doc"])
    out = []
    for r in rules:
        rp = rep.get(r["title"], {})
        flags = []
        if rp.get("placeholder"):
            flags.append("заглушка в запросе каталога: " + rp["placeholder"])
        if rp.get("error"):
            flags.append(rp["error"])
        flags += rp.get("lint", [])
        if src == "Graylog" and r["title"] in file_q and file_q[r["title"]].strip() != r["query"].strip() \
                and not rp.get("placeholder"):
            flags.append("запрос в Graylog отличается от каталога репозитория")
        m = meta.get(r["title"], {})
        out.append({"title": r["title"], "platform": R.platform_of(r["title"]), "priority": r["priority"],
                    "streams": r["streams"], "query": r["query"], "id": r.get("id"),
                    "kind": "тишина" if R.is_silence(r["cond"]) else ("агрегация" if r["cond"] else "событие"),
                    "tactic": m.get("tactic", "—"), "techniques": m.get("techniques", []),
                    "counts": cnt.get(r["title"], {"pos": 0, "neg": 0, "manual": 0}), "flags": flags})
    data = {"source": src, "note": note, "rules": out, "fetched": datetime.now().isoformat(timespec="seconds"),
            "_first_pos": first_pos}
    CACHE["rules"] = (time.time(), data)
    return data


def rule_by_title(title):
    return next((r for r in rules_data()["rules"] if r["title"] == title), None)


def vol_manual():
    return R.load_json(R.VOL_MANUAL, {})


def write_vol_manual(data):
    R.VOL_MANUAL.parent.mkdir(parents=True, exist_ok=True)
    tmp = R.VOL_MANUAL.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(R.VOL_MANUAL)
    CACHE.pop("rules", None)


def rule_detail(title):
    r = rule_by_title(title)
    if not r:
        return None
    rule = {"title": r["title"], "query": r["query"], "streams": r["streams"], "kind": r["kind"],
            "group_by": [], "cond": None, "priority": r["priority"], "id": r["id"]}
    samples, _ = R.build_samples([rule])
    vol = vol_manual().get(title, {})
    seen = {"positive": 0, "negative": 0}
    out = []
    for s in samples:
        item = {"id": s["id"], "expect": s["expect"], "src": s["src"], "origin": s.get("origin", ""), "why": s["why"],
                "doc": s["doc"], "offline_ok": s["offline_ok"], "vol_index": None}
        if s["src"] == "manual" and s.get("origin") == "том":
            kind = "positive" if s["expect"] == "match" else "negative"
            item["vol_kind"] = kind
            # индекс среди образцов тома этого вида
            item["vol_index"] = seen[kind]
            seen[kind] += 1
        out.append(item)
    return {"rule": r, "samples": out, "last": last_results().get(title),
            "live": LIVE["data"].get(title)}


def check_sample(title, kind, doc):
    r = rule_by_title(title)
    if not r:
        return {"error": "нет такого правила"}
    if not isinstance(doc, dict) or not doc or len(doc) > 60:
        return {"error": "образец: объект с полями (до 60)"}
    for k, v in doc.items():
        if not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_][\w.\-]{0,120}", k):
            return {"error": "недопустимое имя поля: %r" % k[:40] if isinstance(k, str) else "недопустимое имя поля"}
        if not isinstance(v, (str, int, float, bool)) or len(str(v)) > 4000:
            return {"error": "значение поля %s: строка или число до 4000 знаков" % k}
    if any("заглушка" in f for f in r["flags"]):
        return {"match": None, "note": "в запросе каталога заглушка, проверка возможна только на живом Graylog"}
    try:
        node, _ = L.parse(r["query"])
    except L.QueryError as e:
        return {"error": "запрос не разобран: %s" % e}
    m = L.evaluate(node, doc)
    want = (kind == "positive")
    return {"match": m, "ok": m == want,
            "note": "эталонный вычислитель %s образец (ожидалось: %s)" % ("находит" if m else "не находит",
                                                                           "находит" if want else "не находит")}


# ------------------------------------------------------------------ живые счётчики, связь

def live_worker():
    LIVE.update(running=True, done=0, error="")
    try:
        gl = connect_gl()
        rules = [r for r in R.load_live_rules(gl) if r.get("id")]
        LIVE["total"] = len(rules)
        data = {}

        def one(r):
            try:
                data[r["title"]] = {"d7": gl.count_events(r["id"], 7), "d30": gl.count_events(r["id"], 30),
                                    "last": gl.last_event(r["id"])}
            except G.ApiError:
                data[r["title"]] = {"d7": None, "d30": None, "last": None}
            LIVE["done"] += 1
        with ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(one, rules))
        LIVE["data"] = data
        LIVE["t"] = time.time()
    except G.ApiError as e:
        LIVE["error"] = str(e)
    LIVE["running"] = False


def health():
    c = CACHE.get("health")
    if c and time.time() - c[0] < 30:
        return c[1]
    h = {"graylog": {"ok": False, "text": ""}, "stream": {"ok": False, "text": ""},
         "gelf": {"ok": bool(cfg("gelf")), "text": cfg("gelf") or "не задан"}}
    try:
        gl = connect_gl()
        h["graylog"] = {"ok": True, "text": "Graylog %s" % gl.system().get("version", "")}
        name = cfg("stream")
        if not name:
            h["stream"]["text"] = "не задан"
        else:
            ok = any(name in (s["id"], s["title"]) for s in gl.streams())
            h["stream"] = {"ok": ok, "text": name if ok else "поток «%s» не найден" % name}
    except G.ApiError as e:
        h["graylog"]["text"] = str(e)[:160]
    CACHE["health"] = (time.time(), h)
    return h


def next_run():
    best = None
    for item in [x.strip() for x in cfg("schedule").split(",") if "@" in x]:
        mode, hhmm = item.split("@", 1)
        try:
            h, m = map(int, hhmm.split(":"))
        except ValueError:
            continue
        t = datetime.now().replace(hour=h, minute=m, second=0, microsecond=0)
        if t <= datetime.now():
            t += timedelta(days=1)
        if not best or t < best[0]:
            best = (t, mode)
    return {"at": best[0].isoformat(timespec="minutes"), "mode": MODE_RU.get(best[1], best[1])} if best else None


DRIFT_RE = re.compile(r"расхождения полей: ([^|]+)")


def field_drift(rows):
    """Собирает по всем провалам прогона поля, которые пропали/изменились при индексации
    (см. rule_tester.diagnose), и группирует по имени поля — чтобы одно изменение пайплайна/маппинга,
    задевшее сразу много правил, было видно одной строкой, а не разбором каждого провала по отдельности."""
    by_field = {}
    for r in rows:
        m = DRIFT_RE.search(r.get("detail") or "")
        if not m:
            continue
        for part in m.group(1).split(","):
            name = part.split(":", 1)[0].strip()
            if not name:
                continue
            by_field.setdefault(name, []).append(r["rule"])
    out = [{"field": f, "count": len(rules), "rules": rules, "platforms": sorted({R.platform_of(t) for t in rules})}
           for f, rules in by_field.items()]
    return sorted(out, key=lambda x: -x["count"])


_GUIDE_CACHE = {"mtime": None, "html": ""}


def guide_html():
    """Руководство администратора (docs/17-admin-guide-ruletester.md), пересобирается, только когда файл меняется."""
    try:
        mtime = GUIDE_MD.stat().st_mtime
    except OSError:
        return "<p>Файл docs/17-admin-guide-ruletester.md не найден в образе контейнера.</p>"
    if _GUIDE_CACHE["mtime"] != mtime:
        md = GUIDE_MD.read_text(encoding="utf-8")
        _GUIDE_CACHE["html"] = mdlite.convert(md)
        _GUIDE_CACHE["mtime"] = mtime
    return _GUIDE_CACHE["html"]


def summary():
    rd = rules_data()
    reps = [report_head(d) for d in read_reports(60)]
    queries = [r for r in reps if r["kind"] == "queries"]
    last = queries[0] if queries else None
    fails = []
    drift = []
    if last:
        full = load_report(last["file"])
        fail_rows = [r for r in full["rows"] if r["status"] not in OK_STATUS and r["status"] != "ПРОПУЩЕНО"]
        fails = [{"rule": r["rule"], "status": r["status"], "detail": r["detail"][:200]} for r in fail_rows][:30]
        drift = field_drift(fail_rows)
    flagged = sum(1 for r in rd["rules"] if r["flags"])
    lr = last_results()
    return {"rules": len(rd["rules"]), "source": rd["source"], "note": rd["note"], "flagged": flagged,
            "last": last, "fails": fails, "field_drift": drift, "next": next_run(), "health": health(),
            "known_failed": sum(1 for v in lr.values() if v["status"] not in OK_STATUS and v["status"] != "ПРОПУЩЕНО"),
            "known_passed": sum(1 for v in lr.values() if v["status"] in OK_STATUS),
            "platforms": sorted({r["platform"] for r in rd["rules"]}), "job": pub_job(JOB["cur"] or JOB["last"])}


# ------------------------------------------------------------------ расписание

def scheduler():
    done = set()
    while True:
        if cfg("schedule_enabled") == "0":
            time.sleep(30)
            continue
        spec = [x.strip() for x in cfg("schedule").split(",") if "@" in x]
        now = datetime.now()
        for item in spec:
            mode, hhmm = item.split("@", 1)
            key = (item, now.strftime("%Y-%m-%d"))
            if mode in MODES and re.fullmatch(r"\d\d:\d\d", hhmm) and key not in done \
                    and hhmm <= now.strftime("%H:%M") < _plus(hhmm, 10):
                done.add(key)
                if mode == "e2e":
                    for pl in [p for p in cfg("e2e_platforms").split(",") if p]:
                        while JOB["cur"] and JOB["cur"]["status"] == "идёт":
                            time.sleep(10)
                        start_job("e2e", platform=pl, confirm=True, who="расписание")
                else:
                    start_job(mode, who="расписание")
        time.sleep(30)


def _plus(hhmm, minutes):
    h, m = map(int, hhmm.split(":"))
    t = min(h * 60 + m + minutes, 23 * 60 + 59)
    return "%02d:%02d" % (t // 60, t % 60)


# ------------------------------------------------------------------ вывод отчётов

def report_csv(d):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Правило", "Платформа", "Результат", "Подробности"])
    for r in d["rows"]:
        w.writerow([r["rule"], r.get("platform", ""), r["status"], r["detail"]])
    return ("\ufeff" + buf.getvalue()).encode("utf-8")


def report_html(d):
    h = report_head(d)
    st = h["stats"]
    rows = "".join("<tr class='%s'><td>%s</td><td>%s</td><td>%s</td></tr>" % (
        "ok" if r["status"] in OK_STATUS else "sk" if r["status"] == "ПРОПУЩЕНО" else "bad",
        html.escape(r["rule"]), html.escape(r["status"]), html.escape(r["detail"])) for r in d["rows"])
    return ("""<!doctype html><html lang="ru"><meta charset="utf-8"><title>%s: отчёт %s</title>
<style>body{font:14px/1.45 system-ui,sans-serif;margin:24px;color:#111}h1{font-size:20px;margin:0 0 4px}
.mut{color:#555}table{border-collapse:collapse;width:100%%;margin-top:16px}td,th{border:1px solid #ccc;padding:5px 8px;text-align:left;vertical-align:top}
tr.bad td:nth-child(2){color:#b00020;font-weight:600}tr.ok td:nth-child(2){color:#127a3d}tr.sk td:nth-child(2){color:#9a6a00}
@media print{body{margin:8mm}}</style>
<h1>%s %s: отчёт проверки правил</h1><div class="mut">Запуск %s, вид %s, %s. Версия отчёта %s.</div>
<p><b>Итог:</b> %s. Прошло %s, провалов %s, пропущено %s из %s.</p>
<table><tr><th>Правило</th><th>Результат</th><th>Подробности</th></tr>%s</table></html>""" % (
        NAME, html.escape(str(h["run"])), NAME, VERSION, html.escape(str(h["run"])), html.escape(str(h["kind"])),
        html.escape(h["created"]), html.escape(h["version"] or "—"), html.escape(h["summary"] or ""),
        st["passed"], st["failed"], st["skipped"], st["total"], rows)).encode("utf-8")


# ------------------------------------------------------------------ HTTP

class H(BaseHTTPRequestHandler):
    server_version = "GraylogRuleTester/" + VERSION

    def log_message(self, *a):
        pass

    def ip(self):
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()

    def reply(self, obj, code=200, ctype="application/json", headers=None):
        b = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def role(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "rt_session" and v in SESSIONS:
                s = SESSIONS[v]
                if time.time() - s["t"] > 12 * 3600:
                    SESSIONS.pop(v, None)
                    return None
                return s["role"]
        return None

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(min(n, 200000)) or b"{}")
        except ValueError:
            return {}

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        path = u.path
        if path == "/":
            return self.reply((HERE / "web_index.html").read_bytes(), ctype="text/html")
        if path == "/favicon.svg":
            return self.reply((HERE / "favicon.svg").read_bytes(), ctype="image/svg+xml")
        role = self.role()
        if not role:
            return self.reply({"error": "нужен вход"}, 401)
        if path.startswith("/guide-images/"):
            name = path[len("/guide-images/"):]
            if not GUIDE_IMAGE_RE.fullmatch(name):
                return self.reply({"error": "не найдено"}, 404)
            img = GUIDE_IMAGES / name
            if not img.is_file():
                return self.reply({"error": "не найдено"}, 404)
            return self.reply(img.read_bytes(), ctype="image/png")
        try:
            return self.get_api(path, q, role)
        except G.ApiError as e:
            return self.reply({"error": str(e)}, 502)

    def get_api(self, path, q, role):
        if path == "/api/status":
            return self.reply({"name": NAME, "version": VERSION, "role": role})
        if path == "/api/summary":
            return self.reply(summary())
        if path == "/api/guide":
            return self.reply({"html": guide_html()})
        if path == "/api/rules":
            d = rules_data(force="refresh" in q)
            lr, live = last_results(), LIVE["data"]
            rows = [dict(r, last=lr.get(r["title"]), live=live.get(r["title"])) for r in d["rules"]]
            return self.reply({"source": d["source"], "note": d["note"], "fetched": d["fetched"], "rules": rows,
                               "live_age": LIVE["t"]})
        if path == "/api/rule":
            d = rule_detail(q.get("title", ""))
            return self.reply(d if d else {"error": "нет такого правила"}, 200 if d else 404)
        if path == "/api/art":
            import art
            out = {}
            for plat in art.PLATFORMS:
                tests = art.load_plan(plat)
                out[plat] = {"name": art.PLATFORM_RU[plat], "file": art.runner_name(plat), "tests": tests,
                             "rules": sorted(art.plan_rules(tests))}
            for plat in out.values():
                for t in plat["tests"]:
                    t.pop("command", None)
                    t.pop("cleanup", None)
            return self.reply(out)
        if path == "/api/art/runner":
            import art
            plat = q.get("os", "")
            if plat not in art.PLATFORMS:
                return self.reply({"error": "система: linux, macos или windows"}, 400)
            return self.reply(art.gen_runner(plat).encode("utf-8"), ctype="text/plain",
                              headers={"Content-Disposition": 'attachment; filename="%s"' % art.runner_name(plat)})
        if path == "/api/method":
            import methodology as M
            out = {}
            for plat in M.PLATFORMS:
                tests = M.load_tests(plat)
                out[plat] = {"name": M.PLATFORM_RU[plat], "file": M.runner_filename(plat), "how": M.how_to_run(plat),
                             "tests": tests, "rules": sorted(M.plan_rules(tests))}
            return self.reply(out)
        if path == "/api/method/runner":
            import methodology as M
            plat = q.get("os", "")
            if plat not in M.PLATFORMS:
                return self.reply({"error": "система: linux, macos, windows или freeipa"}, 400)
            raw = M.runner_path(plat).read_bytes()
            return self.reply(raw, ctype="text/plain",
                              headers={"Content-Disposition": 'attachment; filename="%s"' % M.runner_filename(plat)})
        if path == "/api/job":
            return self.reply({"job": pub_job(JOB["cur"] or JOB["last"], log=True)})
        if path == "/api/history":
            hist = R.DATA / "history.jsonl"
            rows = []
            if hist.exists():
                rows = [json.loads(x) for x in hist.read_text(encoding="utf-8").splitlines()[-150:]][::-1]
            return self.reply({"history": rows, "reports": [report_head(d) for d in read_reports(100)]})
        if path == "/api/report":
            d = load_report(q.get("file", ""))
            return self.reply(d if d else {"error": "нет такого отчёта"}, 200 if d else 404)
        if path == "/api/report.csv":
            d = load_report(q.get("file", ""))
            if not d:
                return self.reply({"error": "нет такого отчёта"}, 404)
            return self.reply(report_csv(d), ctype="text/csv", headers={
                "Content-Disposition": 'attachment; filename="%s.csv"' % d["file"][:-5]})
        if path == "/report":
            d = load_report(q.get("file", ""))
            return self.reply(report_html(d), ctype="text/html") if d else self.reply({"error": "нет отчёта"}, 404)
        if path == "/api/compare":
            a, b = load_report(q.get("a", "")), load_report(q.get("b", ""))
            if not a or not b:
                return self.reply({"error": "выберите два отчёта"}, 400)
            return self.reply({"a": report_head(a), "b": report_head(b), "diff": compare(a, b)})
        if path == "/api/trend":
            return self.reply({"items": trend()})
        if path == "/api/coverage":
            import art
            import methodology as M
            rd = rules_data()
            art_titles, method_titles = set(), set()
            for plat in art.PLATFORMS:
                art_titles |= set(art.plan_rules(art.load_plan(plat)))
            for plat in M.PLATFORMS:
                method_titles |= set(M.plan_rules(M.load_tests(plat)))
            cov = insights.coverage(rd["rules"], insights.catalog_meta(R.CATALOG),
                                    {r["title"]: r["counts"] for r in rd["rules"]}, LIVE["data"],
                                    art_titles=art_titles, method_titles=method_titles)
            cov["live"] = {"age": LIVE["t"], "running": LIVE["running"], "done": LIVE["done"],
                           "total": LIVE["total"], "error": LIVE["error"]}
            return self.reply(cov)
        if path == "/api/quality":
            rd = rules_data()
            return self.reply({"issues": insights.quality(rd["rules"], rd["_first_pos"])})
        if path == "/api/live":
            return self.reply({"age": LIVE["t"], "running": LIVE["running"], "done": LIVE["done"],
                               "total": LIVE["total"], "error": LIVE["error"]})
        if path == "/api/samples/export":
            m = R.load_manual()
            clean = {k: {kk: [{"why": it.get("why", ""), "doc": it["doc"]} for it in v[kk]]
                         for kk in ("positive", "negative") if v[kk]} for k, v in m.items()}
            return self.reply(json.dumps(clean, ensure_ascii=False, indent=2).encode("utf-8"), headers={
                "Content-Disposition": 'attachment; filename="manual.json"'})
        if path == "/api/settings":
            s = {k: cfg(k) for k in SETTING_ENV if k != "graylog_token"}
            s["token_set"] = bool(cfg("graylog_token"))
            s["has_viewer"] = bool(os.environ.get("RT_VIEWER_PASSWORD"))
            return self.reply({"settings": s, "env_only": ["RT_PASSWORD", "RT_VIEWER_PASSWORD"]})
        if path == "/api/audit":
            if role != "admin":
                return self.reply({"error": "только администратор"}, 403)
            p = R.DATA / "audit.jsonl"
            rows = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()[-300:]][::-1] if p.exists() else []
            return self.reply({"audit": rows})
        return self.reply({"error": "не найдено"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self.reply({"error": "нужен JSON"}, 415)
        b = self.body()
        if path == "/api/login":
            login = str(b.get("login", "")).strip()
            pw = str(b.get("password", ""))
            admin, viewer = os.environ.get("RT_PASSWORD", ""), os.environ.get("RT_VIEWER_PASSWORD", "")
            eq = lambda x, y: bool(y) and hmac.compare_digest(hashlib.sha256(x.encode()).digest(),  # noqa: E731
                                                              hashlib.sha256(y.encode()).digest())
            login_ok = hmac.compare_digest(login.encode(), ADMIN_LOGIN.encode())
            role = ("admin" if eq(pw, admin) else "viewer" if eq(pw, viewer) else None) if login_ok else None
            if not role:
                audit("—", self.ip(), "вход не удался")
                time.sleep(1)
                return self.reply({"error": "неверный логин или пароль"}, 403)
            tok = secrets.token_urlsafe(32)
            SESSIONS[tok] = {"role": role, "t": time.time()}
            audit(role, self.ip(), "вход")
            return self.reply({"ok": True, "role": role}, headers={
                "Set-Cookie": "rt_session=%s; HttpOnly; SameSite=Strict; Path=/" % tok})
        role = self.role()
        if not role:
            return self.reply({"error": "нужен вход"}, 401)
        if path == "/api/logout":
            return self.reply({"ok": True}, headers={"Set-Cookie": "rt_session=; Max-Age=0; Path=/"})
        if path == "/api/samples/check":
            return self.reply(check_sample(str(b.get("rule", "")), str(b.get("kind", "positive")), b.get("doc")))
        if role != "admin":
            return self.reply({"error": "у роли «наблюдатель» только просмотр"}, 403)
        ip = self.ip()
        if path == "/api/run":
            mode, platform, rule = str(b.get("mode", "")), str(b.get("platform", ""))[:40], str(b.get("rule", ""))[:200]
            job, err = start_job(mode, platform, rule, bool(b.get("confirm")), since=str(b.get("since", ""))[:40])
            audit(role, ip, "запуск: %s" % mode, "платформа=%s правило=%s%s" % (platform, rule, "" if not err else " ОТКАЗ: " + err))
            return self.reply({"error": err} if err else {"job": pub_job(job)}, 400 if err else 200)
        if path == "/api/samples/save":
            title, kind = str(b.get("rule", "")), str(b.get("kind", ""))
            chk = check_sample(title, kind, b.get("doc"))
            if chk.get("error"):
                return self.reply(chk, 400)
            if kind not in ("positive", "negative"):
                return self.reply({"error": "вид образца: positive или negative"}, 400)
            data = vol_manual()
            e = data.setdefault(title, {"positive": [], "negative": []})
            e.setdefault(kind, []).append({"why": str(b.get("why", ""))[:200] or "ручной (из интерфейса)", "doc": b["doc"]})
            write_vol_manual(data)
            audit(role, ip, "образец добавлен", "%s / %s" % (title, kind))
            return self.reply(dict(chk, saved=True))
        if path == "/api/samples/delete":
            title, kind, idx = str(b.get("rule", "")), str(b.get("kind", "")), b.get("index")
            data = vol_manual()
            lst = data.get(title, {}).get(kind)
            if not isinstance(idx, int) or lst is None or not 0 <= idx < len(lst):
                return self.reply({"error": "образец не найден (образцы из репозитория удаляются правкой samples/manual.json)"}, 400)
            lst.pop(idx)
            if not data[title].get("positive") and not data[title].get("negative"):
                data.pop(title)
            write_vol_manual(data)
            audit(role, ip, "образец удалён", "%s / %s #%d" % (title, kind, idx))
            return self.reply({"ok": True})
        if path == "/api/settings/save":
            changed = [k for k in b if k in SETTING_ENV and (k != "graylog_token" or b[k])]
            save_settings({k: (str(v)[:500] if v is not None else "") for k, v in b.items()})
            audit(role, ip, "настройки изменены", ", ".join(changed))
            return self.reply({"ok": True})
        if path == "/api/live/refresh":
            if not LIVE["running"]:
                threading.Thread(target=live_worker, daemon=True).start()
            audit(role, ip, "обновление счётчиков срабатываний")
            return self.reply({"ok": True})
        self.reply({"error": "не найдено"}, 404)


def main():
    if not os.environ.get("RT_PASSWORD"):
        sys.exit("Не задан RT_PASSWORD: без пароля веб-интерфейс не запускается (он умеет создавать алерты).")
    port = int(os.environ.get("RT_PORT", "8080"))
    threading.Thread(target=scheduler, daemon=True).start()
    print("%s %s: http://0.0.0.0:%d" % (NAME, VERSION, port), flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()


if __name__ == "__main__":
    main()
