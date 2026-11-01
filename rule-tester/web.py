#!/usr/bin/env python3
"""Веб-интерфейс rule-tester: правила из Graylog, запуск проверок, история результатов.

Только стандартная библиотека. Настройки через переменные окружения:
  GRAYLOG_URL, GRAYLOG_TOKEN   доступ к Graylog (токен только на чтение)
  RT_GELF, RT_STREAM           вход GELF HTTP и тестовый поток
  RT_PASSWORD                  пароль входа в интерфейс (обязателен)
  RT_INSECURE=1, RT_CA_FILE    проверка сертификата Graylog
  RT_DATA                      каталог для истории (в контейнере — том /data)
  RT_SCHEDULE                  расписание, например «queries@02:30,selftest@03:00» (время по TZ контейнера)
  RT_E2E_PLATFORMS             платформы для ночного e2e, например «Windows» (по умолчанию e2e по расписанию выключен)
  RT_PORT                      порт (по умолчанию 8080)
"""
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import graylog_api as G  # noqa: E402
import rule_tester as R  # noqa: E402

HERE = Path(__file__).resolve().parent
PASSWORD = os.environ.get("RT_PASSWORD", "")
SESSIONS = {}
JOB = {"lock": threading.Lock(), "cur": None, "last": None}
RULES_CACHE = {"t": 0, "data": None}
MODES = {"queries": "run-queries", "e2e": "run-e2e", "doctor": "doctor", "selftest": "selftest", "harvest": "harvest"}


def env_args():
    return SimpleNamespace(url=None, token_env="GRAYLOG_TOKEN", insecure=os.environ.get("RT_INSECURE") == "1",
                           ca_file=os.environ.get("RT_CA_FILE"))


def base_cmd():
    c = [sys.executable, str(HERE / "rule_tester.py")]
    for flag, var in (("--gelf", "RT_GELF"), ("--stream", "RT_STREAM"), ("--ca-file", "RT_CA_FILE")):
        if os.environ.get(var):
            c += [flag, os.environ[var]]
    if os.environ.get("RT_INSECURE") == "1":
        c.append("--insecure")
    return c


def start_job(mode, platform="", rule="", confirm=False, who="вручную"):
    if mode not in MODES:
        return None, "неизвестный режим"
    if mode == "e2e" and not confirm:
        return None, "для режима «до алерта» нужно подтверждение"
    if mode == "e2e" and not (platform or rule):
        return None, "для режима «до алерта» выберите платформу или правило"
    with JOB["lock"]:
        if JOB["cur"] and JOB["cur"]["status"] == "идёт":
            return None, "уже идёт другой запуск"
        cmd = base_cmd()
        if platform:
            cmd += ["--platform", platform]
        if rule:
            cmd += ["--rule", rule]
        cmd.append(MODES[mode])
        if mode == "e2e":
            cmd.append("--yes-send-alerts")
        job = {"id": datetime.now().strftime("%Y%m%d-%H%M%S"), "mode": mode, "platform": platform, "rule": rule,
               "who": who, "started": datetime.now().isoformat(timespec="seconds"), "status": "идёт", "log": ""}
        JOB["cur"] = job
    threading.Thread(target=run_job, args=(job, cmd), daemon=True).start()
    return job, None


def run_job(job, cmd):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                             env=dict(os.environ, PYTHONUNBUFFERED="1"))
        for line in p.stdout:
            job["log"] += line
            job["log"] = job["log"][-60000:]
        p.wait()
        job["code"] = p.returncode
        job["status"] = "успешно" if p.returncode == 0 else "есть замечания"
    except Exception as e:  # noqa: BLE001
        job["log"] += "\nОшибка запуска: %s\n" % e
        job["status"] = "ошибка"
    job["finished"] = datetime.now().isoformat(timespec="seconds")
    with JOB["lock"]:
        JOB["last"] = job
    hist = R.DATA / "history.jsonl"
    hist.parent.mkdir(parents=True, exist_ok=True)
    with hist.open("a", encoding="utf-8") as f:
        f.write(json.dumps({k: v for k, v in job.items() if k != "log"}, ensure_ascii=False) + "\n")


def rules_payload(force=False):
    if not force and RULES_CACHE["data"] and time.time() - RULES_CACHE["t"] < 60:
        return RULES_CACHE["data"]
    note, src = "", "Graylog"
    try:
        rules = R.load_live_rules(R.connect(env_args()))
    except (G.ApiError, SystemExit) as e:
        rules, src, note = R.load_file_rules(), "каталог в репозитории", "Graylog недоступен: %s" % e
    samples, rep = R.build_samples(rules)
    cnt = {}
    for s in samples:
        c = cnt.setdefault(s["rule"], [0, 0])
        c[0 if s["expect"] == "match" else 1] += 1
    file_q = {r["title"]: r["query"] for r in R.load_file_rules()}
    out = []
    for r in rules:
        rp = rep.get(r["title"], {})
        flags = []
        if rp.get("placeholder"):
            flags.append("заглушка в запросе")
        if rp.get("error"):
            flags.append(rp["error"])
        flags += rp.get("lint", [])
        if src == "Graylog" and r["title"] in file_q and file_q[r["title"]].strip() != r["query"].strip() \
                and not rp.get("placeholder"):
            flags.append("запрос отличается от каталога")
        kind = "тишина" if R.is_silence(r["cond"]) else ("агрегация" if r["cond"] else "событие")
        out.append({"title": r["title"], "platform": R.platform_of(r["title"]), "priority": r["priority"],
                    "streams": r["streams"], "query": r["query"], "kind": kind,
                    "pos": cnt.get(r["title"], [0, 0])[0], "neg": cnt.get(r["title"], [0, 0])[1], "flags": flags})
    data = {"source": src, "note": note, "rules": out, "fetched": datetime.now().isoformat(timespec="seconds")}
    RULES_CACHE.update(t=time.time(), data=data)
    return data


def reports_list():
    items = []
    for p in sorted(R.REPORTS.glob("*.json"), reverse=True)[:100]:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            items.append({"file": p.name, "run": d.get("run"), "kind": d.get("kind"), "summary": d.get("summary")})
        except (OSError, ValueError):
            continue
    return items


def scheduler():
    spec = [x.strip() for x in os.environ.get("RT_SCHEDULE", "").split(",") if "@" in x]
    done = set()
    while spec:
        now = datetime.now()
        for item in spec:
            mode, hhmm = item.split("@", 1)
            key = (item, now.strftime("%Y-%m-%d"))
            if now.strftime("%H:%M") >= hhmm and key not in done and now.strftime("%H:%M") < _plus(hhmm, 10):
                done.add(key)
                if mode == "e2e":
                    plats = [p for p in os.environ.get("RT_E2E_PLATFORMS", "").split(",") if p]
                    for pl in plats:
                        while JOB["cur"] and JOB["cur"]["status"] == "идёт":
                            time.sleep(10)
                        start_job("e2e", platform=pl, confirm=True, who="расписание")
                else:
                    start_job(mode, who="расписание")
        time.sleep(30)


def _plus(hhmm, minutes):
    h, m = map(int, hhmm.split(":"))
    t = h * 60 + m + minutes
    return "%02d:%02d" % (min(t // 60, 23), t % 60 if t < 1440 else 59)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj, code=200, ctype="application/json", headers=None):
        b = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def authed(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "rt_session" and v in SESSIONS:
                return True
        return False

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(min(n, 100000)) or b"{}")
        except ValueError:
            return {}

    def do_GET(self):
        path, _, qs = self.path.partition("?")
        if path == "/":
            return self.reply((HERE / "web_index.html").read_bytes(), ctype="text/html")
        if not self.authed():
            return self.reply({"error": "нужен вход"}, 401)
        if path == "/api/status":
            e = {k: bool(os.environ.get(k)) for k in ("GRAYLOG_URL", "GRAYLOG_TOKEN", "RT_GELF", "RT_STREAM")}
            return self.reply({"env": e, "job": _pub(JOB["cur"] or JOB["last"]), "schedule": os.environ.get("RT_SCHEDULE", "")})
        if path == "/api/rules":
            return self.reply(rules_payload(force="refresh" in qs))
        if path == "/api/job":
            return self.reply({"job": _pub(JOB["cur"] or JOB["last"], log=True)})
        if path == "/api/history":
            hist = R.DATA / "history.jsonl"
            rows = []
            if hist.exists():
                rows = [json.loads(x) for x in hist.read_text(encoding="utf-8").splitlines()[-100:]][::-1]
            return self.reply({"history": rows, "reports": reports_list()})
        if path == "/api/report":
            name = Path(qs.partition("file=")[2]).name
            p = R.REPORTS / name
            if not name.endswith(".json") or not p.is_file():
                return self.reply({"error": "нет такого отчёта"}, 404)
            return self.reply(p.read_bytes())
        self.reply({"error": "не найдено"}, 404)

    def do_POST(self):
        path = self.path.split("?")[0]
        b = self.body()
        if path == "/api/login":
            ok = PASSWORD and hmac.compare_digest(hashlib.sha256(str(b.get("password", "")).encode()).digest(),
                                                  hashlib.sha256(PASSWORD.encode()).digest())
            if not ok:
                time.sleep(1)
                return self.reply({"error": "неверный пароль"}, 403)
            tok = secrets.token_urlsafe(32)
            SESSIONS[tok] = time.time()
            return self.reply({"ok": True}, headers={"Set-Cookie": "rt_session=%s; HttpOnly; SameSite=Strict; Path=/" % tok})
        if not self.authed():
            return self.reply({"error": "нужен вход"}, 401)
        if path == "/api/run":
            job, err = start_job(str(b.get("mode", "")), str(b.get("platform", ""))[:40], str(b.get("rule", ""))[:120],
                                 bool(b.get("confirm")))
            if err:
                return self.reply({"error": err}, 400)
            return self.reply({"job": _pub(job)})
        self.reply({"error": "не найдено"}, 404)


def _pub(job, log=False):
    if not job:
        return None
    d = {k: v for k, v in job.items() if k != "log"}
    if log:
        d["log"] = job["log"]
    return d


def main():
    if not PASSWORD:
        sys.exit("Не задан RT_PASSWORD: без пароля веб-интерфейс не запускается (он умеет создавать алерты).")
    port = int(os.environ.get("RT_PORT", "8080"))
    threading.Thread(target=scheduler, daemon=True).start()
    print("rule-tester: http://0.0.0.0:%d" % port, flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()


if __name__ == "__main__":
    main()
