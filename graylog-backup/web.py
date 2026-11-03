#!/usr/bin/env python3
"""GraylogBackup: веб-интерфейс резервного копирования конфигурации Graylog.

Только стандартная библиотека. Настройки берутся из переменных окружения, а изменения из
интерфейса сохраняются на томе (GB_DATA/settings.json) и имеют приоритет:
  GRAYLOG_URL, GRAYLOG_TOKEN   доступ к Graylog REST (тот же токен, что у rule-tester, подходит)
  GB_MONGO_URI                 строка подключения к MongoDB Graylog, например
                                mongodb://host.containers.internal:27017/graylog
  GB_SERVER_CONF                путь к server.conf graylog-server внутри контейнера (монтируется
                                только для чтения, см. deploy/env.example HOST_SERVER_CONF);
                                пусто — шаг пропускается, password_secret/root_password_sha2 в
                                копию не попадут
  GB_PLUGIN_DIR                 путь к каталогу плагинов graylog-server внутри контейнера
                                (монтируется только для чтения, см. HOST_PLUGIN_DIR); пусто —
                                шаг пропускается
  GB_OPENSEARCH_URL            адрес OpenSearch/Elasticsearch (пусто — шаг search пропускается)
  GB_PASSWORD                  пароль администратора (обязателен, роль одна — других не бывает:
                                инструмент только читает и архивирует, ничего в Graylog не пишет)
  GB_INSECURE=1, GB_CA_FILE    проверка сертификата Graylog/OpenSearch
  GB_DATA                      каталог тома: архивы, настройки, журнал
  GB_RETENTION_DAYS            хранить столько последних дней архивов (пусто — бессрочно)
  GB_SCHEDULE                  время ежедневного автозапуска, «03:30» (пусто — по расписанию не запускать)
  GB_SCHEDULE_ENABLED          "0" — выключить расписание, не трогая само время
  GB_PORT                      порт (по умолчанию 8080)

restore-mongo (восстановление) в веб-интерфейс сознательно не вынесен — это редкая и опасная
операция (перетирает текущую базу Graylog), выполняется только руками из консоли: см. главу 18.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup as B  # noqa: E402
from version import NAME, VERSION  # noqa: E402

HERE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("GB_DATA", "/data"))
SESSIONS = {}
JOB = {"lock": threading.Lock(), "cur": None, "last": None}
ADMIN_LOGIN = "admin"
SETTING_ENV = {"graylog_url": "GRAYLOG_URL", "graylog_token": "GRAYLOG_TOKEN", "mongo_uri": "GB_MONGO_URI",
               "opensearch_url": "GB_OPENSEARCH_URL", "retention_days": "GB_RETENTION_DAYS",
               "schedule": "GB_SCHEDULE", "schedule_enabled": "GB_SCHEDULE_ENABLED",
               "insecure": "GB_INSECURE", "ca_file": "GB_CA_FILE"}


# ------------------------------------------------------------------ настройки, журнал

def settings_path():
    return DATA / "settings.json"


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


def audit(role, ip, action, detail=""):
    p = DATA / "audit.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"t": datetime.now().isoformat(timespec="seconds"), "role": role, "ip": ip,
                            "action": action, "detail": str(detail)[:300]}, ensure_ascii=False) + "\n")


def backups_dir():
    d = DATA / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def child_env():
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    for k in ("graylog_url", "graylog_token", "mongo_uri", "opensearch_url"):
        if cfg(k):
            env[SETTING_ENV[k]] = cfg(k)
    return env


def base_cmd():
    c = [sys.executable, str(HERE / "backup.py"), "--out-dir", str(backups_dir())]
    if cfg("ca_file"):
        c += ["--ca-file", cfg("ca_file")]
    if cfg("insecure") == "1":
        c.append("--insecure")
    return c


# ------------------------------------------------------------------ запуск резервного копирования

def start_job(skip_config=False, skip_mongo=False, skip_search=False, who="вручную"):
    with JOB["lock"]:
        if JOB["cur"] and JOB["cur"]["status"] == "идёт":
            return None, "уже идёт другой запуск"
        cmd = base_cmd() + ["run"]
        if skip_config:
            cmd.append("--skip-config")
        if skip_mongo:
            cmd.append("--skip-mongo")
        if skip_search:
            cmd.append("--skip-search")
        job = {"id": datetime.now().strftime("%Y%m%d-%H%M%S"), "who": who,
               "started": datetime.now().isoformat(timespec="seconds"), "status": "идёт", "log": ""}
        JOB["cur"] = job
    threading.Thread(target=run_job, args=(job, cmd), daemon=True).start()
    return job, None


def run_job(job, cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=child_env())
        job["log"] = ((p.stderr or "") + "\n" + (p.stdout or "")).strip()
        job["code"] = p.returncode
        meta = None
        try:
            meta = json.loads(p.stdout)
        except ValueError:
            pass
        job["meta"] = meta
        if meta:
            bad = [k for k, v in meta.get("steps", {}).items() if v.get("status") == "error"]
            partial = [k for k, v in meta.get("steps", {}).items() if v.get("status") == "partial"]
            job["status"] = "ошибка" if bad else ("есть замечания" if partial else "успешно")
        else:
            job["status"] = "ошибка" if p.returncode else "успешно"
    except subprocess.TimeoutExpired:
        job["status"] = "ошибка"
        job["log"] = (job.get("log", "") + "\nне уложилось в час — прервано").strip()
    except Exception as e:  # noqa: BLE001
        job["status"] = "ошибка"
        job["log"] = (job.get("log", "") + "\nОшибка запуска: %s" % e).strip()
    job["finished"] = datetime.now().isoformat(timespec="seconds")
    with JOB["lock"]:
        JOB["last"] = job


def pub_job(job):
    return job


def run_doctor():
    cmd = [sys.executable, str(HERE / "backup.py")]
    if cfg("ca_file"):
        cmd += ["--ca-file", cfg("ca_file")]
    if cfg("insecure") == "1":
        cmd.append("--insecure")
    cmd.append("doctor")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=child_env())
        return (p.stderr or p.stdout or "").strip(), p.returncode == 0
    except subprocess.TimeoutExpired:
        return "проверка не уложилась в 60 с", False


# ------------------------------------------------------------------ сводка, планировщик

def summary():
    rows = B.list_backups(backups_dir())
    last = rows[0] if rows else None
    return {"last": last, "count": len(rows), "schedule": cfg("schedule"),
            "schedule_enabled": cfg("schedule_enabled") != "0", "retention_days": cfg("retention_days"),
            "graylog_url_set": bool(cfg("graylog_url")), "mongo_set": bool(cfg("mongo_uri")),
            "opensearch_set": bool(cfg("opensearch_url")),
            "server_conf_set": bool(os.environ.get("GB_SERVER_CONF")),
            "plugin_dir_set": bool(os.environ.get("GB_PLUGIN_DIR"))}


def scheduler():
    last_run_day = None
    last_prune_day = None
    while True:
        days = cfg("retention_days")
        if days:
            today = datetime.now().strftime("%Y-%m-%d")
            if last_prune_day != today:
                last_prune_day = today
                try:
                    n = B.prune_backups(backups_dir(), int(days))
                    if n:
                        audit("—", "—", "автоочистка старых архивов", "удалено %d, хранить %s дн." % (n, days))
                except (OSError, ValueError):
                    pass
        if cfg("schedule_enabled") != "0":
            hhmm = cfg("schedule")
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")
            if re.fullmatch(r"\d\d:\d\d", hhmm or "") and last_run_day != today \
                    and hhmm <= now.strftime("%H:%M") < _plus(hhmm, 10):
                last_run_day = today
                job, err = start_job(who="расписание")
                if err:
                    audit("—", "—", "расписание: резервная копия не запущена", err)
        time.sleep(30)


def _plus(hhmm, minutes):
    h, m = map(int, hhmm.split(":"))
    t = min(h * 60 + m + minutes, 23 * 60 + 59)
    return "%02d:%02d" % (t // 60, t % 60)


# ------------------------------------------------------------------ веб-сервер

class H(BaseHTTPRequestHandler):
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
            if k == "gb_session" and v in SESSIONS:
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
        if path == "/api/status":
            return self.reply({"name": NAME, "version": VERSION, "role": role})
        if path == "/api/summary":
            return self.reply(summary())
        if path == "/api/backups":
            return self.reply({"backups": B.list_backups(backups_dir())})
        if path == "/api/backup/download":
            name = q.get("file", "")
            p = backups_dir() / name
            if "/" in name or not p.is_file():
                return self.reply({"error": "нет такого архива"}, 404)
            audit(role, self.ip(), "скачан архив", name)
            return self.reply(p.read_bytes(), ctype="application/gzip",
                              headers={"Content-Disposition": 'attachment; filename="%s"' % name})
        if path == "/api/job":
            return self.reply({"job": pub_job(JOB["cur"] or JOB["last"])})
        if path == "/api/settings":
            s = {k: cfg(k) for k in SETTING_ENV if k != "graylog_token"}
            s["token_set"] = bool(cfg("graylog_token"))
            s["server_conf_set"] = bool(os.environ.get("GB_SERVER_CONF"))
            s["plugin_dir_set"] = bool(os.environ.get("GB_PLUGIN_DIR"))
            return self.reply({"settings": s})
        if path == "/api/audit":
            p = DATA / "audit.jsonl"
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
            admin = os.environ.get("GB_PASSWORD", "")
            eq = lambda x, y: bool(y) and hmac.compare_digest(hashlib.sha256(x.encode()).digest(),  # noqa: E731
                                                              hashlib.sha256(y.encode()).digest())
            login_ok = hmac.compare_digest(login.encode(), ADMIN_LOGIN.encode())
            role = "admin" if (login_ok and eq(pw, admin)) else None
            if not role:
                audit("—", self.ip(), "вход не удался")
                time.sleep(1)
                return self.reply({"error": "неверный логин или пароль"}, 403)
            tok = secrets.token_urlsafe(32)
            SESSIONS[tok] = {"role": role, "t": time.time()}
            audit(role, self.ip(), "вход")
            return self.reply({"ok": True, "role": role}, headers={
                "Set-Cookie": "gb_session=%s; HttpOnly; SameSite=Strict; Path=/" % tok})
        role = self.role()
        if not role:
            return self.reply({"error": "нужен вход"}, 401)
        if path == "/api/logout":
            return self.reply({"ok": True}, headers={"Set-Cookie": "gb_session=; Max-Age=0; Path=/"})
        if path == "/api/run":
            job, err = start_job(skip_config=bool(b.get("skip_config")), skip_mongo=bool(b.get("skip_mongo")),
                                  skip_search=bool(b.get("skip_search")), who=role)
            if err:
                return self.reply({"error": err}, 409)
            audit(role, self.ip(), "резервная копия запущена")
            return self.reply({"ok": True, "job": job})
        if path == "/api/settings/check":
            text, ok = run_doctor()
            return self.reply({"ok": ok, "text": text})
        if path == "/api/settings/save":
            save_settings(b)
            audit(role, self.ip(), "настройки изменены", ", ".join(k for k in b if k in SETTING_ENV))
            return self.reply({"ok": True})
        if path == "/api/backup/delete":
            name = str(b.get("file", ""))
            p = backups_dir() / name
            if "/" in name or not p.is_file():
                return self.reply({"error": "нет такого архива"}, 404)
            p.unlink()
            audit(role, self.ip(), "архив удалён", name)
            return self.reply({"ok": True})
        return self.reply({"error": "не найдено"}, 404)


def main():
    if not os.environ.get("GB_PASSWORD"):
        sys.exit("Не задан GB_PASSWORD: без пароля веб-интерфейс не запускается.")
    port = int(os.environ.get("GB_PORT", "8080"))
    threading.Thread(target=scheduler, daemon=True).start()
    print("%s %s: http://0.0.0.0:%d" % (NAME, VERSION, port), flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()


if __name__ == "__main__":
    main()
