#!/usr/bin/env python3
"""GraylogBackup: резервное копирование конфигурации Graylog (не самих логов).

Семь источников, каждый — отдельным шагом, неудача одного не останавливает остальные:

  config          снимок конфигурации через REST API Graylog (потоки, определения
                  событий, уведомления, index sets, outputs/inputs, pipeline-правила
                  и связи, lookup-таблицы, grok-паттерны, dashboards) — только для
                  чтения и diff'а в git, НЕ предназначен для восстановления: это
                  читаемый JSON, а не content pack, который Graylog умеет импортировать
                  обратно одной кнопкой.
  mongo           полный `mongodump` базы Graylog (основной источник восстановления
                  «один в один»: пользователи, роли, index sets, sidecar-конфигурация —
                  всё, что есть в MongoDB; бóльшая часть entity-конфигурации хранится
                  здесь).
  server_conf     файл server.conf самого graylog-server (путь — GB_SERVER_CONF,
                  монтируется в контейнер только для чтения). Нужен для полного
                  восстановления: именно тут лежит password_secret, которым в MongoDB
                  зашифрована часть значений (секреты некоторых inputs, lookup-
                  адаптеров) — если на новом сервере password_secret будет другим, эти
                  значения после restore-mongo не расшифруются. Здесь же
                  root_password_sha2 и остальные настройки сервера, не хранящиеся
                  в MongoDB.
  mongod_conf     файл конфигурации самой MongoDB (путь — GB_MONGOD_CONF) — bind-адрес,
                  аутентификация, storage engine, keyFile, репликация: то, с чем нужно
                  поднять MongoDB на новом сервере ДО restore-mongo, иначе он просто
                  не будет слушать там, где его ждут, или не примет то же подключение.
  opensearch_conf файл конфигурации OpenSearch/Elasticsearch (путь — GB_OPENSEARCH_CONF) —
                  имя кластера, узел, discovery, пути к сертификатам. Это сам файл
                  конфигурации, а не структура индексов (см. search ниже).
  plugins         содержимое каталога плагинов graylog-server (путь — GB_PLUGIN_DIR,
                  тоже монтируется только для чтения), архивируется в plugins.tar.gz —
                  mongodump сохраняет то, что плагин записал в базу, но не сам .jar.
  search          структура индексов OpenSearch/Elasticsearch: шаблоны индексов,
                  component templates, настройки кластера, политики ISM (если есть) —
                  САМИ ЛОГИ (данные индексов) сюда не попадают, это задача ротации/
                  снапшотов самого кластера, не этого инструмента.

Режимы:
  doctor   проверить доступ к Graylog REST, MongoDB (mongodump), все файлы конфигурации
           с хоста, каталог плагинов и OpenSearch/ES
  run      сделать резервную копию, разом или выборочно (--skip-mongo и т.п.)
  list     список уже сделанных архивов на диске
  prune    удалить архивы старше --days
  restore-mongo  ОПАСНО: восстановить mongodump из архива в MongoDB (--yes обязателен)

Адрес и токен Graylog — те же переменные, что у rule-tester (GRAYLOG_URL, GRAYLOG_TOKEN),
можно использовать общий read-only токен. Остальное — переменные с префиксом GB_
(см. deploy/env.example). server.conf, mongod.conf, opensearch.yml/elasticsearch.yml
и каталог плагинов из архива восстанавливаются простым копированием на нужное место
на новом сервере (с сохранением прав доступа) — отдельной команды для этого нет,
см. главу 18 (раздел «Аварийное восстановление»).
"""
import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import gl_client as G
from version import NAME, VERSION

HERE = Path(__file__).resolve().parent


def log(msg):
    print(msg, file=sys.stderr)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


# ------------------------------------------------------------------ шаг 1: снимок конфигурации (REST)

# (ключ в итоговом JSON, путь/шаблон, поле со списком в ответе, постраничный ли запрос)
CONFIG_ENTITIES = [
    ("streams", "/api/streams", "streams", False),
    ("event_definitions", "/api/events/definitions?per_page={per_page}&page={page}", "event_definitions", True),
    ("event_notifications", "/api/events/notifications?per_page={per_page}&page={page}", "notifications", True),
    ("index_sets", "/api/system/indices/index_sets?stats=false", "index_sets", False),
    ("outputs", "/api/system/outputs", "outputs", False),
    ("inputs", "/api/system/inputs", "inputs", False),
    ("pipelines", "/api/system/pipelines/pipeline", None, False),
    ("pipeline_rules", "/api/system/pipelines/rule", None, False),
    ("pipeline_connections", "/api/system/pipelines/connections", None, False),
    ("lookup_tables", "/api/system/lookup/tables?per_page={per_page}&page={page}", "lookup_tables", True),
    ("lookup_caches", "/api/system/lookup/caches?per_page={per_page}&page={page}", "caches", True),
    ("lookup_adapters", "/api/system/lookup/adapters?per_page={per_page}&page={page}", "data_adapters", True),
    ("grok_patterns", "/api/system/grok", None, False),
    ("dashboards", "/api/views?per_page={per_page}&page={page}", "views", True),
]


def config_snapshot(gl):
    """Опрашивает известные read-only ручки Graylog по очереди. Каждая — своим шагом: если одна
    ручка отсутствует в этой версии Graylog или токену не хватает прав, остальные это не останавливает
    — ошибка записывается в entities[name].error, а не бросается наружу."""
    out = {"entities": {}}
    for name, path, key, paged in CONFIG_ENTITIES:
        try:
            if paged:
                items = gl.paged(path, key)
            else:
                r = gl.get(path.format(page=1, per_page=100))
                items = r.get(key) if key else r
            out["entities"][name] = {"ok": True, "count": (len(items) if isinstance(items, list) else None),
                                      "data": items}
        except G.ApiError as e:
            out["entities"][name] = {"ok": False, "error": str(e)}
    try:
        out["graylog_system"] = gl.system()
    except G.ApiError as e:
        out["graylog_system"] = {"error": str(e)}
    return out


def step_config(gl, workdir):
    t0 = time.time()
    snap = config_snapshot(gl)
    (workdir / "config-snapshot.json").write_text(json.dumps(snap, ensure_ascii=False, indent=1), encoding="utf-8")
    ok = {k: v for k, v in snap["entities"].items() if v.get("ok")}
    bad = {k: v["error"] for k, v in snap["entities"].items() if not v.get("ok")}
    status = "ok" if not bad else ("partial" if ok else "error")
    return {"status": status, "duration_s": round(time.time() - t0, 1),
            "counts": {k: v["count"] for k, v in ok.items()},
            "failed": bad, "graylog_version": snap.get("graylog_system", {}).get("version")}


# ------------------------------------------------------------------ шаг 2: mongodump

def mongodump_bin():
    return os.environ.get("GB_MONGODUMP_BIN", "mongodump")


def mongorestore_bin():
    return os.environ.get("GB_MONGORESTORE_BIN", "mongorestore")


def uri_has_db(uri):
    """True, если строка подключения уже называет базу (mongodb://host/graylog?...) — тогда
    mongodump/mongorestore берут её сами, и явный --db конфликтует с ней (Invalid Options:
    Cannot specify different database in connection URI and command-line option)."""
    try:
        return bool(urlsplit(uri).path.lstrip("/"))
    except ValueError:
        return False


def step_mongo(uri, workdir, timeout=1800):
    t0 = time.time()
    if not uri:
        return {"status": "skipped", "reason": "GB_MONGO_URI не задан"}
    out = workdir / "mongodump.archive.gz"
    cmd = [mongodump_bin(), "--uri=%s" % uri, "--archive=%s" % out, "--gzip"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"status": "error", "reason": "%s не найден (установлен ли mongodb-database-tools в образе?)"
                % mongodump_bin()}
    except subprocess.TimeoutExpired:
        return {"status": "error", "reason": "mongodump не уложился в %d с" % timeout}
    if r.returncode != 0 or not out.exists():
        return {"status": "error", "reason": (r.stderr or r.stdout or "mongodump завершился с ошибкой")[-2000:]}
    return {"status": "ok", "duration_s": round(time.time() - t0, 1), "bytes": out.stat().st_size}


def mongo_restore(uri, archive_path, drop=True, yes=False):
    """ОПАСНО: заменяет содержимое базы Graylog в MongoDB дампом из архива. Только консоль,
    только с --yes. Перед восстановлением остановите graylog-server, иначе он продолжит
    писать поверх данных во время восстановления."""
    if not yes:
        raise SystemExit("restore-mongo требует --yes — без него ничего не делает")
    cmd = [mongorestore_bin(), "--uri=%s" % uri, "--archive=%s" % archive_path, "--gzip"]
    if drop:
        cmd.append("--drop")
    log("Выполняю: %s" % " ".join(cmd))
    r = subprocess.run(cmd, text=True)
    return r.returncode == 0


# ------------------------------------------------------------------ шаги 3-5: отдельные файлы конфигурации с хоста

def step_host_file(path, workdir, dest_name, env_name, sanity_marker=None, sanity_hint=None):
    """Копирует один файл конфигурации с хоста (смонтирован в контейнер только для чтения, см.
    install.sh и HOST_*/GB_* в deploy/env.example) в архив как есть. sanity_marker — байтовая
    строка, которую ожидаем встретить внутри; её отсутствие не прерывает шаг, но помечает его
    partial — подстраховка от того, что в переменной случайно указали не тот файл."""
    t0 = time.time()
    if not path:
        return {"status": "skipped", "reason": "%s не задан" % env_name}
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        return {"status": "error", "reason": "не удалось прочитать %s: %s" % (path, e)}
    (workdir / dest_name).write_bytes(data)
    result = {"status": "ok", "duration_s": round(time.time() - t0, 1), "bytes": len(data)}
    if sanity_marker is not None:
        has_marker = sanity_marker in data
        result["sanity_ok"] = has_marker
        if not has_marker:
            result["status"] = "partial"
            result["reason"] = sanity_hint or "в файле не нашлось ожидаемого содержимого — похоже, не тот файл"
    return result


def step_server_conf(path, workdir):
    return step_host_file(path, workdir, "server.conf", "GB_SERVER_CONF",
                           sanity_marker=b"password_secret",
                           sanity_hint="в файле не нашлось password_secret — похоже, это не server.conf Graylog")


def step_mongod_conf(path, workdir):
    return step_host_file(path, workdir, "mongod.conf", "GB_MONGOD_CONF",
                           sanity_marker=b"storage:",
                           sanity_hint="в файле не нашлось раздела storage: — похоже, это не mongod.conf")


def step_opensearch_conf(path, workdir):
    return step_host_file(path, workdir, "opensearch.yml", "GB_OPENSEARCH_CONF",
                           sanity_marker=b"cluster.name",
                           sanity_hint="в файле не нашлось cluster.name — похоже, это не opensearch.yml/elasticsearch.yml")


# ------------------------------------------------------------------ шаг 6: каталог плагинов

def step_plugins(path, workdir):
    t0 = time.time()
    if not path:
        return {"status": "skipped", "reason": "GB_PLUGIN_DIR не задан"}
    d = Path(path)
    if not d.is_dir():
        return {"status": "error", "reason": "каталог не найден или недоступен: %s" % path}
    out = workdir / "plugins.tar.gz"
    failed = {}
    count = 0
    with tarfile.open(out, "w:gz") as tar:
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            try:
                tar.add(f, arcname=str(f.relative_to(d)))
                count += 1
            except OSError as e:
                failed[str(f.relative_to(d))] = str(e)
    if count == 0:
        out.unlink(missing_ok=True)
        status = "error" if failed else "skipped"
        return {"status": status, "reason": "каталог плагинов пуст" if not failed else "ни один файл не прочитан",
                "failed": failed}
    return {"status": "ok" if not failed else "partial", "duration_s": round(time.time() - t0, 1),
            "files": count, "failed": failed, "bytes": out.stat().st_size}


# ------------------------------------------------------------------ шаг 7: структура индексов OpenSearch/ES

def _os_get(base, path, insecure, ca_file, timeout=30, body=None):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif ca_file:
        ctx = ssl.create_default_context(cafile=ca_file)
    req = urllib.request.Request(base.rstrip("/") + path, method="GET")
    req.add_header("Accept", "application/json")
    if body is not None:
        # GET с телом: нужен некоторым поисковым ручкам (например, листинг политик ISM) —
        # без тела (даже пустого) OpenSearch у части версий отвечает 400 Bad Request
        # ("Required content body is missing"), трактуя запрос как поиск без параметров.
        data = json.dumps(body).encode("utf-8")
        req.data = data
        req.add_header("Content-Type", "application/json")
        req.add_header("Content-Length", str(len(data)))
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.loads(r.read() or b"{}")


def step_search(url, workdir, insecure=False, ca_file=None):
    t0 = time.time()
    if not url:
        return {"status": "skipped", "reason": "GB_OPENSEARCH_URL не задан"}
    out = {}
    errors = {}
    for key, path, required, body in (
        ("index_templates", "/_index_template", True, None),
        ("component_templates", "/_component_template", True, None),
        ("legacy_templates", "/_template", False, None),
        ("cluster_settings", "/_cluster/settings?include_defaults=false&flat_settings=true", True, None),
        # только OpenSearch (на Elasticsearch — 404); листинг всех политик — поисковая ручка,
        # без JSON-тела (даже пустого {}) часть версий отвечает 400 Bad Request.
        ("ism_policies", "/_plugins/_ism/policies", False, {}),
    ):
        try:
            out[key] = _os_get(url, path, insecure, ca_file, body=body)
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            errors[key] = str(e)
            if required and key not in ("legacy_templates",):
                pass  # не required-блокирующая: пишем ошибку и продолжаем остальные ключи
    (workdir / "opensearch-templates.json").write_text(
        json.dumps({"templates": out, "errors": errors}, ensure_ascii=False, indent=1), encoding="utf-8")
    status = "ok" if out else "error"
    if out and errors:
        status = "partial"
    return {"status": status, "duration_s": round(time.time() - t0, 1), "got": list(out), "failed": errors}


# ------------------------------------------------------------------ сборка архива, список, ротация

def run_backup(gl_url, gl_token, mongo_uri, os_url, out_dir, insecure=False, ca_file=None,
                skip_config=False, skip_mongo=False, skip_search=False,
                server_conf_path=None, skip_server_conf=False,
                plugin_dir=None, skip_plugins=False,
                mongod_conf_path=None, skip_mongod_conf=False,
                opensearch_conf_path=None, skip_opensearch_conf=False):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = now_stamp()
    name = "graylog-backup-%s" % stamp
    with tempfile.TemporaryDirectory(prefix="gb-") as tmp:
        workdir = Path(tmp)
        steps = {}
        if not skip_config:
            try:
                gl = G.Graylog(gl_url, gl_token, insecure=insecure, ca_file=ca_file)
                steps["config"] = step_config(gl, workdir)
            except G.ApiError as e:
                steps["config"] = {"status": "error", "reason": str(e)}
        else:
            steps["config"] = {"status": "skipped", "reason": "--skip-config"}
        steps["mongo"] = step_mongo(mongo_uri, workdir) if not skip_mongo else \
            {"status": "skipped", "reason": "--skip-mongo"}
        steps["server_conf"] = step_server_conf(server_conf_path, workdir) if not skip_server_conf else \
            {"status": "skipped", "reason": "--skip-server-conf"}
        steps["mongod_conf"] = step_mongod_conf(mongod_conf_path, workdir) if not skip_mongod_conf else \
            {"status": "skipped", "reason": "--skip-mongod-conf"}
        steps["opensearch_conf"] = step_opensearch_conf(opensearch_conf_path, workdir) if not skip_opensearch_conf else \
            {"status": "skipped", "reason": "--skip-opensearch-conf"}
        steps["plugins"] = step_plugins(plugin_dir, workdir) if not skip_plugins else \
            {"status": "skipped", "reason": "--skip-plugins"}
        steps["search"] = step_search(os_url, workdir, insecure, ca_file) if not skip_search else \
            {"status": "skipped", "reason": "--skip-search"}

        meta = {"tool": NAME, "version": VERSION, "started": stamp, "finished_at": now_iso(),
                "graylog_url": gl_url, "graylog_version": steps.get("config", {}).get("graylog_version"),
                "steps": steps}
        (workdir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")

        archive_path = out_dir / (name + ".tar.gz")
        with tarfile.open(archive_path, "w:gz") as tar:
            for f in sorted(workdir.iterdir()):
                tar.add(f, arcname=f.name)
    meta["archive"] = archive_path.name
    meta["bytes"] = archive_path.stat().st_size
    return meta


def list_backups(out_dir):
    out_dir = Path(out_dir)
    if not out_dir.is_dir():
        return []
    rows = []
    for p in sorted(out_dir.glob("graylog-backup-*.tar.gz"), reverse=True):
        meta = None
        try:
            with tarfile.open(p, "r:gz") as tar:
                f = tar.extractfile("meta.json")
                if f:
                    meta = json.loads(f.read())
        except (OSError, tarfile.TarError, json.JSONDecodeError):
            pass
        rows.append({"file": p.name, "bytes": p.stat().st_size,
                     "mtime": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
                     "steps": (meta or {}).get("steps"), "graylog_version": (meta or {}).get("graylog_version")})
    return rows


def prune_backups(out_dir, days):
    out_dir = Path(out_dir)
    if not out_dir.is_dir() or not days or days <= 0:
        return 0
    cutoff = time.time() - days * 86400
    removed = 0
    for p in out_dir.glob("graylog-backup-*.tar.gz"):
        if p.stat().st_mtime < cutoff:
            p.unlink()
            removed += 1
    return removed


# ------------------------------------------------------------------ doctor

def _doctor_check_file(label, path, env_name, sanity_marker=None, sanity_hint=None, ok_detail=""):
    """Общая часть doctor для одного файла конфигурации с хоста. Возвращает True/False (ok)."""
    if not path:
        log("[ - ] %s: %s не задан, этот шаг будет пропущен" % (label, env_name))
        return True
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        log("[FAIL] %s: %s — %s" % (label, path, e))
        return False
    if sanity_marker is not None and sanity_marker not in data:
        log("[FAIL] %s: %s читается, но %s" % (label, path, sanity_hint or "похоже, не тот файл"))
        return False
    log("[ OK ] %s: %s читается%s" % (label, path, (", " + ok_detail) if ok_detail else ""))
    return True


def doctor(gl_url, gl_token, mongo_uri, os_url, insecure=False, ca_file=None,
           server_conf_path=None, plugin_dir=None,
           mongod_conf_path=None, opensearch_conf_path=None):
    ok = True
    if gl_url and gl_token:
        try:
            gl = G.Graylog(gl_url, gl_token, insecure=insecure, ca_file=ca_file)
            sysinfo = gl.system()
            log("[ OK ] Graylog REST: %s (%s)" % (gl_url, sysinfo.get("version", "?")))
        except G.ApiError as e:
            ok = False
            log("[FAIL] Graylog REST: %s" % e)
    else:
        log("[ - ] Graylog REST: GRAYLOG_URL/GRAYLOG_TOKEN не заданы, снимок конфигурации будет пропущен")

    if mongo_uri:
        try:
            r = subprocess.run([mongodump_bin(), "--version"], capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                raise FileNotFoundError
            log("[ OK ] mongodump найден: %s" % r.stdout.splitlines()[0])
        except (FileNotFoundError, subprocess.TimeoutExpired):
            ok = False
            log("[FAIL] mongodump не найден в образе (нужен пакет mongodb-database-tools)")
            mongo_uri = None
        if mongo_uri:
            with tempfile.TemporaryDirectory(prefix="gb-doctor-") as tmp:
                probe_out = Path(tmp) / "probe.archive.gz"
                cmd = [mongodump_bin(), "--uri=%s" % mongo_uri, "--archive=%s" % probe_out, "--gzip",
                       "--collection=__graylog_backup_doctor_probe__"]
                # --db конфликтует с базой, уже указанной в URI (mongodump это проверяет и
                # отказывается стартовать) — добавляем его, только если URI базу не называет.
                if not uri_has_db(mongo_uri):
                    cmd.insert(1, "--db=admin")
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if r.returncode == 0:
                        log("[ OK ] MongoDB: подключение и аутентификация по %s работают" % mongo_uri)
                    else:
                        ok = False
                        log("[FAIL] MongoDB: %s" % (r.stderr or r.stdout)[-500:])
                except subprocess.TimeoutExpired:
                    ok = False
                    log("[FAIL] MongoDB: не отвечает за 30 с")
    else:
        log("[ - ] MongoDB: GB_MONGO_URI не задан, этот шаг будет пропущен при резервном копировании")

    if not _doctor_check_file("server.conf", server_conf_path, "GB_SERVER_CONF",
                               sanity_marker=b"password_secret",
                               sanity_hint="password_secret не найден — похоже, не тот файл",
                               ok_detail="password_secret на месте"):
        ok = False

    if not _doctor_check_file("mongod.conf", mongod_conf_path, "GB_MONGOD_CONF",
                               sanity_marker=b"storage:",
                               sanity_hint="раздел storage: не найден — похоже, не тот файл"):
        ok = False

    if not _doctor_check_file("opensearch.yml/elasticsearch.yml", opensearch_conf_path, "GB_OPENSEARCH_CONF",
                               sanity_marker=b"cluster.name",
                               sanity_hint="cluster.name не найден — похоже, не тот файл"):
        ok = False

    if plugin_dir:
        d = Path(plugin_dir)
        if d.is_dir():
            n = sum(1 for _ in d.rglob("*") if _.is_file())
            log("[ OK ] Каталог плагинов: %s читается, файлов: %d" % (plugin_dir, n))
        else:
            ok = False
            log("[FAIL] Каталог плагинов: %s не найден или недоступен" % plugin_dir)
    else:
        log("[ - ] Каталог плагинов: GB_PLUGIN_DIR не задан, этот шаг будет пропущен")

    if os_url:
        try:
            info = _os_get(os_url, "/", insecure, ca_file, timeout=10)
            log("[ OK ] OpenSearch/Elasticsearch: %s (%s)" % (os_url, (info.get("version") or {}).get("number", "?")))
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            ok = False
            log("[FAIL] OpenSearch/Elasticsearch: %s" % e)
    else:
        log("[ - ] OpenSearch/Elasticsearch: GB_OPENSEARCH_URL не задан, шаг search будет пропущен")
    return 0 if ok else 1


# ------------------------------------------------------------------ CLI

def main(argv=None):
    # Общие флаги вынесены в родительский парсер и подключены к каждой подкоманде через parents=,
    # Важно: argparse подменяет уже установленное значение дефолтом подпарсера, если один и тот же
    # флаг объявлен и на верхнем парсере, и на подкоманде через parents= (subparsers парсит свою
    # часть в отдельный Namespace и копирует его поверх общего, затирая то, что разобрал родитель) —
    # поэтому все общие флаги объявлены ТОЛЬКО на верхнем парсере и пишутся ДО имени подкоманды,
    # как и у rule_tester.py: `backup.py --out-dir ... run`, а не `backup.py run --out-dir ...`.
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", help="адрес Graylog REST (или GRAYLOG_URL)")
    ap.add_argument("--insecure", action="store_true", help="не проверять сертификат (только лаборатория)")
    ap.add_argument("--ca-file", help="файл CA для проверки сертификата Graylog/OpenSearch")
    ap.add_argument("--out-dir", default=os.environ.get("GB_OUT_DIR", "./backups"), help="куда класть архивы")
    ap.add_argument("--version", action="version", version="%s %s" % (NAME, VERSION))
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor")

    p = sub.add_parser("run")
    p.add_argument("--skip-config", action="store_true")
    p.add_argument("--skip-mongo", action="store_true")
    p.add_argument("--skip-server-conf", action="store_true")
    p.add_argument("--skip-mongod-conf", action="store_true")
    p.add_argument("--skip-opensearch-conf", action="store_true")
    p.add_argument("--skip-plugins", action="store_true")
    p.add_argument("--skip-search", action="store_true")

    sub.add_parser("list")

    p = sub.add_parser("prune")
    p.add_argument("--days", type=int, required=True)

    p = sub.add_parser("restore-mongo")
    p.add_argument("--archive", required=True, help="путь к архиву graylog-backup-*.tar.gz")
    p.add_argument("--yes", action="store_true", help="обязателен: подтверждение, что это осознанное действие")
    p.add_argument("--no-drop", action="store_true", help="не стирать существующие коллекции перед восстановлением")

    args = ap.parse_args(argv)
    gl_url = args.url or os.environ.get("GRAYLOG_URL", "")
    gl_token = os.environ.get("GRAYLOG_TOKEN", "")
    mongo_uri = os.environ.get("GB_MONGO_URI", "")
    os_url = os.environ.get("GB_OPENSEARCH_URL", "")
    server_conf_path = os.environ.get("GB_SERVER_CONF", "")
    plugin_dir = os.environ.get("GB_PLUGIN_DIR", "")
    mongod_conf_path = os.environ.get("GB_MONGOD_CONF", "")
    opensearch_conf_path = os.environ.get("GB_OPENSEARCH_CONF", "")

    if args.cmd == "doctor":
        return doctor(gl_url, gl_token, mongo_uri, os_url, insecure=args.insecure, ca_file=args.ca_file,
                      server_conf_path=server_conf_path, plugin_dir=plugin_dir,
                      mongod_conf_path=mongod_conf_path, opensearch_conf_path=opensearch_conf_path)

    if args.cmd == "run":
        meta = run_backup(gl_url, gl_token, mongo_uri, os_url, args.out_dir, insecure=args.insecure,
                           ca_file=args.ca_file, skip_config=args.skip_config, skip_mongo=args.skip_mongo,
                           skip_search=args.skip_search,
                           server_conf_path=server_conf_path, skip_server_conf=args.skip_server_conf,
                           plugin_dir=plugin_dir, skip_plugins=args.skip_plugins,
                           mongod_conf_path=mongod_conf_path, skip_mongod_conf=args.skip_mongod_conf,
                           opensearch_conf_path=opensearch_conf_path, skip_opensearch_conf=args.skip_opensearch_conf)
        print(json.dumps(meta, ensure_ascii=False, indent=1))
        bad = [k for k, v in meta["steps"].items() if v.get("status") == "error"]
        return 2 if bad else 0

    if args.cmd == "list":
        for row in list_backups(args.out_dir):
            print("%s  %8d байт  %s" % (row["mtime"], row["bytes"], row["file"]))
        return 0

    if args.cmd == "prune":
        n = prune_backups(args.out_dir, args.days)
        print("Удалено архивов: %d" % n)
        return 0

    if args.cmd == "restore-mongo":
        if not mongo_uri:
            log("GB_MONGO_URI не задан")
            return 2
        archive = Path(args.archive)
        if not archive.is_file():
            log("Не найден архив: %s" % archive)
            return 2
        with tempfile.TemporaryDirectory(prefix="gb-restore-") as tmp:
            with tarfile.open(archive, "r:gz") as tar:
                tar.extract("mongodump.archive.gz", tmp, filter="data")
            ok = mongo_restore(mongo_uri, Path(tmp) / "mongodump.archive.gz",
                                drop=not args.no_drop, yes=args.yes)
        return 0 if ok else 2

    return 1


if __name__ == "__main__":
    sys.exit(main())
