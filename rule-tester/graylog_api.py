"""Минимальный клиент Graylog REST и GELF HTTP на стандартной библиотеке.

Чтение: определения событий, потоки, поиск сообщений, поиск событий.
Запись: только отправка тестовых сообщений на вход GELF и (по флагу setup --apply) создание тестового потока.
"""
import base64
import json
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone


class ApiError(RuntimeError):
    pass


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def now_utc():
    return datetime.now(timezone.utc)


class Graylog:
    def __init__(self, url, token, insecure=False, ca_file=None, timeout=30):
        self.base = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif ca_file:
            ctx = ssl.create_default_context(cafile=ca_file)
        else:
            ctx = ssl.create_default_context()
        self.ctx = ctx

    def _req(self, method, path, body=None, base=None):
        url = (base or self.base) + path
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        req.add_header("X-Requested-By", "rule-tester")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            auth = base64.b64encode(("%s:token" % self.token).encode()).decode()
            req.add_header("Authorization", "Basic " + auth)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:400]
            raise ApiError("%s %s -> HTTP %s: %s" % (method, path, e.code, detail))
        except urllib.error.URLError as e:
            raise ApiError("%s %s -> %s" % (method, path, e.reason))
        return json.loads(raw) if raw.strip() else {}

    def get(self, path):
        return self._req("GET", path)

    def post(self, path, body):
        return self._req("POST", path, body)

    # ---- чтение
    def system(self):
        return self.get("/api/system")

    def streams(self):
        return self.get("/api/streams").get("streams", [])

    def stream_rules(self, stream_id):
        return self.get("/api/streams/%s" % stream_id).get("rules", [])

    def index_sets(self):
        return self.get("/api/system/indices/index_sets?stats=false").get("index_sets", [])

    def event_definitions(self):
        out, page = [], 1
        while True:
            r = self.get("/api/events/definitions?per_page=100&page=%d" % page)
            out += r.get("event_definitions", [])
            if len(out) >= r.get("total", len(out)) or not r.get("event_definitions"):
                return out
            page += 1

    def search_messages(self, query, stream_ids=None, minutes=30, limit=100, fields=None):
        """Поиск сообщений (Views Search). Возвращает (всего, [словарь сообщения])."""
        end = now_utc() + timedelta(minutes=5)
        start = end - timedelta(minutes=minutes + 5)
        st = {"id": "st1", "type": "messages", "limit": limit, "offset": 0}
        if stream_ids:
            st["streams"] = list(stream_ids)
        if fields:
            st["fields"] = fields
        body = {"queries": [{
            "id": "q1",
            "query": {"type": "elasticsearch", "query_string": query},
            "timerange": {"type": "absolute", "from": iso(start), "to": iso(end)},
            "search_types": [st],
        }]}
        r = self.post("/api/views/search/sync", body)
        res = r["results"]["q1"]
        if res.get("errors"):
            raise ApiError("ошибка запроса: %s" % res["errors"])
        part = res["search_types"]["st1"]
        errs = part.get("errors") or []
        if errs:
            raise ApiError("ошибка запроса: %s" % errs)
        msgs = [m.get("message", m) for m in part.get("messages", [])]
        return part.get("total_results", len(msgs)), msgs

    def search_events(self, definition_ids, since, until=None, per_page=200):
        body = {"query": "", "page": 1, "per_page": per_page,
                "timerange": {"type": "absolute", "from": iso(since), "to": iso(until or now_utc() + timedelta(minutes=1))},
                "filter": {"alerts": "include", "event_definitions": list(definition_ids)},
                "sort_by": "timestamp", "sort_direction": "desc"}
        r = self.post("/api/events/search", body)
        return [e.get("event", e) for e in r.get("events", [])]

    # ---- запись
    def create_test_stream(self, title, index_set_id):
        body = {"title": title, "description": "Тестовые сообщения rule-tester (не боевой поток)",
                "rules": [{"field": "rt_run", "type": 5, "value": "", "inverted": False,
                           "description": "есть поле rt_run"}],
                "matching_type": "AND", "remove_matches_from_default_stream": True,
                "index_set_id": index_set_id}
        sid = self.post("/api/streams", body)["stream_id"]
        self._req("POST", "/api/streams/%s/resume" % sid)
        return sid


def send_gelf(gelf_url, doc, timeout=15, ctx=None):
    """Отправляет одно сообщение GELF HTTP. doc — словарь полей Graylog (message, source, …)."""
    host = str(doc.get("source") or "rule-tester")
    msg = {"version": "1.1", "host": host, "short_message": str(doc.get("message") or "rule-tester sample"),
           "level": 6}
    for k, v in doc.items():
        if k in ("message", "source", "id", "_id"):
            continue
        msg[k if k.startswith("_") else "_" + k] = v
    req = urllib.request.Request(gelf_url, data=json.dumps(msg).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            r.read()
    except urllib.error.HTTPError as e:
        raise ApiError("GELF %s -> HTTP %s" % (gelf_url, e.code))
    except urllib.error.URLError as e:
        raise ApiError("GELF %s -> %s" % (gelf_url, e.reason))


def wait_until(fn, timeout, step=3):
    end = time.time() + timeout
    while True:
        v = fn()
        if v:
            return v
        if time.time() >= end:
            return None
        time.sleep(step)
