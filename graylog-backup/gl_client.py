"""Минимальный клиент Graylog REST на стандартной библиотеке (только чтение).

Самостоятельная копия того же приёма, что в rule-tester/graylog_api.py: своей зависимости
между инструментами нет намеренно, у каждого свой Containerfile и свой набор файлов.
"""
import base64
import json
import ssl
import urllib.error
import urllib.request


class ApiError(RuntimeError):
    pass


class Graylog:
    def __init__(self, url, token, insecure=False, ca_file=None, timeout=60):
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

    def get(self, path):
        req = urllib.request.Request(self.base + path, method="GET")
        req.add_header("Accept", "application/json")
        req.add_header("X-Requested-By", "graylog-backup")
        if self.token:
            auth = base64.b64encode(("%s:token" % self.token).encode()).decode()
            req.add_header("Authorization", "Basic " + auth)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            raise ApiError("GET %s -> HTTP %s: %s" % (path, e.code, detail))
        except urllib.error.URLError as e:
            raise ApiError("GET %s -> %s" % (path, e.reason))
        return json.loads(raw) if raw.strip() else {}

    def paged(self, path_fmt, key, per_page=100):
        """path_fmt — шаблон с {page}/{per_page}, key — поле со списком в ответе."""
        out, page = [], 1
        while True:
            r = self.get(path_fmt.format(page=page, per_page=per_page))
            items = r.get(key, [])
            out += items
            total = r.get("total", len(out))
            if not items or len(out) >= total:
                return out
            page += 1

    def system(self):
        return self.get("/api/system")
