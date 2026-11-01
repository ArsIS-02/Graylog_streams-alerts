#!/usr/bin/env python3
"""Заглушка Graylog для проверки самого инструмента (без настоящего Graylog).

Умеет: /api/system, /api/streams, /api/events/definitions, /api/views/search/sync, /api/events/search и GELF HTTP.
Поиск вычисляется тем же вычислителем, что и у тестера, поэтому заглушка проверяет обмен по API и отчёты,
а не настоящую семантику Graylog.

  python3 mock_graylog.py --port 9000 [--drop-field FIELD] [--no-stream-ok]
"""
import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lucene as L  # noqa: E402
import rule_tester as R  # noqa: E402

STATE = {"msgs": [], "streams": {}, "drop": set()}
DEFS = []


def init():
    names = {}
    for r in R.load_file_rules():
        for s in r["streams"]:
            names.setdefault(s, "stream-%d" % (len(names) + 1))
    STATE["streams"] = {v: {"id": v, "title": k, "rules": [
        {"field": "gl2_source_input", "type": 7, "value": "", "inverted": False}]} for k, v in names.items()}
    STATE["streams"]["test-stream"] = {"id": "test-stream", "title": "Rule Tester", "rules": [
        {"field": "rt_run", "type": 5, "value": "", "inverted": False}]}
    for i, r in enumerate(R.load_file_rules()):
        DEFS.append({"id": "def-%03d" % i, "title": r["title"], "priority": 2,
                     "config": {"type": "aggregation-v1", "query": r["query"], "streams": [names[s] for s in r["streams"]],
                                "group_by": r["group_by"], "search_within_ms": 300000, "execute_every_ms": 300000,
                                "conditions": {"expression": None if not r["cond"] else {
                                    "expr": r["cond"]["op"], "left": {"expr": "number-ref", "ref": "count-000"},
                                    "right": {"expr": "number", "value": r["cond"]["value"]}}}}})


def ev(query, msgs):
    node, _ = L.parse(query)
    return [m for m in msgs if L.evaluate(node, m)]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/api/system":
            return self.send({"version": "7.2.1-mock"})
        if p == "/api/streams":
            return self.send({"streams": [{"id": s["id"], "title": s["title"]} for s in STATE["streams"].values()]})
        m = re.match(r"/api/streams/(.+)", p)
        if m:
            return self.send(STATE["streams"].get(m.group(1), {}))
        if p == "/api/system/indices/index_sets":
            return self.send({"index_sets": [{"id": "is1", "title": "Default", "default": True}]})
        if p == "/api/events/definitions":
            return self.send({"event_definitions": DEFS, "total": len(DEFS)})
        self.send({"message": "not found"}, 404)

    def do_POST(self):
        p, b = self.path.split("?")[0], self.body()
        if p == "/gelf":
            m = {"source": b.get("host"), "message": b.get("short_message"), "_ts": time.time()}
            for k, v in b.items():
                if k.startswith("_"):
                    m[k[1:]] = v
            for d in STATE["drop"]:
                m.pop(d, None)
            STATE["msgs"].append(m)
            return self.send({}, 202)
        if p == "/api/views/search/sync":
            q = b["queries"][0]
            st = q["search_types"][0]
            try:
                hits = ev(q["query"]["query_string"], STATE["msgs"])
            except L.QueryError as e:
                return self.send({"results": {"q1": {"errors": [str(e)], "search_types": {}}}})
            total = len(hits)
            hits = hits[:st.get("limit", 100)]
            out = [{"message": {k: v for k, v in m.items() if not k.startswith("_")}} for m in hits]
            return self.send({"results": {"q1": {"search_types": {"st1": {"messages": out, "total_results": total}}}}})
        if p == "/api/events/search":
            ids = b["filter"].get("event_definitions", [])
            res = []
            for d in DEFS:
                if d["id"] not in ids:
                    continue
                c = d["config"]
                try:
                    hits = [m for m in ev(c["query"], [x for x in STATE["msgs"] if "rt_run" in x])]
                except L.QueryError:
                    continue
                cond = R.cond_of(c["conditions"])
                if hits and len(hits) >= R.threshold(cond):
                    res.append({"event": {"id": "ev-" + d["id"], "event_definition_id": d["id"],
                                          "timestamp": datetime.now(timezone.utc).isoformat()}})
            return self.send({"events": res, "total_events": len(res)})
        if p == "/api/streams":
            STATE["streams"]["new"] = {"id": "new", "title": b["title"], "rules": b["rules"]}
            return self.send({"stream_id": "new"})
        self.send({}, 200)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--drop-field", action="append", default=[], help="убирать поле при приёме (имитация пайплайна)")
    a = ap.parse_args()
    STATE["drop"] = set(a.drop_field)
    init()
    print("mock Graylog на http://127.0.0.1:%d" % a.port, flush=True)
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()
