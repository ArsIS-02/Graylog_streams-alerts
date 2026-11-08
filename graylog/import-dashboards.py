#!/usr/bin/env python3
"""Импорт дашбордов из dashboards-spec.json в Graylog 7.x через REST API.

Питоновский порт import-dashboards.js (тот же JSON видов), чтобы не гонять
консоль браузера.

Запуск:
  python3 import-dashboards.py --dry-run                 # показать, что будет создано
  python3 import-dashboards.py --title "💓 Пульс"        # создать только совпадающие по подстроке
  python3 import-dashboards.py                           # создать все из спеки

Потоки находятся по названию — названия в spec должны совпадать с Graylog.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import ssl
import urllib.request
import urllib.error
import uuid as uuidlib

BASE = "https://graylog.apps.monitoring.test"
AUTH = ("admin", "admin")

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


def api(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Requested-By", "cli")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{AUTH[0]}:{AUTH[1]}".encode()).decode())
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data=data, timeout=60, context=_SSL) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"HTTP {e.code} {method} {path}\n{e.read().decode()[:1500]}")


def uuid() -> str:
    return str(uuidlib.uuid4())


def pivot(p, for_type: bool) -> dict:
    kind, field, param = p
    if kind == "t":
        interval = {"type": "auto", "scaling": 1}
        if param != "auto":
            m = re.match(r"^(\d+)(minutes|hours|days)$", param)
            short = {"minutes": "m", "hours": "h", "days": "d"}[m.group(2)]
            interval = ({"type": "timeunit", "timeunit": m.group(1) + short} if for_type
                        else {"type": "timeunit", "value": int(m.group(1)), "unit": m.group(2)})
        if for_type:  # DTO поискового типа: плоская форма, без обёртки config
            return {"type": "time", "field": field, "interval": interval}
        return {"type": "time", "fields": [field], "config": {"interval": interval}}
    if for_type:
        return {"type": "values", "fields": [field], "limit": param}
    return {"type": "values", "fields": [field], "config": {"limit": param}}


def fn(f: str) -> dict:
    m = re.match(r"^(\w+)\((.*)\)$", f)
    return {"type": m.group(1), "id": f, "field": m.group(2) or None}


def sorts(arr, ser):
    out = []
    for s in arr or []:
        f, _, direction = s.partition(" ")
        kind = "series" if f in ser else "pivot"
        out.append({"type": kind, "field": f, "direction": direction or "Ascending"})
    return out


def build(D: dict, sid) -> tuple[dict, dict]:
    queries, state = [], {}
    for P in D["pages"]:
        qid = uuid()
        widgets, mapping, positions, titles, types = [], {}, {}, {}, []
        for W in P["widgets"]:
            wid = uuid()
            sids = [sid(t) for t in W.get("s", [])]
            base = {"id": wid, "type": "messages" if W["v"] == "messages" else ("text" if W["v"] == "text" else "aggregation"),
                    "filter": None, "timerange": {"type": "relative", "range": W.get("r") or P["timerange"]},
                    "query": {"type": "elasticsearch", "query_string": W.get("q") or ""},
                    "streams": sids, "stream_categories": []}
            positions[wid] = {"col": W["pos"][0], "row": W["pos"][1], "height": W["h"], "width": W["w"]}
            titles[wid] = W["t"]
            if W["v"] == "text":
                w = dict(base, config={"text": W.get("txt", "")})
                w.pop("timerange"); w.pop("query"); w.pop("streams")
                widgets.append(w)
                continue
            st_id = uuid()
            mapping[wid] = [st_id]
            if W["v"] == "messages":
                widgets.append(dict(base, config={"fields": W["f"], "show_message_row": True, "show_summary": False,
                                                  "decorators": []}))
                types.append({"type": "messages", "id": st_id, "limit": W.get("lim", 100), "offset": 0,
                              "sort": [{"field": "timestamp", "order": "DESC"}], "decorators": [],
                              "streams": sids, "timerange": base["timerange"], "query": base["query"], "filter": None})
                continue
            ser = W.get("m") or ["count()"]
            if W["v"] == "bar":
                vc = {"barmode": W.get("bm", "group"), "axis_type": "linear"}
            elif W["v"] in ("area", "line"):
                vc = {"axis_type": "linear", "interpolation": "linear"}
            else:
                vc = {}
            widgets.append(dict(base, config={
                "visualization": W["v"], "visualization_config": vc or None,
                "series": [{"config": {"name": None}, "function": f} for f in ser],
                "row_pivots": [pivot(p, False) for p in W.get("rows", [])],
                "column_pivots": [pivot(p, False) for p in W.get("cols", [])],
                "sort": sorts(W.get("sort"), ser), "rollup": True, "event_annotation": False}))
            types.append({"type": "pivot", "id": st_id, "name": "chart", "streams": sids,
                          "timerange": base["timerange"], "query": base["query"], "filter": None,
                          "series": [fn(f) for f in ser],
                          "row_groups": [pivot(p, True) for p in W.get("rows", [])],
                          "column_groups": [pivot(p, True) for p in W.get("cols", [])],
                          "sort": sorts(W.get("sort"), ser), "rollup": True, "filters": []})
        queries.append({"id": qid, "query": {"type": "elasticsearch", "query_string": ""},
                        "timerange": {"type": "relative", "range": P["timerange"]}, "search_types": types})
        state[qid] = {"selected_fields": None, "static_message_list_id": None,
                      "titles": {"widget": titles, "tab": {"title": P.get("title") or "Страница"}},
                      "widgets": widgets, "widget_mapping": mapping, "positions": positions,
                      "formatting": {"highlighting": []}}
    search = {"queries": queries, "parameters": []}
    view = {"type": "DASHBOARD", "title": D["title"], "summary": D.get("summary", ""),
            "description": D.get("description", ""), "properties": [], "requires": {}, "state": state}
    return search, view


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", default="dashboards-spec.json")
    ap.add_argument("--title", default=None, help="подстрока названия дашборда")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--update-existing", action="store_true",
                    help="обновить существующий дашборд с тем же названием (PUT), не создавая дубль")
    args = ap.parse_args()

    spec = json.load(open(args.spec, encoding="utf-8"))
    streams = api("GET", "/api/streams")["streams"]

    def sid(title: str) -> str:
        for s in streams:
            if s["title"] == title:
                return s["id"]
        raise SystemExit(f"Нет потока: {title}")

    existing: dict[str, str] = {}
    if args.update_existing:
        views = api("GET", "/api/views?per_page=200")
        for v in views.get("views", []):
            if v.get("type") == "DASHBOARD":
                existing[v["title"]] = v["id"]

    for D in spec:
        if args.title and args.title not in D["title"]:
            continue
        search, view = build(D, sid)
        if args.dry_run:
            mark = " (обновлю " + existing[D["title"]] + ")" if D["title"] in existing else ""
            print(f"[dry] {D['title']}: страниц {len(D['pages'])}, "
                  f"виджетов {sum(len(p['widgets']) for p in D['pages'])}{mark}")
            continue
        s = api("POST", "/api/views/search", search)
        view["search_id"] = s["id"]
        vid = existing.get(D["title"])
        if vid:
            view["id"] = vid
            api("PUT", f"/api/views/{vid}", {"entity": view})
            print(f"UPD {D['title']}  →  {vid}")
        else:
            v = api("POST", "/api/views", {"entity": view})
            print(f"OK  {D['title']}  →  {v['id']}")


if __name__ == "__main__":
    main()
